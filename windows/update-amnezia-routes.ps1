<#
.SYNOPSIS
Обновляет список RU Direct в split tunneling AmneziaVPN на Windows.

.DESCRIPTION
Источник — список, который собирает этот же репозиторий (tools/build_ru_direct.py)
и публикует в dist/ и в GitHub Releases. Скрипт скачивает его, проверяет и
записывает в QSettings AmneziaVPN (HKCU\Software\AmneziaVPN.ORG\AmneziaVPN\Conf),
аккуратно останавливая и возвращая GUI вместе с туннелем.

Перезагрузка Windows не нужна. Демон AmneziaVPN-service не разбирает туннель,
когда GUI просто закрывают. Скрипт отправляет демону штатную команду отключения,
чтобы удалить прежние маршруты, и затем возвращает соединение. Остановка службы
используется только как резервный способ.

Незавершённая запись журналируется и откатывается при следующем запуске.

При включённом KillSwitch автоматическое закрытие работающей Amnezia запрещено:
штатное отключение снимает его защиту. -AllowVpnReconnect разрешает такой
перезапуск только для текущего запуска и допускает трафик без VPN в этот период.
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Lite,
    [string]$Source,
    [switch]$ReplaceAll,
    [switch]$NoRestart,
    [switch]$AllowVpnReconnect,
    [switch]$SelfTest,
    [switch]$Status,
    [switch]$RecoverOnly,
    [switch]$NoLocalSubnets,
    [ValidateRange(-1, 10000)]
    [int]$ServerIndex = -1,
    [string]$StateDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$IsWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $IsWindowsHost -and -not $SelfTest) {
    throw 'Этот updater предназначен только для Windows.'
}

if (-not $StateDir) {
    $base = $env:LOCALAPPDATA
    if (-not $base) { $base = [IO.Path]::GetTempPath() }
    $StateDir = Join-Path $base 'AmneziaRouteSync'
}

$ListBase = 'https://raw.githubusercontent.com/w1zardz/amnezia-vpn-russia-split-tunneling/master/dist'
$ListFull = "$ListBase/amnezia-ru-direct.json"
$ListLite = "$ListBase/amnezia-ru-direct-lite.json"

$RegistryConfSubKey = 'Software\AmneziaVPN.ORG\AmneziaVPN\Conf'
$RegistryServersSubKey = 'Software\AmneziaVPN.ORG\AmneziaVPN\Servers'
$GuiProcessName = 'AmneziaVPN'
$DaemonServiceName = 'AmneziaVPN-service'
$TunnelServiceName = 'AmneziaWGTunnel$AmneziaVPN'
$SupportedAppMajor = 5

$RouteModeVpnAllExceptSites = 2
$MaxListBytes = 4194304
# Шире /12 не пускаем: такая сеть означала бы «пол-интернета мимо VPN».
$MinimumPrefix = 12
$MinimumRoutes = 40
$MaximumRoutes = 1500
# Лимит уже развёрнутых и схлопнутых маршрутов, включая DNS, а не строк JSON.
$MaximumEffectiveRoutes = 2000
$MaximumAddresses = [uint64]40000000
$MinimumEntries = 300
$MaximumEntries = 4000
$MaxRegistryEntries = 4096

# Стабильные RFC1918-исключения нужны ДО старта VPN. Hyper-V/WSL может сменить
# подсеть после перезагрузки или создать её уже после входа. Снимок интерфейсов
# устаревает, и WindowsRouteMonitor Amnezia 5.0.1.5 начинает захватывать локальные
# broadcast-маршруты с тысячами ошибок 5010. -NoLocalSubnets отключает эту политику
# для пользователей, которым приватные адреса нужны именно внутри Amnezia.
$PrivateSubnetRanges = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')

$ManagedPath = Join-Path $StateDir 'managed-entries.json'
$StatusPath = Join-Path $StateDir 'status.json'
$ImportPath = Join-Path $StateDir 'amnezia-split-routes.json'
$JournalPath = Join-Path $StateDir '.registry-transaction.json'
$BackupDir = Join-Path $StateDir 'backups'
$DnsCachePath = Join-Path $StateDir 'dns-cache.json'

$RoutingValueNames = @('ExceptSites', 'routeMode', 'sitesSplitTunnelingEnabled')

Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.ServiceProcess

$QtCodecSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace AmneziaRouteSync {
    public static class QtVariantMapCodec {
        private const UInt32 QVariantMap = 8;
        private const UInt32 QString = 10;
        private const UInt32 QStringList = 11;

        private static void WriteUInt32(Stream stream, UInt32 value) {
            stream.WriteByte((byte)(value >> 24));
            stream.WriteByte((byte)(value >> 16));
            stream.WriteByte((byte)(value >> 8));
            stream.WriteByte((byte)value);
        }

        private static UInt32 ReadUInt32(byte[] data, ref int offset) {
            if (offset + 4 > data.Length) throw new InvalidDataException("Unexpected end of QDataStream");
            UInt32 value = ((UInt32)data[offset] << 24) | ((UInt32)data[offset + 1] << 16)
                         | ((UInt32)data[offset + 2] << 8) | data[offset + 3];
            offset += 4;
            return value;
        }

        private static void WriteQString(Stream stream, string value) {
            byte[] bytes = Encoding.BigEndianUnicode.GetBytes(value ?? String.Empty);
            WriteUInt32(stream, checked((UInt32)bytes.Length));
            stream.Write(bytes, 0, bytes.Length);
        }

        private static string ReadQString(byte[] data, ref int offset) {
            UInt32 rawLength = ReadUInt32(data, ref offset);
            if (rawLength == UInt32.MaxValue) return null;
            if ((rawLength & 1) != 0 || rawLength > 131072 || offset + rawLength > data.Length)
                throw new InvalidDataException("Invalid QString length");
            string value = Encoding.BigEndianUnicode.GetString(data, offset, (int)rawLength);
            offset += (int)rawLength;
            return value;
        }

        public static byte[] Encode(IDictionary<string, List<string>> map) {
            using (MemoryStream stream = new MemoryStream()) {
                WriteUInt32(stream, QVariantMap);
                WriteUInt32(stream, checked((UInt32)map.Count));
                foreach (string key in map.Keys.OrderBy(k => k, StringComparer.Ordinal)) {
                    WriteQString(stream, key);
                    WriteUInt32(stream, QStringList);
                    List<string> values = map[key] ?? new List<string>();
                    WriteUInt32(stream, checked((UInt32)values.Count));
                    foreach (string value in values) WriteQString(stream, value);
                }
                byte[] payload = stream.ToArray();
                StringBuilder wrapper = new StringBuilder("@Variant(", payload.Length + 10);
                foreach (byte value in payload) wrapper.Append((char)value);
                wrapper.Append(')');
                return Encoding.Unicode.GetBytes(wrapper.ToString());
            }
        }

        public static Dictionary<string, List<string>> Decode(byte[] registryData) {
            Dictionary<string, List<string>> result = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            if (registryData == null || registryData.Length == 0) return result;
            if ((registryData.Length & 1) != 0) throw new InvalidDataException("Invalid UTF-16 registry value");
            string wrapper = Encoding.Unicode.GetString(registryData);
            const string prefix = "@Variant(";
            if (!wrapper.StartsWith(prefix, StringComparison.Ordinal) || !wrapper.EndsWith(")", StringComparison.Ordinal))
                throw new InvalidDataException("ExceptSites is not a Qt @Variant value");
            string inner = wrapper.Substring(prefix.Length, wrapper.Length - prefix.Length - 1);
            byte[] payload = new byte[inner.Length];
            for (int i = 0; i < inner.Length; ++i) {
                if (inner[i] > 255) throw new InvalidDataException("Invalid byte in Qt wrapper");
                payload[i] = (byte)inner[i];
            }
            int offset = 0;
            if (ReadUInt32(payload, ref offset) != QVariantMap) throw new InvalidDataException("Root QVariant is not a map");
            UInt32 count = ReadUInt32(payload, ref offset);
            if (count > 8192) throw new InvalidDataException("Too many ExceptSites entries");
            for (UInt32 i = 0; i < count; ++i) {
                string key = ReadQString(payload, ref offset);
                UInt32 type = ReadUInt32(payload, ref offset);
                List<string> values = new List<string>();
                if (type == QString) {
                    values.Add(ReadQString(payload, ref offset) ?? String.Empty);
                } else if (type == QStringList) {
                    UInt32 valueCount = ReadUInt32(payload, ref offset);
                    if (valueCount > 4096) throw new InvalidDataException("Too many values for ExceptSites entry");
                    for (UInt32 j = 0; j < valueCount; ++j) values.Add(ReadQString(payload, ref offset) ?? String.Empty);
                } else {
                    throw new InvalidDataException("Unsupported QVariant type in ExceptSites: " + type);
                }
                if (result.ContainsKey(key)) throw new InvalidDataException("Duplicate ExceptSites key");
                result.Add(key, values);
            }
            if (offset != payload.Length) throw new InvalidDataException("Trailing data in ExceptSites QVariantMap");
            return result;
        }
    }
}
'@

Add-Type -TypeDefinition $QtCodecSource -Language CSharp

function Assert-QtCodec {
    $fixture = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]'
    $fixture.Add('198.51.100.20/32', (New-Object 'System.Collections.Generic.List[string]'))
    $fixture.Add('203.0.113.100/32', (New-Object 'System.Collections.Generic.List[string]'))
    $expected = 'QABWAGEAcgBpAGEAbgB0ACgAAAAAAAAACAAAAAAAAAACAAAAAAAAACAAAAAxAAAAOQAAADgAAAAuAAAANQAAADEAAAAuAAAAMQAAADAAAAAwAAAALgAAADIAAAAwAAAALwAAADMAAAAyAAAAAAAAAAsAAAAAAAAAAAAAAAAAAAAgAAAAMgAAADAAAAAzAAAALgAAADAAAAAuAAAAMQAAADEAAAAzAAAALgAAADEAAAAwAAAAMAAAAC8AAAAzAAAAMgAAAAAAAAALAAAAAAAAAAAAKQA='
    $encoded = [AmneziaRouteSync.QtVariantMapCodec]::Encode($fixture)
    if ([Convert]::ToBase64String($encoded) -cne $expected) {
        throw 'Qt QVariantMap codec self-test failed; Registry не изменён.'
    }
    $decoded = [AmneziaRouteSync.QtVariantMapCodec]::Decode($encoded)
    if ($decoded.Count -ne 2 -or -not $decoded.ContainsKey('203.0.113.100/32')) {
        throw 'Qt QVariantMap codec round-trip failed; Registry не изменён.'
    }
    $manualFixture = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]'
    $manualFixture.Add('203.0.113.100/32', (New-Object 'System.Collections.Generic.List[string]'))
    $manualValues = New-Object 'System.Collections.Generic.List[string]'
    $manualValues.Add('198.51.100.7')
    $manualFixture.Add('example.com', $manualValues)
    $manualExpected = 'QABWAGEAcgBpAGEAbgB0ACgAAAAAAAAACAAAAAAAAAACAAAAAAAAACAAAAAyAAAAMAAAADMAAAAuAAAAMAAAAC4AAAAxAAAAMQAAADMAAAAuAAAAMQAAADAAAAAwAAAALwAAADMAAAAyAAAAAAAAAAsAAAAAAAAAAAAAAAAAAAAWAAAAZQAAAHgAAABhAAAAbQAAAHAAAABsAAAAZQAAAC4AAABjAAAAbwAAAG0AAAAAAAAACwAAAAAAAAABAAAAAAAAABgAAAAxAAAAOQAAADgAAAAuAAAANQAAADEAAAAuAAAAMQAAADAAAAAwAAAALgAAADcAKQA='
    $manualEncoded = [AmneziaRouteSync.QtVariantMapCodec]::Encode($manualFixture)
    if ([Convert]::ToBase64String($manualEncoded) -cne $manualExpected) {
        throw 'Qt QVariantMap manual-entry fixture failed; Registry не изменён.'
    }
    $manualDecoded = [AmneziaRouteSync.QtVariantMapCodec]::Decode($manualEncoded)
    if ($manualDecoded['example.com'].Count -ne 1 -or $manualDecoded['example.com'][0] -cne '198.51.100.7') {
        throw 'Qt QVariantMap manual-entry round-trip failed; Registry не изменён.'
    }
}

# --- файлы состояния ----------------------------------------------------------

function Write-JsonAtomic([string]$Path, $Value) {
    $directory = Split-Path -Parent $Path
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $temporary = "$Path.tmp.$PID"
    try {
        $json = $Value | ConvertTo-Json -Depth 12
        [IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $Path) }
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Write-TextAtomic([string]$Path, [string]$Text) {
    $directory = Split-Path -Parent $Path
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $temporary = "$Path.tmp.$PID"
    try {
        [IO.File]::WriteAllText($temporary, $Text, (New-Object Text.UTF8Encoding($false)))
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $Path) }
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Read-JsonFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Read-ManagedEntries {
    $value = Read-JsonFile $ManagedPath
    if ($null -eq $value) { return @() }
    return @($value | ForEach-Object { [string]$_ })
}

# --- IPv4 ---------------------------------------------------------------------

function ConvertTo-IPv4Number([string]$Address) {
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $parsed.ToString() -cne $Address) {
        throw "Некорректный IPv4: $Address"
    }
    $bytes = $parsed.GetAddressBytes()
    return ([uint64]$bytes[0] -shl 24) -bor ([uint64]$bytes[1] -shl 16) -bor ([uint64]$bytes[2] -shl 8) -bor [uint64]$bytes[3]
}

function ConvertFrom-IPv4Number([uint64]$Address) {
    return '{0}.{1}.{2}.{3}' -f (($Address -shr 24) -band 255), (($Address -shr 16) -band 255), (($Address -shr 8) -band 255), ($Address -band 255)
}

function Get-PrefixMask([int]$Prefix) {
    if ($Prefix -eq 0) { return [uint64]0 }
    return (([uint64]4294967295 -shl (32 - $Prefix)) -band [uint64]4294967295)
}

function New-Cidr([uint64]$Network, [int]$Prefix) {
    $mask = Get-PrefixMask $Prefix
    if (($Network -band $mask) -ne $Network) { throw 'CIDR не является network address' }
    return [pscustomobject]@{
        Text    = "$(ConvertFrom-IPv4Number $Network)/$Prefix"
        Prefix  = $Prefix
        Network = $Network
        Mask    = $mask
        Count   = [uint64]1 -shl (32 - $Prefix)
    }
}

function ConvertTo-Cidr([string]$Value) {
    if ($Value.Contains('/')) {
        $parts = $Value.Split('/')
        if ($parts.Count -ne 2) { throw "Некорректный CIDR: $Value" }
        $prefix = 0
        if (-not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 0 -or $prefix -gt 32) {
            throw "Некорректный CIDR: $Value"
        }
        return (New-Cidr (ConvertTo-IPv4Number $parts[0]) $prefix)
    }
    return (New-Cidr (ConvertTo-IPv4Number $Value) 32)
}

$ReservedRanges = @(
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'
)
$ReservedIntervals = @($ReservedRanges | ForEach-Object {
    $cidr = ConvertTo-Cidr $_
    [pscustomobject]@{ Start = $cidr.Network; End = $cidr.Network + $cidr.Count - 1 }
})

function Test-CidrGlobal($Cidr) {
    $start = [uint64]$Cidr.Network
    $end = [uint64]($Cidr.Network + $Cidr.Count - 1)
    foreach ($range in $ReservedIntervals) {
        if ($start -le $range.End -and $range.Start -le $end) { return $false }
    }
    return $true
}

function Compress-Cidrs($Cidrs) {
    $sorted = @($Cidrs | Sort-Object -Property @{ Expression = { $_.Network } }, @{ Expression = { $_.Prefix } })
    $stack = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in $sorted) {
        $current = $item
        while ($null -ne $current -and $stack.Count -gt 0) {
            $top = $stack[$stack.Count - 1]
            $topEnd = [uint64]($top.Network + $top.Count - 1)
            $currentEnd = [uint64]($current.Network + $current.Count - 1)
            if ($current.Network -ge $top.Network -and $currentEnd -le $topEnd) {
                $current = $null
                break
            }
            if ($top.Prefix -eq $current.Prefix -and $top.Prefix -gt 0 -and
                $current.Network -eq ($top.Network + $top.Count)) {
                $parentMask = Get-PrefixMask ($top.Prefix - 1)
                if (($top.Network -band $parentMask) -eq $top.Network) {
                    $stack.RemoveAt($stack.Count - 1)
                    $current = New-Cidr $top.Network ($top.Prefix - 1)
                    continue
                }
            }
            break
        }
        if ($null -ne $current) { $stack.Add($current) }
    }
    return @($stack.ToArray())
}

function Test-Hostname([string]$Value) {
    if (-not $Value -or $Value.Length -gt 253 -or -not $Value.Contains('.')) { return $false }
    if ($Value -cne $Value.ToLowerInvariant()) { return $false }
    if ($Value.StartsWith('.') -or $Value.StartsWith('-') -or $Value.EndsWith('.') -or $Value.EndsWith('-')) { return $false }
    if ($Value -notmatch '^[a-z0-9.-]+$') { return $false }
    foreach ($label in $Value.Split('.')) {
        if ($label.Length -lt 1 -or $label.Length -gt 63) { return $false }
        if ($label.StartsWith('-') -or $label.EndsWith('-')) { return $false }
    }
    return $true
}

# --- загрузка и проверка списка ------------------------------------------------

function Get-HttpsText([string]$Url) {
    if (-not $Url.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) { throw "Разрешён только HTTPS: $Url" }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('Amnezia-Split-Route-Sync-Windows/2.0')
    $response = $null
    $stream = $null
    $memory = $null
    $cancellation = New-Object Threading.CancellationTokenSource
    $cancellation.CancelAfter(60000)
    try {
        $response = $client.GetAsync($Url, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancellation.Token).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) { throw "Источник вернул HTTP $([int]$response.StatusCode): $Url" }
        if ($null -ne $response.Content.Headers.ContentLength -and [long]$response.Content.Headers.ContentLength -gt $MaxListBytes) {
            throw "Источник больше $MaxListBytes байт: $Url"
        }
        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $memory = New-Object IO.MemoryStream
        $buffer = New-Object byte[] 65536
        $total = 0
        while (($read = $stream.ReadAsync($buffer, 0, $buffer.Length, $cancellation.Token).GetAwaiter().GetResult()) -gt 0) {
            $total += $read
            if ($total -gt $MaxListBytes) { throw "Источник больше $MaxListBytes байт: $Url" }
            $memory.Write($buffer, 0, $read)
        }
        if ($total -eq 0) { throw "Источник пуст: $Url" }
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        return $utf8.GetString($memory.ToArray())
    } catch [Threading.Tasks.TaskCanceledException] {
        # HttpClient переводит собственный таймаут именно в это исключение, а
        # необработанным оно вылезает в консоль как «Отменена задача» без единого
        # намёка на причину.
        throw "Источник не ответил за 60 секунд: $Url"
    } catch [OperationCanceledException] {
        throw "Источник не ответил за 60 секунд: $Url"
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $memory) { $memory.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        $cancellation.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

function Get-SourceText([string]$SourceValue) {
    if ($SourceValue.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        # Задача по расписанию просыпается вместе с сетью, а список тянется из-за
        # рубежа: одна заминка не должна отменять весь запуск на шесть часов.
        $attempt = 0
        while ($true) {
            $attempt++
            try { return (Get-HttpsText $SourceValue) } catch {
                if ($attempt -ge 3) { throw }
                Write-Host "Загрузка не удалась ($($_.Exception.Message)), попытка $attempt из 3"
                Start-Sleep -Seconds (5 * $attempt)
            }
        }
    }
    if (-not (Test-Path -LiteralPath $SourceValue -PathType Leaf)) { throw "Не найден файл списка: $SourceValue" }
    $info = Get-Item -LiteralPath $SourceValue
    if ($info.Length -gt $MaxListBytes) { throw "Файл списка больше $MaxListBytes байт: $SourceValue" }
    return [IO.File]::ReadAllText($SourceValue, (New-Object Text.UTF8Encoding($false, $true)))
}

function ConvertFrom-ImportList([string]$Text, [string]$SourceName) {
    # Формат импорта Amnezia: [{"hostname": "<домен или CIDR>", "ip": ""}]
    $document = $null
    try { $document = $Text | ConvertFrom-Json } catch { throw "${SourceName}: список не является валидным JSON" }
    $entries = @($document)
    if ($entries.Count -eq 0) { throw "${SourceName}: ожидается непустой массив записей" }

    $domains = New-Object 'System.Collections.Generic.List[string]'
    $networks = New-Object 'System.Collections.Generic.List[object]'
    $snapshotAddresses = @{}
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $index = -1
    foreach ($entry in $entries) {
        $index++
        if ($null -eq $entry -or $entry -isnot [psobject] -or
            ($entry.PSObject.Properties.Name -notcontains 'hostname')) {
            throw "${SourceName}: запись $index без hostname"
        }
        $value = [string]$entry.hostname
        if (-not $value -or -not $value.Trim()) { throw "${SourceName}: запись $index без hostname" }
        $value = $value.Trim().ToLowerInvariant().TrimEnd('.')
        if (-not $seen.Add($value)) { continue }

        if ($value.Contains('/') -or $value -match '^[0-9.]+$') {
            $cidr = ConvertTo-Cidr $value
            if ($cidr.Prefix -lt $MinimumPrefix) { throw "${SourceName}: слишком широкая сеть $value" }
            if (-not (Test-CidrGlobal $cidr)) { throw "${SourceName}: сеть $value не является публичной" }
            $networks.Add($cidr)
            continue
        }
        if (-not (Test-Hostname $value)) { throw "${SourceName}: некорректный домен $value" }
        $domains.Add($value)
        $values = @()
        if ($entry.PSObject.Properties.Name -contains 'ips') { $values += @($entry.ips) }
        if ($entry.PSObject.Properties.Name -contains 'ip') { $values += @($entry.ip) }
        $ips = @(Get-PublicIPv4Values $values | Sort-Object -Unique)
        if ($ips.Count -gt 0) { $snapshotAddresses[$value] = $ips }
    }

    $total = $domains.Count + $networks.Count
    if ($total -lt $MinimumEntries -or $total -gt $MaximumEntries) {
        throw "${SourceName}: $total записей вне допустимого диапазона $MinimumEntries..$MaximumEntries"
    }

    $collapsed = @(Compress-Cidrs $networks.ToArray())
    if ($collapsed.Count -lt $MinimumRoutes -or $collapsed.Count -gt $MaximumRoutes) {
        throw "подозрительное число маршрутов: $($collapsed.Count) (допустимо $MinimumRoutes..$MaximumRoutes)"
    }
    $covered = [uint64]0
    foreach ($cidr in $collapsed) { $covered += $cidr.Count }
    if ($covered -gt $MaximumAddresses) { throw "список покрывает слишком много IPv4-адресов: $covered" }

    $sortedDomains = @($domains.ToArray() | Sort-Object -CaseSensitive)
    return [pscustomobject]@{
        Domains = $sortedDomains
        Cidrs   = @($collapsed | ForEach-Object { $_.Text })
        DomainAddresses = $snapshotAddresses
    }
}

# --- локальные подсети ---------------------------------------------------------

function Test-CidrPrivate($Cidr) {
    foreach ($range in $PrivateSubnetRanges) {
        $parent = ConvertTo-Cidr $range
        if ($Cidr.Prefix -ge $parent.Prefix -and ($Cidr.Network -band $parent.Mask) -eq $parent.Network) {
            return $true
        }
    }
    return $false
}

function Get-LocalSubnetEntries {
    if ($NoLocalSubnets) { return @() }
    return @($PrivateSubnetRanges)
}

# --- IPv6 -----------------------------------------------------------------------

# AmneziaVPN исключает из туннеля только IPv4: в конфиге AllowedIPs = 0.0.0.0/0, ::/0,
# а ExceptSites разбирается регуляркой по IPv4-адресам. Весь IPv6 всегда уходит в VPN.
# Если у провайдера IPv6 есть, а внутри туннеля он не работает, браузер всё равно
# пробует AAAA — и страницы вроде оплаты Яндекс Директа (trust.yandex.ru) не грузятся.
$IPv6ProbeAddress = '2a02:6b8::347'   # trust.yandex.ru, платёжная форма Яндекса
$IPv6ProbePort = 443
$IPv6ProbeTimeoutMs = 4000

function Test-IPv6Reachable {
    $client = $null
    try {
        $client = New-Object Net.Sockets.TcpClient([Net.Sockets.AddressFamily]::InterNetworkV6)
        $async = $client.BeginConnect($IPv6ProbeAddress, $IPv6ProbePort, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($IPv6ProbeTimeoutMs, $false)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        if ($client) { try { $client.Close() } catch { } }
    }
}

function Write-IPv6TunnelWarning {
    $tunnelAliases = $null
    $routes = @()
    $addresses = @()
    try {
        $tunnelAliases = Get-TunnelAliases
        $routes = @(Get-NetRoute -AddressFamily IPv6 -ErrorAction Stop |
            Where-Object { $_.DestinationPrefix -in @('::/0', '::/1') })
        $addresses = @(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction Stop)
    } catch {
        # Диагностика необязательна: нет NetTCPIP — просто молчим.
        return
    }

    $tunnelRoutes = @($routes | Where-Object { $tunnelAliases.Contains([string]$_.InterfaceAlias) })
    if ($tunnelRoutes.Count -eq 0) { return }

    # Глобальный IPv6 (2000::/3) на обычном адаптере: значит провайдер IPv6 выдал.
    $nativeAliases = New-Object 'System.Collections.Generic.List[string]'
    foreach ($address in $addresses) {
        $alias = [string]$address.InterfaceAlias
        if ($tunnelAliases.Contains($alias)) { continue }
        $value = [string]$address.IPAddress
        if ($value -notmatch '^[23]') { continue }
        if (-not $nativeAliases.Contains($alias)) { $nativeAliases.Add($alias) }
    }
    if ($nativeAliases.Count -eq 0) { return }
    if (Test-IPv6Reachable) { return }

    $tunnelNames = @($tunnelRoutes | ForEach-Object { [string]$_.InterfaceAlias } | Sort-Object -Unique)
    $adapter = $nativeAliases[0]
    Write-Warning "IPv6 уходит в туннель ($($tunnelNames -join ', ')) и там не работает: соединение с [$IPv6ProbeAddress]:$IPv6ProbePort не установилось."
    Write-Host '  Список RU Direct это не лечит: AmneziaVPN исключает из VPN только IPv4.'
    Write-Host '  Сайты с AAAA (Яндекс Директ и его оплата, trust.yandex.ru, pay.yandex.ru, yandex.ru)'
    Write-Host '  браузер пробует по IPv6 через VPN — страницы и платёжные формы виснут или не грузятся.'
    Write-Host "  Отключите IPv6 на адаптере (PowerShell от администратора):"
    Write-Host "    Disable-NetAdapterBinding -Name `"$adapter`" -ComponentID ms_tcpip6"
    Write-Host "  Вернуть обратно:"
    Write-Host "    Enable-NetAdapterBinding -Name `"$adapter`" -ComponentID ms_tcpip6"
}

# --- DNS для Windows -----------------------------------------------------------

# AmneziaWG использует IP из значений ExceptSites; сам ключ-домен не резолвит.
# DNS выполняется до остановки VPN, максимум 24 незавершённых запроса и 45 секунд
# на весь список. При сбое сохраняются прежние публичные IPv4 этого домена.
function Start-DomainLookup([string]$Hostname) {
    return ,([Net.Dns]::GetHostAddressesAsync($Hostname))
}

function Get-PublicIPv4Values($Values) {
    foreach ($value in @($Values)) {
        $address = $null
        if ([Net.IPAddress]::TryParse([string]$value, [ref]$address) -and
            $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
            $canonical = $address.ToString()
            if (Test-CidrGlobal (ConvertTo-Cidr $canonical)) { $canonical }
        }
    }
}

function Resolve-ManagedDomains([string[]]$Domains, [int]$TimeoutSeconds = 45, [int]$Concurrency = 24) {
    $addresses = @{}
    $previousAddresses = @{}
    if ($Domains.Count -eq 0) {
        return [pscustomobject]@{ Addresses = $addresses; PreviousAddresses = $previousAddresses; Cached = $false
            Cache = [ordered]@{ version = 1; updated_at = [DateTime]::UtcNow.ToString('o'); domains = @(); addresses = @{} } }
    }
    $cached = $null
    try { $cached = Read-JsonFile $DnsCachePath } catch { Write-Warning 'Кэш DNS повреждён; обновляю его.' }
    if ($null -ne $cached) {
        try {
            if ($cached.version -ne 1) { throw 'Unknown DNS cache version' }
            # После перехода на CIDR в реестре больше нет имён доменов. Храним
            # последние рабочие IP отдельно от свежих ответов, включая старый кэш v1.
            $previous = $cached.addresses
            if ($cached.PSObject.Properties.Name -contains 'last_known_addresses') {
                $previous = $cached.last_known_addresses
            }
            foreach ($entry in $previous.PSObject.Properties) {
                $ips = @(Get-PublicIPv4Values $entry.Value | Sort-Object -Unique)
                if ($ips.Count -gt 0) { $previousAddresses[$entry.Name] = $ips }
            }
            # PowerShell 7.5+ автоматически превращает ISO-время из JSON в DateTime.
            $updated = if ($cached.updated_at -is [DateTime]) { $cached.updated_at }
                       else { [DateTime]::Parse([string]$cached.updated_at, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
            $age = [DateTime]::UtcNow - $updated.ToUniversalTime()
            $known = @($cached.domains)
            $requested = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
            foreach ($domain in $Domains) { [void]$requested.Add($domain) }
            $knownSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
            foreach ($domain in $known) { [void]$knownSet.Add([string]$domain) }
            if ($age.TotalHours -ge 0 -and $age.TotalHours -lt 4 -and
                $requested.IsSubsetOf($knownSet)) {
                foreach ($entry in $cached.addresses.PSObject.Properties) {
                    if (-not $requested.Contains($entry.Name)) { continue }
                    $ips = @(Get-PublicIPv4Values $entry.Value | Sort-Object -Unique)
                    if ($ips.Count -gt 0) { $addresses[$entry.Name] = $ips }
                }
                return [pscustomobject]@{ Addresses = $addresses; PreviousAddresses = $previousAddresses; Cache = $cached; Cached = $true }
            }
        } catch { Write-Warning 'Кэш DNS несовместим; обновляю его.' }
    }

    $pending = @{}
    $next = 0
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (($next -lt $Domains.Count -or $pending.Count -gt 0) -and $timer.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        while ($next -lt $Domains.Count -and $pending.Count -lt $Concurrency) {
            $domain = $Domains[$next++]
            try { $pending[$domain] = Start-DomainLookup $domain } catch { }
        }
        foreach ($domain in @($pending.Keys)) {
            $lookup = $pending[$domain]
            if (-not $lookup.IsCompleted) { continue }
            try {
                $ips = @(Get-PublicIPv4Values ($lookup.GetAwaiter().GetResult()) | Sort-Object -Unique)
                if ($ips.Count -gt 0) { $addresses[$domain] = $ips }
            } catch { }
            $pending.Remove($domain)
        }
        if ($pending.Count -gt 0) { Start-Sleep -Milliseconds 25 }
    }
    $failed = $Domains.Count - $addresses.Count
    # addresses содержит только свежие ответы; fallback учитывается отдельно.
    $cache = [ordered]@{ version = 1; updated_at = [DateTime]::UtcNow.ToString('o'); domains = @($Domains); addresses = $addresses.Clone() }
    if ($failed -gt 0) { Write-Warning "DNS: для $failed из $($Domains.Count) доменов нет свежего публичного IPv4; сохранены прежние IP, если они были." }
    return [pscustomobject]@{ Addresses = $addresses; PreviousAddresses = $previousAddresses; Cache = $cache; Cached = $false }
}

function Get-ManagedRoutePlan($List, $Dns, $Current, [string[]]$PreviousManaged) {
    $networks = New-Object 'System.Collections.Generic.List[object]'
    foreach ($value in $List.Cidrs) { $networks.Add((ConvertTo-Cidr $value)) }
    $owned = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($value in $PreviousManaged) { [void]$owned.Add($value) }
    $domainAddresses = @{}
    $unresolved = 0
    foreach ($domain in $List.Domains) {
        $sources = @($Dns.Addresses, $Dns.PreviousAddresses)
        if ($owned.Contains($domain)) { $sources += $Current }
        $sources += $List.DomainAddresses
        $ips = @()
        foreach ($sourceAddresses in $sources) {
            if (-not $sourceAddresses.ContainsKey($domain)) { continue }
            $ips = @(Get-PublicIPv4Values $sourceAddresses[$domain] | Sort-Object -Unique)
            if ($ips.Count -gt 0) { break }
        }
        if ($ips.Count -eq 0) { $unresolved++; continue }
        $domainAddresses[$domain] = $ips
        foreach ($ip in $ips) { $networks.Add((ConvertTo-Cidr $ip)) }
    }
    # Сжимаем всё объединение: одинаковые IP разных доменов, /32 внутри BGP-сети
    # и смежные сети. Имена и пустые IP не передаём в демон (там они дают /999999).
    $collapsed = @(Compress-Cidrs $networks.ToArray())
    if ($collapsed.Count -gt $MaximumEffectiveRoutes) {
        throw "После DNS осталось $($collapsed.Count) маршрутов (лимит $MaximumEffectiveRoutes). Используйте -Lite; настройки не изменены."
    }
    $covered = [uint64]0
    foreach ($cidr in $collapsed) { $covered += $cidr.Count }
    if ($covered -gt $MaximumAddresses) { throw "DNS-список покрывает слишком много IPv4: $covered" }
    return [pscustomobject]@{
        Entries = @($collapsed | ForEach-Object { $_.Text })
        DomainAddresses = $domainAddresses
        InputRouteCount = $networks.Count
        RemovedRouteCount = $networks.Count - $collapsed.Count
        UnresolvedDomainCount = $unresolved
    }
}

# --- реестр -------------------------------------------------------------------

function Read-ExceptSites {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $false)
    if ($null -eq $key) { return @{} }
    try {
        $value = $key.GetValue('ExceptSites', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -eq $value) { return @{} }
        if (-not ($value -is [byte[]])) { throw 'Conf\ExceptSites имеет неожиданный тип Registry' }
        $decoded = [AmneziaRouteSync.QtVariantMapCodec]::Decode([byte[]]$value)
        $result = @{}
        foreach ($entry in $decoded.GetEnumerator()) { $result[$entry.Key] = @($entry.Value) }
        return $result
    } finally { $key.Dispose() }
}

function Read-RoutingScalars {
    $result = [ordered]@{ mode = $null; enabled = $null; apps_enabled = $null }
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $false)
    if ($null -eq $key) { return $result }
    try {
        $names = @($key.GetValueNames())
        if ($names -contains 'routeMode') { $result.mode = [string]$key.GetValue('routeMode') }
        if ($names -contains 'sitesSplitTunnelingEnabled') { $result.enabled = [string]$key.GetValue('sitesSplitTunnelingEnabled') }
        if ($names -contains 'appsSplitTunnelingEnabled') { $result.apps_enabled = [string]$key.GetValue('appsSplitTunnelingEnabled') }
    } finally { $key.Dispose() }
    return $result
}

function Assert-SafeAmneziaRestart($Session) {
    if (-not ($Session.GuiRunning -or $Session.Connected)) { return }
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $false)
    # Missing or unrecognized settings cannot establish that the user disabled
    # protection. Never turn an uncertain setting into permission to disconnect.
    $killSwitch = $null
    try {
        if ($null -ne $key) { $killSwitch = $key.GetValue('killSwitchEnabled', $null) }
    } finally { if ($null -ne $key) { $key.Dispose() } }
    if ([string]$killSwitch -in @('false', '0')) { return }
    if ($AllowVpnReconnect) {
        Write-Warning 'Разрешён перезапуск Amnezia: штатное отключение снимает KillSwitch. До восстановления VPN возможен прямой трафик.'
        return
    }
    throw ('Обновление отложено: Amnezia работает, а KillSwitch включён или его состояние неизвестно. ' +
           'Штатное отключение снимает защиту; updater не будет закрывать GUI и туннель. ' +
           'Для разового осознанного переподключения используйте -AllowVpnReconnect после подготовки независимой защиты. ' +
           'Этот флаг сам не блокирует трафик без VPN.')
}

function ConvertTo-QtMap($Sites) {
    $map = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]' ([StringComparer]::Ordinal)
    foreach ($key in @($Sites.Keys)) {
        $values = New-Object 'System.Collections.Generic.List[string]'
        foreach ($value in @($Sites[$key])) { if ($null -ne $value) { $values.Add([string]$value) } }
        $map.Add([string]$key, $values)
    }
    return $map
}

function Read-RoutingRegistrySnapshot {
    $items = [ordered]@{}
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $false)
    try {
        $valueNames = if ($null -ne $key) { @($key.GetValueNames()) } else { @() }
        foreach ($name in $RoutingValueNames) {
            if ($name -notin $valueNames) {
                $items[$name] = [ordered]@{ present = $false }
                continue
            }
            $kind = $key.GetValueKind($name)
            $value = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $encoded = switch ($kind) {
                ([Microsoft.Win32.RegistryValueKind]::Binary) { [Convert]::ToBase64String([byte[]]$value); break }
                ([Microsoft.Win32.RegistryValueKind]::DWord) { [string][uint32]$value; break }
                ([Microsoft.Win32.RegistryValueKind]::QWord) { [string][uint64]$value; break }
                ([Microsoft.Win32.RegistryValueKind]::MultiString) { @([string[]]$value); break }
                ([Microsoft.Win32.RegistryValueKind]::String) { [string]$value; break }
                ([Microsoft.Win32.RegistryValueKind]::ExpandString) { [string]$value; break }
                default { throw "Неподдерживаемый Registry type $kind для $name" }
            }
            $items[$name] = [ordered]@{ present = $true; kind = $kind.ToString(); value = $encoded }
        }
    } finally {
        if ($null -ne $key) { $key.Dispose() }
    }
    return [ordered]@{ version = 1; values = $items }
}

function Restore-RoutingRegistrySnapshot($Snapshot) {
    if ($null -eq $Snapshot -or $Snapshot.version -ne 1) { throw 'Неизвестная версия routing Registry backup' }
    $actual = @($Snapshot.values.PSObject.Properties.Name | Sort-Object)
    if (($actual -join ',') -cne (@($RoutingValueNames | Sort-Object) -join ',')) {
        throw 'Routing Registry backup имеет неожиданные поля'
    }
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($RegistryConfSubKey, $true)
    try {
        foreach ($name in $RoutingValueNames) {
            $key.DeleteValue($name, $false)
            $item = $Snapshot.values.PSObject.Properties[$name].Value
            if (-not [bool]$item.present) { continue }
            $kind = [Microsoft.Win32.RegistryValueKind][Enum]::Parse([Microsoft.Win32.RegistryValueKind], [string]$item.kind, $false)
            $value = switch ($kind) {
                ([Microsoft.Win32.RegistryValueKind]::Binary) { ,([Convert]::FromBase64String([string]$item.value)); break }
                ([Microsoft.Win32.RegistryValueKind]::DWord) { [uint32]::Parse([string]$item.value); break }
                ([Microsoft.Win32.RegistryValueKind]::QWord) { [uint64]::Parse([string]$item.value); break }
                ([Microsoft.Win32.RegistryValueKind]::MultiString) { ,([string[]]@($item.value)); break }
                ([Microsoft.Win32.RegistryValueKind]::String) { [string]$item.value; break }
                ([Microsoft.Win32.RegistryValueKind]::ExpandString) { [string]$item.value; break }
                default { throw "Неподдерживаемый Registry type $kind для $name" }
            }
            $key.SetValue($name, $value, $kind)
        }
        $key.Flush()
    } finally { $key.Dispose() }
}

function Write-RoutingRegistry($Sites) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($RegistryConfSubKey, $true)
    try {
        $key.SetValue('ExceptSites', [AmneziaRouteSync.QtVariantMapCodec]::Encode((ConvertTo-QtMap $Sites)), [Microsoft.Win32.RegistryValueKind]::Binary)
        $key.SetValue('routeMode', $RouteModeVpnAllExceptSites, [Microsoft.Win32.RegistryValueKind]::DWord)
        $key.SetValue('sitesSplitTunnelingEnabled', 'true', [Microsoft.Win32.RegistryValueKind]::String)
        $key.Flush()
    } finally { $key.Dispose() }
}

function Assert-RoutingRegistry($Sites) {
    $verified = Read-ExceptSites
    foreach ($entry in $Sites.GetEnumerator()) {
        if (-not $verified.ContainsKey($entry.Key)) { throw "Read-back не содержит запись $($entry.Key)" }
        if ((@($verified[$entry.Key]) -join "`n") -cne (@($entry.Value) -join "`n")) {
            throw "Read-back изменил значение $($entry.Key)"
        }
    }
    if ($verified.Count -ne $Sites.Count) { throw 'Read-back содержит лишние записи' }
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $false)
    if ($null -eq $key) { throw 'Read-back не нашёл ключ Conf' }
    try {
        if ($key.GetValueKind('routeMode') -ne [Microsoft.Win32.RegistryValueKind]::DWord -or
            [int]$key.GetValue('routeMode') -ne $RouteModeVpnAllExceptSites) {
            throw "Read-back routeMode не равен DWORD $RouteModeVpnAllExceptSites"
        }
        if ($key.GetValueKind('sitesSplitTunnelingEnabled') -ne [Microsoft.Win32.RegistryValueKind]::String -or
            [string]$key.GetValue('sitesSplitTunnelingEnabled') -cne 'true') {
            throw 'Read-back sitesSplitTunnelingEnabled не равен true'
        }
    } finally { $key.Dispose() }
}

function Get-DesiredSites($Current, [string[]]$PreviousManaged, [string[]]$Entries, $DomainAddresses = @{}) {
    $desired = @{}
    if (-not $ReplaceAll) {
        $previous = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($value in @($PreviousManaged)) { [void]$previous.Add($value) }
        foreach ($entry in $Current.GetEnumerator()) {
            if (-not $previous.Contains($entry.Key)) { $desired[$entry.Key] = @($entry.Value) }
        }
    }
    # Amnezia дописывает в значение записи резолвнутые IP домена. Затирать их
    # пустым списком нельзя: иначе каждый запуск видел бы «список изменился»
    # и дёргал GUI с туннелем на ровном месте.
    foreach ($entry in @($Entries)) {
        if ($DomainAddresses.ContainsKey($entry)) { $desired[$entry] = @($DomainAddresses[$entry]) }
        elseif ((Test-Hostname $entry) -and $Current.ContainsKey($entry)) {
            $desired[$entry] = @(Get-PublicIPv4Values $Current[$entry] | Sort-Object -Unique)
        }
        elseif ($Current.ContainsKey($entry) -and -not $entry.Contains('/')) { $desired[$entry] = @($Current[$entry]) }
        else { $desired[$entry] = @() }
    }
    if ($desired.Count -gt $MaxRegistryEntries) {
        throw "итоговый список из $($desired.Count) записей превышает лимит $MaxRegistryEntries"
    }
    return $desired
}

function Test-SitesEqual($Left, $Right) {
    if ($Left.Count -ne $Right.Count) { return $false }
    foreach ($entry in $Left.GetEnumerator()) {
        if (-not $Right.ContainsKey($entry.Key)) { return $false }
        if ((@($entry.Value) -join "`n") -cne (@($Right[$entry.Key]) -join "`n")) { return $false }
    }
    return $true
}

# --- процессы, службы, сессия --------------------------------------------------

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-GuiProcesses {
    $currentSessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    return @(Get-Process -Name $GuiProcessName -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $currentSessionId })
}

# return @(...) разворачивает массив обратно в один объект, поэтому оборачиваем
# результат на каждой стороне вызова: под Set-StrictMode .Count на Process падает.
function Test-GuiRunning { return @(Get-GuiProcesses).Count -gt 0 }

function Get-AmneziaService {
    $service = Get-Service -Name $DaemonServiceName -ErrorAction SilentlyContinue
    if ($null -ne $service) { return $service }
    $candidates = @(Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'Amnezia*' -and $_.Name -notlike '*Tunnel*' })
    if ($candidates.Count -eq 1) { return $candidates[0] }
    return $null
}

function Get-TunnelService {
    $service = Get-Service -Name $TunnelServiceName -ErrorAction SilentlyContinue
    if ($null -ne $service) { return $service }
    $candidates = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Tunnel$AmneziaVPN' })
    if ($candidates.Count -eq 1) { return $candidates[0] }
    return $null
}

function Test-TunnelServiceRunning {
    $tunnel = Get-TunnelService
    if ($null -eq $tunnel) { return $false }
    try {
        $tunnel.Refresh()
        return ($tunnel.Status -eq [ServiceProcess.ServiceControllerStatus]::Running -or
                $tunnel.Status -eq [ServiceProcess.ServiceControllerStatus]::StartPending)
    } catch {
        if (Test-ServiceMissingError $_.Exception) { return $false }
        throw
    }
}

# WireGuard deletes its temporary service on disconnect. A ServiceController
# obtained just before that deletion can no longer query or wait on it.
function Test-ServiceMissingError([Exception]$Exception) {
    while ($null -ne $Exception) {
        if ($Exception -is [ComponentModel.Win32Exception] -and $Exception.NativeErrorCode -eq 1060) { return $true }
        $Exception = $Exception.InnerException
    }
    return $false
}

function Test-AmneziaAdapter($Adapter) {
    return ($Adapter.OperationalStatus -eq [Net.NetworkInformation.OperationalStatus]::Up -and
            "$($Adapter.Name) $($Adapter.Description)" -match '(?i)amnezia')
}

function Test-VpnAdapterUp {
    foreach ($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if (Test-AmneziaAdapter $adapter) { return $true }
    }
    return $false
}

function Test-AmneziaUserspaceTunnel {
    # OpenVPN/Xray могут использовать TAP/Wintun без имени Amnezia. Проверяем
    # путь процесса, а не общий тип адаптера, который бывает у другого VPN.
    $processes = @(Get-Process -Name 'openvpn', 'xray', 'ss-local' -ErrorAction SilentlyContinue)
    if ($processes.Count -eq 0) { return $false }
    $directory = (Split-Path -Parent (Get-AmneziaExePath)).TrimEnd('\') + '\'
    foreach ($process in $processes) {
        try {
            if ($process.Path -and $process.Path.StartsWith($directory, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        } catch { }
    }
    return $false
}

function Test-TunnelRunning {
    if (Test-TunnelServiceRunning) { return $true }
    return ((Test-VpnAdapterUp) -or (Test-AmneziaUserspaceTunnel))
}

function Test-TunnelReady {
    $tunnel = Get-TunnelService
    if ($null -ne $tunnel) {
        try {
            $tunnel.Refresh()
            return ($tunnel.Status -eq [ServiceProcess.ServiceControllerStatus]::Running -and (Test-VpnAdapterUp) -and (Test-DaemonHandshake))
        } catch {
            if (Test-ServiceMissingError $_.Exception) { return $false }
            throw
        }
    }
    return ((Test-VpnAdapterUp) -or (Test-AmneziaUserspaceTunnel))
}

function Test-DaemonHandshake {
    # Служба и адаптер появляются ДО рукопожатия. Тот же status, который читает
    # GUI: date заполняется демоном только после полученного handshake.
    $pipe = New-Object IO.Pipes.NamedPipeClientStream('.', 'amneziavpn', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
    $reader = $null
    try {
        $pipe.Connect(500)
        $request = [Text.Encoding]::UTF8.GetBytes('{"type":"status"}' + "`n")
        $pipe.Write($request, 0, $request.Length)
        $pipe.Flush()
        $reader = New-Object IO.StreamReader($pipe)
        $reply = $reader.ReadLineAsync()
        if (-not $reply.Wait(1500)) { return $false }
        $statusReply = $reply.GetAwaiter().GetResult() | ConvertFrom-Json
        return ($statusReply.type -eq 'status' -and $statusReply.connected -eq $true -and
            $statusReply.PSObject.Properties.Name -contains 'date' -and
            -not [string]::IsNullOrWhiteSpace([string]$statusReply.date))
    } catch { return $false }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        $pipe.Dispose()
    }
}

function Get-AmneziaExePath {
    foreach ($process in (Get-GuiProcesses)) {
        try {
            if ($process.Path -and (Test-Path -LiteralPath $process.Path -PathType Leaf)) { return $process.Path }
        } catch { }
    }
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    if ($env:ProgramFiles) { $candidates.Add((Join-Path $env:ProgramFiles 'AmneziaVPN\AmneziaVPN.exe')) }
    if (${env:ProgramFiles(x86)}) { $candidates.Add((Join-Path ${env:ProgramFiles(x86)} 'AmneziaVPN\AmneziaVPN.exe')) }
    if ($env:LOCALAPPDATA) { $candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\AmneziaVPN\AmneziaVPN.exe')) }
    $service = Get-AmneziaService
    if ($null -ne $service) {
        $imagePath = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)" -ErrorAction SilentlyContinue).ImagePath
        if ($imagePath) {
            $exe = $imagePath.Trim('"')
            if ($exe -match '^(?<path>.+?\.exe)') { $exe = $Matches['path'] }
            $directory = Split-Path -Parent $exe
            if ($directory) { $candidates.Add((Join-Path $directory 'AmneziaVPN.exe')) }
        }
    }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw 'Не найден AmneziaVPN.exe. Установите AmneziaVPN 5.x и повторите.'
}

function Assert-AmneziaVersion([string]$ExePath) {
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($ExePath).ProductVersion
    $major = 0
    if (-not $version -or -not [int]::TryParse(($version -split '\.')[0], [ref]$major) -or $major -ne $SupportedAppMajor) {
        throw "Поддерживается AmneziaVPN major $SupportedAppMajor, найдена версия $version"
    }
    return $version
}

function Get-AmneziaSession {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $false)
    $autoConnect = $false
    $selectedIndex = $ServerIndex
    try {
        if ($null -ne $key) {
            $names = @($key.GetValueNames())
            if ($names -contains 'autoConnect') { $autoConnect = ([string]$key.GetValue('autoConnect') -ceq 'true') }
        }
    } finally { if ($null -ne $key) { $key.Dispose() } }
    $serversKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryServersSubKey, $false)
    try {
        # В 5.0.1.5 defaultServerIndex может остаться от старой версии, а выбор
        # хранится в defaultServerId. Зашифрованный serversList не читаем.
        if ($selectedIndex -lt 0 -and $null -ne $serversKey -and
            -not $serversKey.GetValue('defaultServerId') -and
            (@($serversKey.GetValueNames()) -contains 'defaultServerIndex')) {
            $raw = $serversKey.GetValue('defaultServerIndex')
            $parsed = 0
            if ([int]::TryParse([string]$raw, [ref]$parsed) -and $parsed -ge 0) { $selectedIndex = $parsed }
        }
    } finally { if ($null -ne $serversKey) { $serversKey.Dispose() } }

    return [pscustomobject]@{
        GuiRunning  = (Test-GuiRunning)
        Connected   = (Test-TunnelRunning)
        AutoConnect = $autoConnect
        ServerIndex = $selectedIndex
    }
}

function ConvertTo-SessionDocument($Session) {
    return [ordered]@{
        gui_running  = [bool]$Session.GuiRunning
        connected    = [bool]$Session.Connected
        auto_connect = [bool]$Session.AutoConnect
        server_index = [int]$Session.ServerIndex
    }
}

function ConvertFrom-SessionDocument($Value) {
    if ($null -eq $Value) { throw 'transaction journal не содержит Amnezia session' }
    foreach ($name in @('gui_running', 'connected', 'auto_connect', 'server_index')) {
        if ($Value.PSObject.Properties.Name -notcontains $name) { throw 'transaction journal содержит неполную Amnezia session' }
    }
    return [pscustomobject]@{
        GuiRunning  = [bool]$Value.gui_running
        Connected   = [bool]$Value.connected
        AutoConnect = [bool]$Value.auto_connect
        ServerIndex = [int]$Value.server_index
    }
}

function Stop-AmneziaGui {
    $processes = @(Get-GuiProcesses)
    if ($processes.Count -eq 0) { return }
    foreach ($process in $processes) {
        try { [void]$process.CloseMainWindow() } catch { }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline -and (Test-GuiRunning)) { Start-Sleep -Milliseconds 250 }
    foreach ($process in (Get-GuiProcesses)) {
        try { $process.Kill() } catch { }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $deadline -and (Test-GuiRunning)) { Start-Sleep -Milliseconds 250 }
    if (Test-GuiRunning) { throw 'AmneziaVPN не завершилась за 25 секунд; Registry не изменён.' }
    # Qt дописывает кэш QSettings в реестр при выходе приложения.
    Start-Sleep -Milliseconds 750
}

function Wait-ServiceStatus($Service, [ServiceProcess.ServiceControllerStatus]$Status, [int]$Seconds) {
    try {
        $Service.WaitForStatus($Status, [TimeSpan]::FromSeconds($Seconds))
        return $true
    } catch [ServiceProcess.TimeoutException] {
        return $false
    } catch {
        if (Test-ServiceMissingError $_.Exception) {
            return ($Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped)
        }
        throw
    }
}

function Stop-ServiceHard($Service) {
    try {
        $Service.Refresh()
        if ($Service.Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped) { return $true }
    } catch {
        if (Test-ServiceMissingError $_.Exception) { return $true }
        throw
    }
    try {
        # Stop-Service сам может ждать бесконечно; ServiceController.Stop только
        # отправляет запрос, а ожидание ниже ограничено нашим таймаутом.
        $Service.Stop()
    } catch {
        Write-Warning "SCM не остановил $($Service.Name): $($_.Exception.Message)"
    }
    if (Wait-ServiceStatus $Service ([ServiceProcess.ServiceControllerStatus]::Stopped) 20) { return $true }
    # Служба может не объявлять SERVICE_ACCEPT_STOP — тогда гасим её процесс.
    $servicePid = 0
    try {
        $instance = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($Service.Name)'" -ErrorAction Stop
        if ($null -ne $instance) { $servicePid = [int]$instance.ProcessId }
    } catch {
        Write-Warning "не удалось узнать PID службы $($Service.Name): $($_.Exception.Message)"
    }
    if ($servicePid -gt 0) {
        Write-Host "Служба $($Service.Name) не приняла stop, снимаю процесс $servicePid"
        Stop-Process -Id $servicePid -Force -ErrorAction SilentlyContinue
    }
    return (Wait-ServiceStatus $Service ([ServiceProcess.ServiceControllerStatus]::Stopped) 20)
}

function Request-AmneziaDisconnect {
    # The same command as the GUI: the daemon removes exclusion routes from the
    # physical adapter and clears its connection state before deleting the tunnel.
    $pipe = New-Object IO.Pipes.NamedPipeClientStream('.', 'amneziavpn', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
    $reader = $null
    try {
        $pipe.Connect(1000)
        $request = [Text.Encoding]::UTF8.GetBytes('{"type":"deactivate"}' + "`n")
        $pipe.Write($request, 0, $request.Length)
        $pipe.Flush()
        $reader = New-Object IO.StreamReader($pipe)
        $reply = $reader.ReadLineAsync()
        if (-not $reply.Wait(5000)) { return $false }
        $message = $reply.GetAwaiter().GetResult() | ConvertFrom-Json
        return ($message.type -eq 'disconnected')
    } catch { return $false }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        $pipe.Dispose()
    }
}

function Stop-AmneziaTunnel {
    # Stopping only the tunnel service leaves the daemon's state and routes on
    # Ethernet alive. Ask the daemon to clean up first; SCM is a fallback.
    [void](Request-AmneziaDisconnect)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline -and (Test-TunnelRunning)) { Start-Sleep -Milliseconds 250 }
    if (-not (Test-TunnelRunning)) { return }

    $tunnel = Get-TunnelService
    if ($null -ne $tunnel) {
        if (-not (Stop-ServiceHard $tunnel)) {
            throw "Служба $($tunnel.Name) не остановилась"
        }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline -and (Test-TunnelRunning)) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-TunnelRunning)) { return }

    $daemon = Get-AmneziaService
    if ($null -eq $daemon) { throw 'VPN-адаптер остался поднят, а служба демона не найдена' }
    if (-not (Stop-ServiceHard $daemon)) {
        throw "Служба $($daemon.Name) не остановилась"
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline -and (Test-TunnelRunning)) { Start-Sleep -Milliseconds 500 }
    if (Test-TunnelRunning) { throw 'Туннель Amnezia остался активен после остановки службы; список не применён.' }
}

function Start-AmneziaDaemon {
    $daemon = Get-AmneziaService
    if ($null -eq $daemon) { return }
    $daemon.Refresh()
    if ($daemon.Status -eq [ServiceProcess.ServiceControllerStatus]::Running) { return }
    Start-Service -InputObject $daemon -ErrorAction Stop
    if (-not (Wait-ServiceStatus $daemon ([ServiceProcess.ServiceControllerStatus]::Running) 30)) {
        throw "Служба $($daemon.Name) не запустилась за 30 секунд"
    }
}

# Scheduled Task работает с повышенными правами, и запущенная из неё AmneziaVPN.exe
# наследует admin-токен. Такой экземпляр перестаёт открываться из трея и из меню
# «Пуск»: Windows не пропускает оконные сообщения от обычного процесса к
# привилегированному (UIPI), поэтому вместо окна стартует второй экземпляр и висит
# на бесконечном «подключении». Поднимаем GUI разовой задачей от текущего
# пользователя с RunLevel Limited; cmd /c start отвязывает процесс от задачи, чтобы
# Task Scheduler не убил его вместе с ней.
function Start-AmneziaGui([string]$ExePath, [string[]]$Arguments) {
    if (-not (Test-Elevated)) {
        if ($Arguments.Count -gt 0) {
            Start-Process -FilePath $ExePath -ArgumentList $Arguments -WindowStyle Minimized | Out-Null
        } else {
            Start-Process -FilePath $ExePath -WindowStyle Minimized | Out-Null
        }
        return
    }

    $cmdExe = "$env:SystemRoot\System32\cmd.exe"
    if (-not (Test-Path -LiteralPath $cmdExe -PathType Leaf)) { throw "Не найден $cmdExe" }
    foreach ($argument in $Arguments) {
        if ($argument -match '["\r\n]') { throw 'Недопустимый аргумент запуска AmneziaVPN.' }
    }
    $argumentText = "/c start `"`" /min `"$ExePath`""
    if ($Arguments.Count -gt 0) { $argumentText = "$argumentText $($Arguments -join ' ')" }

    $taskName = "Amnezia-Route-Sync-Launch-$PID"
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $action = New-ScheduledTaskAction -Execute $cmdExe -Argument $argumentText
    $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal `
            -Settings $settings -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        while ([DateTime]::UtcNow -lt $deadline -and -not (Test-GuiRunning)) { Start-Sleep -Milliseconds 250 }
    } finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Restore-AmneziaSession($Session, [string]$ExePath) {
    if ($Session.Connected) { Start-AmneziaDaemon }
    if (-not $Session.GuiRunning -and -not $Session.Connected) { return }
    if (-not $ExePath) {
        throw 'Не найден AmneziaVPN.exe: journal сохранён для повторного восстановления.'
    }
    $arguments = @()
    if ($Session.Connected -and -not $Session.AutoConnect) {
        if ($Session.ServerIndex -lt 0) { throw 'Неизвестен индекс сервера для восстановления VPN.' }
        $arguments = @('--connect', [string]$Session.ServerIndex)
    } elseif ($Session.Connected) {
        $arguments = @('--autostart')
    }
    if (-not (Test-GuiRunning)) {
        Start-AmneziaGui $ExePath $arguments
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline -and -not (Test-GuiRunning)) { Start-Sleep -Milliseconds 250 }
    if (-not (Test-GuiRunning)) { throw 'настройки записаны, но процесс AmneziaVPN не появился' }
    if (-not $Session.Connected) { return }
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while ([DateTime]::UtcNow -lt $deadline -and -not (Test-TunnelReady)) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-TunnelReady)) {
        throw 'Туннель не поднялся за 60 секунд; journal сохранён. Подключите AmneziaVPN и повторите обновление.'
    }
}

# --- транзакция ----------------------------------------------------------------

function Remove-OldRoutingBackups([int]$Keep = 10) {
    if (-not (Test-Path -LiteralPath $BackupDir -PathType Container)) { return }
    @(Get-ChildItem -LiteralPath $BackupDir -Filter 'routing-*.json' -File |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -Skip $Keep) | Remove-Item -Force -ErrorAction SilentlyContinue
}

function Restore-PendingTransaction([string]$ExePath) {
    $journal = Read-JsonFile $JournalPath
    if ($null -eq $journal) { return }
    if ($journal.version -ne 1) { throw "повреждён transaction journal $JournalPath" }
    $session = ConvertFrom-SessionDocument $journal.session
    $phase = [string]$journal.phase

    if ($phase -eq 'stopping' -or $phase -eq 'restoring') {
        Restore-AmneziaSession $session $ExePath
        Remove-Item -LiteralPath $JournalPath -Force
        Write-Host 'Восстановлена AmneziaVPN после прерванной подготовки.'
        return
    }
    if ($phase -ne 'writing') { throw "transaction journal содержит неизвестную фазу '$phase'" }
    $backupPath = [string]$journal.backup
    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
        throw "Registry journal указывает на отсутствующий backup: $backupPath"
    }
    if ($session.Connected -and -not (Test-Elevated)) {
        throw 'Для восстановления подключённой Amnezia нужны права администратора; journal сохранён.'
    }
    # A writing journal may predate this guard. Preserve it if rollback would
    # require disconnecting a currently running protected session. Phases that
    # only restore connectivity above must remain recoverable without an opt-in.
    Assert-SafeAmneziaRestart (Get-AmneziaSession)
    Stop-AmneziaGui
    if ($session.Connected) {
        Stop-AmneziaTunnel
    }
    Restore-RoutingRegistrySnapshot (Read-JsonFile $backupPath)
    Write-JsonAtomic $ManagedPath @($journal.previous_managed | ForEach-Object { [string]$_ })
    Write-JsonAtomic $JournalPath ([ordered]@{ version = 1; phase = 'restoring'; session = (ConvertTo-SessionDocument $session) })
    Restore-AmneziaSession $session $ExePath
    Remove-Item -LiteralPath $JournalPath -Force
    Write-Host 'Откачена незавершённая routing-транзакция.'
}

function Invoke-RoutingTransaction([string[]]$Entries, [string]$ExePath, $DomainAddresses = @{}) {
    $current = Read-ExceptSites
    $previousManaged = @(Read-ManagedEntries)
    $desired = Get-DesiredSites $current $previousManaged $Entries $DomainAddresses
    $scalars = Read-RoutingScalars
    $manualCount = $desired.Count - @($Entries).Count

    $needsChange = -not (Test-SitesEqual $current $desired) -or
                   ([string]$scalars.mode -cne [string]$RouteModeVpnAllExceptSites) -or
                   ([string]$scalars.enabled -cne 'true')
    if (-not $needsChange) {
        Write-JsonAtomic $ManagedPath @($Entries)
        return [pscustomobject]@{ Changed = $false; ManualCount = $manualCount }
    }

    $session = Get-AmneziaSession
    Assert-SafeAmneziaRestart $session
    $currentSessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    if (@(Get-Process -Name $GuiProcessName -ErrorAction SilentlyContinue |
            Where-Object { $_.SessionId -ne $currentSessionId }).Count -gt 0) {
        throw 'AmneziaVPN запущена в другой сессии Windows. Обновление отложено, чтобы не прервать чужое подключение.'
    }
    if ($session.Connected -and -not $session.AutoConnect -and $session.ServerIndex -lt 0) {
        throw 'Amnezia хранит выбранный сервер по ID: включите автоподключение или задайте -ServerIndex (с нуля), чтобы восстановить тот же VPN. Настройки не изменены.'
    }
    if ($session.GuiRunning -and -not $session.Connected -and $session.AutoConnect) {
        throw 'VPN отключён при включённом автоподключении. Закройте AmneziaVPN или подключитесь перед обновлением, чтобы перезапуск не изменил состояние подключения.'
    }
    if ($NoRestart) {
        if ($session.GuiRunning -or $session.Connected) {
            throw 'Указан -NoRestart, но AmneziaVPN запущена: закройте её и отключите VPN, иначе запись затрётся.'
        }
    } elseif ($session.Connected -and -not (Test-Elevated)) {
        throw ('AmneziaVPN подключена: чтобы применить новый список без перезагрузки Windows, ' +
               'нужно перезапустить службу AmneziaVPN-service. Запустите PowerShell от имени администратора.')
    }

    [IO.Directory]::CreateDirectory($BackupDir) | Out-Null
    Write-JsonAtomic $JournalPath ([ordered]@{
        version = 1
        phase   = 'stopping'
        session = (ConvertTo-SessionDocument $session)
    })

    $stopAttempted = $false
    $resolved = $false
    try {
        if (-not $NoRestart) {
            $stopAttempted = $true
            Stop-AmneziaGui
            if ($session.Connected) { Stop-AmneziaTunnel }
        }

        # После выхода GUI кэш QSettings уже на диске — перечитываем факт.
        $current = Read-ExceptSites
        $desired = Get-DesiredSites $current $previousManaged $Entries $DomainAddresses
        $manualCount = $desired.Count - @($Entries).Count

        $backupPath = Join-Path $BackupDir ("routing-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
        Write-JsonAtomic $backupPath (Read-RoutingRegistrySnapshot)
        Write-JsonAtomic $JournalPath ([ordered]@{
            version          = 1
            phase            = 'writing'
            session          = (ConvertTo-SessionDocument $session)
            backup           = $backupPath
            previous_managed = @($previousManaged)
            desired_managed  = @($Entries)
        })

        try {
            Write-RoutingRegistry $desired
            Assert-RoutingRegistry $desired
            Write-JsonAtomic $ManagedPath @($Entries)
            $resolved = $true
        } catch {
            try {
                Restore-RoutingRegistrySnapshot (Read-JsonFile $backupPath)
                Write-JsonAtomic $ManagedPath @($previousManaged)
                $resolved = $true
            } catch {
                throw "АВАРИЯ: routing rollback не удался; journal сохранён: $($_.Exception.Message)"
            }
            throw
        }
    } finally {
        if ($resolved) {
            Write-JsonAtomic $JournalPath ([ordered]@{ version = 1; phase = 'restoring'; session = (ConvertTo-SessionDocument $session) })
        }
        if ($stopAttempted) {
            Restore-AmneziaSession $session $ExePath
        }
        if ($resolved) {
            Remove-Item -LiteralPath $JournalPath -Force -ErrorAction SilentlyContinue
            Remove-OldRoutingBackups
        }
    }

    return [pscustomobject]@{ Changed = $true; ManualCount = $manualCount }
}

# --- self-test -----------------------------------------------------------------

if ($SelfTest) {
    Assert-QtCodec
    $network = ConvertTo-Cidr '203.0.113.0/24'
    $hostRoute = ConvertTo-Cidr '203.0.113.100/32'
    if ($hostRoute.Prefix -ne 32 -or $network.Count -ne 256) { throw 'CIDR self-test failed.' }
    $strictRejected = $false
    try { $null = ConvertTo-Cidr '203.0.113.100/24' } catch { $strictRejected = $true }
    if (-not $strictRejected) { throw 'Non-network CIDR self-test failed.' }
    $collapsed = @(Compress-Cidrs @((ConvertTo-Cidr '10.0.0.0/25'), (ConvertTo-Cidr '10.0.0.128/25'), (ConvertTo-Cidr '10.0.0.1/32')))
    if ($collapsed.Count -ne 1 -or $collapsed[0].Text -cne '10.0.0.0/24') { throw 'CIDR collapse self-test failed.' }
    $chain = @(Compress-Cidrs @((ConvertTo-Cidr '5.255.192.0/18'), (ConvertTo-Cidr '5.255.128.0/18'), (ConvertTo-Cidr '5.255.0.0/17')))
    if ($chain.Count -ne 1 -or $chain[0].Text -cne '5.255.0.0/16') { throw 'CIDR merge-chain self-test failed.' }
    $unaligned = @(Compress-Cidrs @((ConvertTo-Cidr '10.0.1.0/24'), (ConvertTo-Cidr '10.0.2.0/24')))
    if ($unaligned.Count -ne 2) { throw 'CIDR unaligned-merge self-test failed.' }
    if (Test-CidrGlobal (ConvertTo-Cidr '10.0.0.0/12')) { throw 'Reserved-range self-test failed.' }
    if (-not (Test-CidrGlobal (ConvertTo-Cidr '5.255.0.0/16'))) { throw 'Global-range self-test failed.' }
    if (-not (Test-CidrPrivate (ConvertTo-Cidr '192.168.1.0/24'))) { throw 'Private-subnet self-test failed.' }
    if (-not (Test-CidrPrivate (ConvertTo-Cidr '10.8.1.0/24'))) { throw 'Private-subnet self-test failed (10/8).' }
    if (Test-CidrPrivate (ConvertTo-Cidr '5.255.0.0/16')) { throw 'Private-subnet self-test failed (global).' }

    # Политика не зависит от того, успел ли Hyper-V создать интерфейс.
    function Get-NetAdapter { throw 'LAN policy must not enumerate adapters' }
    function Get-NetIPAddress { throw 'LAN policy must not snapshot dynamic subnets' }
    $localTest = @(Get-LocalSubnetEntries)
    if (($localTest -join ',') -cne '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16') {
        throw "Local-subnet self-test failed: $($localTest -join ',')"
    }
    $NoLocalSubnets = $true
    if (@(Get-LocalSubnetEntries).Count -ne 0) { throw 'Local-subnet opt-out failed.' }
    $NoLocalSubnets = $false
    if (-not (Test-Hostname 'gosuslugi.ru') -or (Test-Hostname 'GosUslugi.ru') -or (Test-Hostname 'no-dot')) {
        throw 'Hostname self-test failed.'
    }
    $fixture = @(
        @(1..300 | ForEach-Object { [pscustomobject]@{ hostname = "host$_.example.ru"; ip = '' } }),
        @(0..39 | ForEach-Object { [pscustomobject]@{ hostname = "5.255.$($_ * 2).0/24"; ip = '' } })
    ) | ForEach-Object { $_ }
    $parsed = ConvertFrom-ImportList (($fixture | ConvertTo-Json -Depth 5)) 'self-test'
    if ($parsed.Domains.Count -ne 300 -or $parsed.Cidrs.Count -ne 40) { throw 'Import-list self-test failed.' }
    $rejected = $false
    try { $null = ConvertFrom-ImportList '[{"hostname":"10.0.0.0/8","ip":""}]' 'self-test' } catch { $rejected = $true }
    if (-not $rejected) { throw 'Private-network rejection self-test failed.' }
    $bulk = @{}
    foreach ($entry in (@($parsed.Domains) + @($parsed.Cidrs))) { $bulk[$entry] = @() }
    $bulkEncoded = [AmneziaRouteSync.QtVariantMapCodec]::Encode((ConvertTo-QtMap $bulk))
    $bulkDecoded = [AmneziaRouteSync.QtVariantMapCodec]::Decode($bulkEncoded)
    if ($bulkDecoded.Count -ne $bulk.Count) { throw 'Bulk QVariantMap round-trip self-test failed.' }
    Write-Host 'Windows updater self-test: OK'
    if ($Source) {
        $list = ConvertFrom-ImportList (Get-SourceText $Source) $Source
        Write-Host "Список $Source принят: $($list.Domains.Count) доменов и $($list.Cidrs.Count) сетей IPv4"
    }
    exit 0
}

# --- диагностика ----------------------------------------------------------------

if ($Status) {
    Write-IPv6TunnelWarning
    $sites = Read-ExceptSites
    $scalars = Read-RoutingScalars
    $managed = @(Read-ManagedEntries)
    Write-Host "Записей в Conf\ExceptSites: $($sites.Count)"
    Write-Host "routeMode: $($scalars.mode) (нужно 2)"
    Write-Host "sitesSplitTunnelingEnabled: $($scalars.enabled) (нужно true)"
    Write-Host "appsSplitTunnelingEnabled: $($scalars.apps_enabled)"
    if ($scalars.apps_enabled -ceq 'true') {
        Write-Host 'Исключения приложений включены: для этих приложений действуют отдельные правила обхода VPN.'
    }
    Write-Host "Записей под управлением скрипта: $($managed.Count)"

    try {
        foreach ($probe in @('gosuslugi.ru', 'esia.gosuslugi.ru', 'sberbank.ru', '213.59.252.0/22')) {
            # Присваивание из if разворачивает пустой массив в $null, поэтому @() отдельно.
            $values = @()
            if ($sites.ContainsKey($probe)) { $values = @($sites[$probe] | Where-Object { $_ }) }
            $present = if ($sites.ContainsKey($probe)) { 'есть' } else { 'отдельного ключа нет; адрес может покрываться CIDR' }
            $resolved = if ($values.Count -gt 0) { " (значения: $($values -join ', '))" } else { ' (значения пусты)' }
            Write-Host "  $probe в списке: $present$resolved"
        }
        $networkKeys = @($sites.Keys | Where-Object { $_ -like '*/*' })
        $domainKeys = @($sites.Keys | Where-Object { $_ -notlike '*/*' })
        Write-Host "Ключей-сетей: $($networkKeys.Count), ключей-доменов: $($domainKeys.Count)"
        Write-Host 'В компактном списке имена доменов заменены объединением их IPv4 и готовых сетей.'
        $missingPrivate = @($PrivateSubnetRanges | Where-Object { -not $sites.ContainsKey($_) })
        if (-not $NoLocalSubnets -and $missingPrivate.Count -gt 0) {
            Write-Warning 'Нет полного набора стабильных LAN-исключений: обновите updater. Снимок подсетей Hyper-V может устареть после перезагрузки.'
        }
        $resolvedDomains = @($domainKeys | Where-Object { @(Get-PublicIPv4Values $sites[$_]).Count -gt 0 }).Count
        Write-Host "Доменов с сохранёнными публичными IPv4: $resolvedDomains из $($domainKeys.Count)"
        if ($resolvedDomains -lt $domainKeys.Count) {
            Write-Warning 'Домены без IP не создают маршруты в AmneziaWG; их могут покрывать готовые сети CIDR.'
        }
        Write-Host "Примеры сетей: $((@($networkKeys | Sort-Object | Select-Object -First 5)) -join ', ')"
        Write-Host "Примеры доменов: $((@($domainKeys | Sort-Object | Select-Object -First 5)) -join ', ')"
    } catch {
        Write-Warning "не удалось проверить записи: $($_.Exception.Message)"
    }

    try {
        $daemon = Get-AmneziaService
        $tunnel = Get-TunnelService
        $daemonStatus = if ($null -eq $daemon) { 'не найдена' } else { "$($daemon.Name) = $($daemon.Status)" }
        $tunnelStatus = if ($null -eq $tunnel) { 'не найдена' } else { "$($tunnel.Name) = $($tunnel.Status)" }
        Write-Host "Служба демона: $daemonStatus"
        Write-Host "Служба туннеля: $tunnelStatus"
        Write-Host "GUI запущена: $(Test-GuiRunning); VPN-адаптер поднят: $(Test-VpnAdapterUp)"
        if (-not (Test-TunnelRunning)) { Write-Warning 'VPN не подключён: прямой маршрут сам по себе не подтверждает работу split tunneling.' }
        foreach ($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($adapter.OperationalStatus -eq [Net.NetworkInformation.OperationalStatus]::Up) {
                Write-Host "  адаптер up: $($adapter.Name) / $($adapter.Description)"
            }
        }
    } catch {
        Write-Warning "не удалось опросить службы и адаптеры: $($_.Exception.Message)"
    }

    try {
        $address = ([Net.Dns]::GetHostAddresses('gosuslugi.ru') |
            Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork } |
            Select-Object -First 1).IPAddressToString
        Write-Host "gosuslugi.ru резолвится в $address"
        if (Get-Command Find-NetRoute -ErrorAction SilentlyContinue) {
            # Find-NetRoute отдаёт пару объектов: NetIPAddress и NetRoute. NextHop
            # есть только у второго, поэтому фильтруем по свойству, а не по позиции.
            $route = @(Find-NetRoute -RemoteIPAddress $address -ErrorAction Stop |
                Where-Object { $_.PSObject.Properties.Name -contains 'NextHop' }) |
                Select-Object -First 1
            if ($null -ne $route) {
                $alias = (Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue).Name
                Write-Host "маршрут до gosuslugi.ru: префикс $($route.DestinationPrefix), шлюз $($route.NextHop), интерфейс $alias (index $($route.InterfaceIndex))"
            }
        }
    } catch {
        Write-Warning "не удалось проверить маршрут: $($_.Exception.Message)"
    }

    try {
        if (Test-Path -LiteralPath $JournalPath -PathType Leaf) {
            Write-Warning "Есть незавершённая транзакция: $JournalPath"
            Get-Content -LiteralPath $JournalPath -Raw -Encoding UTF8 | Write-Host
        }
        $taskName = "Amnezia-Split-Route-Sync-$([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        if ($null -ne $taskInfo) {
            Write-Host "Задача: последний запуск $($taskInfo.LastRunTime), код $($taskInfo.LastTaskResult)"
        } else {
            Write-Host "Задача $taskName не зарегистрирована"
        }
    } catch {
        Write-Warning "не удалось прочитать журнал и задачу: $($_.Exception.Message)"
    }

    if (Test-Path -LiteralPath $StatusPath -PathType Leaf) {
        Write-Host '--- status.json ---'
        Get-Content -LiteralPath $StatusPath -Raw -Encoding UTF8 | Write-Host
    } else {
        Write-Host "status.json отсутствует: $StatusPath"
    }
    exit 0
}

# --- основной сценарий ---------------------------------------------------------

$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($currentSid -eq 'S-1-5-18') { throw 'Updater нельзя запускать от SYSTEM: настройки лежат в HKCU пользователя.' }

if (-not $Source) {
    $Source = if ($Lite) { $ListLite } else { $ListFull }
}

$mutex = New-Object Threading.Mutex($false, "Global\Amnezia-Split-Route-Sync-$currentSid")
$hasLock = $false
try {
    try { $hasLock = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $hasLock = $true }
    if (-not $hasLock) {
        if ($DryRun -or $RecoverOnly) { throw 'Другой updater уже работает; проверка/восстановление не выполнены. Дождитесь его завершения.' }
        Write-Host 'Другой updater уже работает, пропускаю запуск.'
        exit 0
    }

    Assert-QtCodec
    Write-IPv6TunnelWarning
    if (-not $DryRun) { [IO.Directory]::CreateDirectory($StateDir) | Out-Null }

    $exePath = $null
    $appVersion = 'не установлена'
    if ($DryRun -or $RecoverOnly) {
        try {
            $exePath = Get-AmneziaExePath
            $appVersion = Assert-AmneziaVersion $exePath
        } catch {
            Write-Warning $_.Exception.Message
        }
    } else {
        $exePath = Get-AmneziaExePath
        $appVersion = Assert-AmneziaVersion $exePath
    }

    if (-not $DryRun) {
        # Recovery не зависит от сети: сначала обязательно вернуть VPN и настройки.
        Restore-PendingTransaction $exePath
    }
    if ($RecoverOnly) {
        Write-Host 'Recovery завершён; незавершённых routing-транзакций нет.'
        exit 0
    }

    $text = Get-SourceText $Source
    $list = ConvertFrom-ImportList $text $Source
    $localSubnets = @(Get-LocalSubnetEntries)
    Write-Host "Проверено $($list.Domains.Count) доменов и $($list.Cidrs.Count) сетей IPv4 для AmneziaVPN $appVersion"
    if ($localSubnets.Count -gt 0) {
        Write-Host "Локальные подсети мимо VPN: $($localSubnets -join ', ')"
    } elseif (-not $NoLocalSubnets) {
        Write-Host 'Локальных подсетей не найдено — LAN останется в туннеле.'
    }

    $dns = Resolve-ManagedDomains $list.Domains
    Write-Host "DNS: $($dns.Addresses.Count) из $($list.Domains.Count) доменов с публичными IPv4; кэш: $($dns.Cached)"
    $plan = Get-ManagedRoutePlan $list $dns (Read-ExceptSites) @(Read-ManagedEntries)
    $entries = @($plan.Entries) + $localSubnets
    Write-Host "Маршруты после DNS: $($plan.InputRouteCount) -> $($plan.Entries.Count); убрано повторов и перекрытий: $($plan.RemovedRouteCount)"
    if ($plan.UnresolvedDomainCount -gt 0) {
        Write-Warning "$($plan.UnresolvedDomainCount) доменов без известных IPv4 пропущены; их готовые BGP-сети сохранены."
    }
    if ($DryRun) { exit 0 }

    # Сохраняем привязку имён ДО записи CIDR: даже сбой при восстановлении VPN
    # не должен лишить следующую попытку fallback при недоступном DNS.
    Write-JsonAtomic $DnsCachePath ([ordered]@{
        version = 1; updated_at = $dns.Cache.updated_at; domains = @($list.Domains)
        addresses = $dns.Addresses; last_known_addresses = $plan.DomainAddresses
    })
    $result = Invoke-RoutingTransaction $entries $exePath

    Write-TextAtomic $ImportPath $text
    Write-JsonAtomic $StatusPath ([ordered]@{
        changed                  = [bool]$result.Changed
        source                   = $Source
        domain_count             = $list.Domains.Count
        cidr_count               = $list.Cidrs.Count
        effective_route_count    = $plan.Entries.Count
        active_routes_verified   = $false
        routes_before_compaction = $plan.InputRouteCount
        redundant_routes_removed = $plan.RemovedRouteCount
        unresolved_domain_count  = $plan.UnresolvedDomainCount
        local_subnets            = @($localSubnets)
        entry_count              = $entries.Count
        manual_entries_preserved = [int]$result.ManualCount
        app_version              = $appVersion
        dns_resolved_count       = $dns.Addresses.Count
        updated_at               = [DateTime]::UtcNow.ToString('o')
    })

    if ($result.Changed) {
        Write-Host ("AmneziaVPN обновлена: $($entries.Count) записей, сохранено ручных записей: $($result.ManualCount). " +
                    'Запись настроек проверена; это не подтверждает загрузку нового списка клиентом. Сравните свежий журнал с планом.')
    } else {
        Write-Host "В реестре уже записан план из $($entries.Count) записей; активные маршруты отдельно не проверялись."
    }
} finally {
    if ($hasLock) { [void]$mutex.ReleaseMutex() }
    $mutex.Dispose()
}
