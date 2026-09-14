// Persistent, per-executable outbound policy. No changes to other providers.
// Build with the Windows SDK and MSVC; see install-app-vpn-guard.ps1.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>

namespace fs = std::filesystem;
static const GUID Provider = {0xc853785a,0xe129,0x44e1,{0xa1,0x3b,0x52,0x78,0xf5,0x53,0x6d,0x96}};
static const GUID Sublayer = {0xb61fbdb7,0xbb47,0x4684,{0x81,0xe2,0x3c,0x19,0x86,0xa1,0x65,0x42}};

void check(DWORD code, const char* operation) {
    if (code != ERROR_SUCCESS) throw std::runtime_error(std::string(operation) + ": " + std::to_string(code));
}
struct Engine {
    HANDLE handle = nullptr;
    explicit Engine(bool dynamic = false) {
        FWPM_SESSION0 session{};
        session.flags = dynamic ? FWPM_SESSION_FLAG_DYNAMIC : 0;
        check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &handle), "Open WFP");
    }
    ~Engine() { if (handle) FwpmEngineClose0(handle); }
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
};
struct Transaction {
    HANDLE engine;
    bool committed = false;
    explicit Transaction(HANDLE value) : engine(value) { check(FwpmTransactionBegin0(engine, 0), "Begin policy transaction"); }
    void commit() { check(FwpmTransactionCommit0(engine), "Commit policy transaction"); committed = true; }
    ~Transaction() { if (!committed) FwpmTransactionAbort0(engine); }
};
struct Config { std::wstring adapter; std::set<std::wstring> programs; };
std::wstring wide(const std::string& value) {
    if (value.empty()) return {};
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (!count) throw std::runtime_error("Invalid UTF-8 configuration");
    std::wstring result(count, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), count);
    return result;
}
std::wstring lower(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
    return text;
}
std::wstring identityPath(const std::wstring& path) {
    if (lower(path).find(L"\\device\\") == 0) return lower(path);
    FWP_BYTE_BLOB* app = nullptr;
    check(FwpmGetAppIdFromFileName0(path.c_str(), &app), "Resolve protected executable identity");
    std::wstring result(reinterpret_cast<const wchar_t*>(app->data), app->size / sizeof(wchar_t));
    FwpmFreeMemory0(reinterpret_cast<void**>(&app));
    while (!result.empty() && result.back() == L'\0') result.pop_back();
    return lower(result);
}
std::wstring nativePrefix(const std::wstring& path) {
    if (lower(path).find(L"\\device\\") == 0) return lower(path);
    if (path.size() < 4 || path[1] != L':' || path[2] != L'\\') throw std::runtime_error("Protected prefixes must use an absolute local drive path");
    wchar_t device[32768];
    auto drive = path.substr(0, 2);
    if (!QueryDosDeviceW(drive.c_str(), device, 32768)) check(GetLastError(), "Resolve protected volume");
    if (path.find(L"..") != std::wstring::npos || path.find(L'*') != std::wstring::npos)
        throw std::runtime_error("Invalid protected path prefix");
    return lower(std::wstring(device) + path.substr(2));
}
Config readConfig(const fs::path& path) {
    std::ifstream input(path);
    if (!input) throw std::runtime_error("Cannot read guard configuration");
    Config config;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line.size() < 3 || line[1] != '|') throw std::runtime_error("Invalid guard configuration record");
        auto value = wide(line.substr(2));
        if (line[0] == 'A') config.adapter = value;
        else if (line[0] == 'P' || line[0] == 'N') config.programs.insert(identityPath(value));
        else if (line[0] == 'D') config.programs.insert(L"prefix:" + nativePrefix(value));
        else throw std::runtime_error("Unknown guard configuration record");
    }
    if (config.adapter.empty() || config.programs.empty()) throw std::runtime_error("Incomplete guard configuration");
    return config;
}
std::set<std::wstring> programs(const Config& config) {
    auto result = config.programs;
    if (result.empty()) throw std::runtime_error("No protected executable was found");
    if (result.size() > 512) throw std::runtime_error("Protected program scope is unexpectedly large");
    return result;
}
UINT64 vpnLuid(const std::wstring& alias) {
    ULONG length = 16384;
    std::vector<unsigned char> buffer(length);
    ULONG result;
    for (int attempt = 0; ; ++attempt) {
        result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                     nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &length);
        if (result != ERROR_BUFFER_OVERFLOW || attempt == 2) break;
        buffer.resize(length);
    }
    if (result == ERROR_NO_DATA) return 0;
    check(result, "Read network interfaces");
    UINT64 found = 0;
    for (auto adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); adapter; adapter = adapter->Next) {
        if (adapter->FriendlyName && alias == adapter->FriendlyName && adapter->OperStatus == IfOperStatusUp) {
            // Physical adapters cannot become an allowed VPN by being renamed.
            if (adapter->IfType != IF_TYPE_PROP_VIRTUAL || !adapter->Description ||
                std::wstring(adapter->Description).find(L"WireGuard") == std::wstring::npos)
                throw std::runtime_error("The selected interface is not an Amnezia WireGuard tunnel");
            if (found) throw std::runtime_error("Multiple VPN interfaces have the same alias");
            found = adapter->Luid.Value;
        }
    }
    return found;
}
void ensureProvider(HANDLE engine) {
    FWPM_PROVIDER0 provider{};
    provider.providerKey = Provider;
    provider.displayData.name = const_cast<wchar_t*>(L"Amnezia App VPN Guard");
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    DWORD result = FwpmProviderAdd0(engine, &provider, nullptr);
    if (result != FWP_E_ALREADY_EXISTS) check(result, "Create guard provider");
    FWPM_SUBLAYER0 layer{};
    layer.subLayerKey = Sublayer;
    layer.providerKey = const_cast<GUID*>(&Provider);
    layer.displayData.name = const_cast<wchar_t*>(L"Amnezia App VPN Guard");
    layer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    layer.weight = 0xffff;
    result = FwpmSubLayerAdd0(engine, &layer, nullptr);
    if (result != FWP_E_ALREADY_EXISTS) check(result, "Create guard sublayer");
}
std::vector<UINT64> ownFilters(HANDLE engine) {
    std::vector<UINT64> result;
    for (const auto& layer : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6}) {
        FWPM_FILTER_ENUM_TEMPLATE0 query{};
        query.providerKey = const_cast<GUID*>(&Provider);
        query.layerKey = layer; // GUID_NULL is not an "all layers" wildcard.
        query.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
        query.actionMask = 0xffffffff;
        HANDLE cursor = nullptr;
        check(FwpmFilterCreateEnumHandle0(engine, &query, &cursor), "List guard filters");
        try {
            for (;;) {
                FWPM_FILTER0** entries = nullptr;
                UINT32 count = 0;
                check(FwpmFilterEnum0(engine, cursor, 128, &entries, &count), "Read guard filters");
                for (UINT32 i = 0; i < count; ++i) result.push_back(entries[i]->filterId);
                if (entries) FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
                if (count < 128) break;
            }
        } catch (...) { FwpmFilterDestroyEnumHandle0(engine, cursor); throw; }
        FwpmFilterDestroyEnumHandle0(engine, cursor);
    }
    return result;
}
UINT64 addBlock(HANDLE engine, const std::wstring& path, const GUID& layer, UINT64 allowedLuid,
                const GUID& sublayer, bool persistent) {
    bool prefix = path.find(L"prefix:") == 0;
    auto identity = prefix ? path.substr(7) : identityPath(path);
    FWP_BYTE_BLOB app{};
    app.size = static_cast<UINT32>((identity.size() + 1) * sizeof(wchar_t));
    app.data = reinterpret_cast<UINT8*>(identity.data());
    // FWP_MATCH_PREFIX actually matches a suffix. A sortable string range is
    // used for a true path prefix; both boundaries include the terminal NUL.
    auto upperIdentity = identity + L'\xffff';
    FWP_BYTE_BLOB upperApp{};
    upperApp.size = static_cast<UINT32>((upperIdentity.size() + 1) * sizeof(wchar_t));
    upperApp.data = reinterpret_cast<UINT8*>(upperIdentity.data());
    FWP_RANGE0 range{};
    range.valueLow.type = FWP_BYTE_BLOB_TYPE; range.valueLow.byteBlob = &app;
    range.valueHigh.type = FWP_BYTE_BLOB_TYPE; range.valueHigh.byteBlob = &upperApp;
    try {
        FWPM_FILTER_CONDITION0 conditions[3]{};
        conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        conditions[0].matchType = prefix ? FWP_MATCH_RANGE : FWP_MATCH_EQUAL;
        conditions[0].conditionValue.type = prefix ? FWP_RANGE_TYPE : FWP_BYTE_BLOB_TYPE;
        if (prefix) conditions[0].conditionValue.rangeValue = &range;
        else conditions[0].conditionValue.byteBlob = &app;
        // Preserve loopback IPC, not direct connections to LAN or the Internet.
        conditions[1].fieldKey = FWPM_CONDITION_FLAGS;
        conditions[1].matchType = FWP_MATCH_FLAGS_NONE_SET;
        conditions[1].conditionValue.type = FWP_UINT32;
        conditions[1].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
        conditions[2].fieldKey = FWPM_CONDITION_IP_NEXTHOP_INTERFACE;
        conditions[2].matchType = FWP_MATCH_NOT_EQUAL;
        conditions[2].conditionValue.type = FWP_UINT64;
        conditions[2].conditionValue.uint64 = &allowedLuid;
        FWPM_FILTER0 filter{};
        check(UuidCreate(&filter.filterKey), "Create filter key");
        filter.displayData.name = const_cast<wchar_t*>(L"VPN only: block other outbound interfaces");
        filter.displayData.description = const_cast<wchar_t*>(path.c_str());
        filter.layerKey = layer;
        filter.subLayerKey = sublayer;
        filter.action.type = FWP_ACTION_BLOCK;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 15;
        filter.numFilterConditions = allowedLuid ? 3 : 2;
        filter.filterCondition = conditions;
        if (persistent) { filter.flags = FWPM_FILTER_FLAG_PERSISTENT; filter.providerKey = const_cast<GUID*>(&Provider); }
        UINT64 id = 0;
        check(FwpmFilterAdd0(engine, &filter, nullptr, &id), "Add outbound block filter");
        return id;
    } catch (...) { throw; }
}
void apply(HANDLE engine, const std::set<std::wstring>& paths, UINT64 luid) {
    if (paths.empty()) throw std::runtime_error("Refusing to replace protection with an empty program list");
    Transaction transaction(engine);
    ensureProvider(engine);
    auto previous = ownFilters(engine);
    for (const auto& path : paths) {
        addBlock(engine, path, FWPM_LAYER_ALE_AUTH_CONNECT_V4, luid, Sublayer, true);
        addBlock(engine, path, FWPM_LAYER_ALE_AUTH_CONNECT_V6, luid, Sublayer, true);
    }
    // A single WFP transaction keeps the old policy enforced until the whole
    // replacement succeeds. A failed refresh never opens a gap.
    for (auto id : previous) check(FwpmFilterDeleteById0(engine, id), "Replace old guard filter");
    transaction.commit();
    if (ownFilters(engine).size() != paths.size() * 2) throw std::runtime_error("Guard filter read-back count mismatch");
}
void removeGuard(HANDLE engine) {
    Transaction transaction(engine);
    for (auto id : ownFilters(engine)) check(FwpmFilterDeleteById0(engine, id), "Remove guard filter");
    DWORD result = FwpmSubLayerDeleteByKey0(engine, &Sublayer);
    if (result != FWP_E_SUBLAYER_NOT_FOUND) check(result, "Remove guard sublayer");
    result = FwpmProviderDeleteByKey0(engine, &Provider);
    if (result != FWP_E_PROVIDER_NOT_FOUND) check(result, "Remove guard provider");
    transaction.commit();
}
void status(HANDLE engine) {
    auto filters = ownFilters(engine);
    size_t persistent = 0, disabled = 0;
    for (auto id : filters) {
        FWPM_FILTER0* filter = nullptr;
        check(FwpmFilterGetById0(engine, id, &filter), "Inspect installed guard filter");
        if (filter->flags & FWPM_FILTER_FLAG_PERSISTENT) ++persistent;
        if (filter->flags & FWPM_FILTER_FLAG_DISABLED) ++disabled;
        FwpmFreeMemory0(reinterpret_cast<void**>(&filter));
    }
    std::cout << "App guard filters: " << filters.size() << "; persistent: " << persistent << "; disabled: " << disabled << "\n";
    if (disabled || persistent != filters.size()) throw std::runtime_error("Guard filter persistence/activation check failed");
}
int connectProbe(int family) {
    SOCKET sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return WSAGetLastError();
    u_long nonblocking = 1;
    ioctlsocket(sock, FIONBIO, &nonblocking);
    sockaddr_storage address{};
    int length;
    if (family == AF_INET) {
        auto remote = reinterpret_cast<sockaddr_in*>(&address);
        remote->sin_family = AF_INET; remote->sin_port = htons(443);
        InetPtonW(AF_INET, L"1.1.1.1", &remote->sin_addr); length = sizeof(*remote);
    } else {
        auto remote = reinterpret_cast<sockaddr_in6*>(&address);
        remote->sin6_family = AF_INET6; remote->sin6_port = htons(443);
        InetPtonW(AF_INET6, L"2606:4700:4700::1111", &remote->sin6_addr); length = sizeof(*remote);
    }
    int result = connect(sock, reinterpret_cast<sockaddr*>(&address), length);
    int error = result == 0 ? 0 : WSAGetLastError();
    if (error == WSAEWOULDBLOCK) {
        fd_set writes, errors;
        FD_ZERO(&writes); FD_ZERO(&errors); FD_SET(sock, &writes); FD_SET(sock, &errors);
        timeval timeout{5,0};
        result = select(0, nullptr, &writes, &errors, &timeout);
        int size = sizeof(error);
        if (result > 0) getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size);
        else error = result == 0 ? WSAETIMEDOUT : WSAGetLastError();
    }
    closesocket(sock);
    return error;
}
void probe(const std::wstring& adapter) {
    auto luid = vpnLuid(adapter);
    if (!luid) throw std::runtime_error("Probe requires a connected VPN interface");
    WSADATA data{};
    check(WSAStartup(MAKEWORD(2,2), &data), "Initialize socket probe");
    if (connectProbe(AF_INET) != 0) throw std::runtime_error("Baseline VPN TCP probe did not connect");
    Engine engine(true);
    GUID key{};
    check(UuidCreate(&key), "Create probe sublayer key");
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = key;
    sublayer.displayData.name = const_cast<wchar_t*>(L"Temporary VPN guard verification");
    sublayer.weight = 0xffff;
    check(FwpmSubLayerAdd0(engine.handle, &sublayer, nullptr), "Create temporary probe sublayer");
    wchar_t exe[32768];
    DWORD size = GetModuleFileNameW(nullptr, exe, 32768);
    if (!size || size == 32768) throw std::runtime_error("Cannot resolve probe executable");
    auto v4 = addBlock(engine.handle, exe, FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0, key, false);
    auto v6 = addBlock(engine.handle, exe, FWPM_LAYER_ALE_AUTH_CONNECT_V6, 0, key, false);
    int ipv4 = connectProbe(AF_INET), ipv6 = connectProbe(AF_INET6);
    if (ipv4 != WSAEACCES || ipv6 != WSAEACCES)
        throw std::runtime_error("No-VPN probe must be denied by Windows: IPv4=" + std::to_string(ipv4) + ", IPv6=" + std::to_string(ipv6));
    std::cout << "PASS: simulated absent VPN blocks IPv4 and IPv6 (WSAEACCES)\n";
    auto directory = fs::path(exe).parent_path().wstring();
    {
        Transaction transaction(engine.handle);
        check(FwpmFilterDeleteById0(engine.handle, v4), "Replace probe IPv4 filter");
        check(FwpmFilterDeleteById0(engine.handle, v6), "Replace probe IPv6 filter");
        v4 = addBlock(engine.handle, L"prefix:" + nativePrefix(directory + L"-unrelated\\"), FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0, key, false);
        v6 = addBlock(engine.handle, L"prefix:" + nativePrefix(directory + L"-unrelated\\"), FWPM_LAYER_ALE_AUTH_CONNECT_V6, 0, key, false);
        transaction.commit();
    }
    if (connectProbe(AF_INET) != 0) throw std::runtime_error("Directory prefix affected an unrelated sibling path");
    {
        Transaction transaction(engine.handle);
        check(FwpmFilterDeleteById0(engine.handle, v4), "Replace prefix probe IPv4 filter");
        check(FwpmFilterDeleteById0(engine.handle, v6), "Replace prefix probe IPv6 filter");
        v4 = addBlock(engine.handle, L"prefix:" + nativePrefix(directory + L"\\"), FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0, key, false);
        v6 = addBlock(engine.handle, L"prefix:" + nativePrefix(directory + L"\\"), FWPM_LAYER_ALE_AUTH_CONNECT_V6, 0, key, false);
        transaction.commit();
    }
    if (connectProbe(AF_INET) != WSAEACCES || connectProbe(AF_INET6) != WSAEACCES)
        throw std::runtime_error("Directory prefix did not block the executable in IPv4/IPv6");
    std::cout << "PASS: directory-prefix policy blocks contained executable, preserves unrelated sibling path\n";
    // Create a new, renamed executable AFTER the rule is installed. No scan or
    // policy refresh is allowed before its first connection attempt.
    auto futureDir = fs::path(directory) / (L"future-version-probe-" + std::to_wstring(GetCurrentProcessId()));
    auto futureExe = futureDir / L"renamed-client.exe";
    if (!CreateDirectoryW(futureDir.c_str(), nullptr)) check(GetLastError(), "Create future-version probe directory");
    if (!CopyFileW(exe, futureExe.c_str(), TRUE)) {
        DWORD error = GetLastError(); RemoveDirectoryW(futureDir.c_str()); check(error, "Create future-version executable");
    }
    std::wstring command = L"\"" + futureExe.wstring() + L"\" --assert-denied";
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    DWORD childCode = 1;
    bool launched = CreateProcessW(futureExe.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child) != FALSE;
    if (launched) {
        if (WaitForSingleObject(child.hProcess, 15000) != WAIT_OBJECT_0) {
            TerminateProcess(child.hProcess, 1); WaitForSingleObject(child.hProcess, 5000);
        }
        GetExitCodeProcess(child.hProcess, &childCode);
        CloseHandle(child.hThread); CloseHandle(child.hProcess);
    }
    DeleteFileW(futureExe.c_str()); RemoveDirectoryW(futureDir.c_str());
    if (!launched || childCode != 0) throw std::runtime_error("A newly created executable was not immediately blocked");
    std::cout << "PASS: new renamed executable is blocked on its first IPv4/IPv6 attempt without a policy refresh\n";
    {
        Transaction transaction(engine.handle);
        check(FwpmFilterDeleteById0(engine.handle, v4), "Replace VPN prefix IPv4 filter");
        check(FwpmFilterDeleteById0(engine.handle, v6), "Replace VPN prefix IPv6 filter");
        addBlock(engine.handle, L"prefix:" + nativePrefix(directory + L"\\"), FWPM_LAYER_ALE_AUTH_CONNECT_V4, luid, key, false);
        addBlock(engine.handle, L"prefix:" + nativePrefix(directory + L"\\"), FWPM_LAYER_ALE_AUTH_CONNECT_V6, luid, key, false);
        transaction.commit();
    }
    if (connectProbe(AF_INET) != 0) throw std::runtime_error("VPN interface was not usable under the guard");
    std::cout << "PASS: VPN IPv4 connection succeeds with interface restriction\n";
    WSACleanup();
    // Dynamic probe filters are removed even if this process crashes.
}
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc < 2) throw std::runtime_error("Usage: app-vpn-guard --once|--watch config.txt | --status | --remove | --probe adapter");
        std::wstring command = argv[1];
        if (command == L"--assert-denied") {
            WSADATA data{};
            check(WSAStartup(MAKEWORD(2,2), &data), "Initialize future-version socket probe");
            bool denied = connectProbe(AF_INET) == WSAEACCES && connectProbe(AF_INET6) == WSAEACCES;
            WSACleanup(); return denied ? 0 : 1;
        }
        if (command == L"--probe" && argc == 3) { probe(argv[2]); return 0; }
        if (command == L"--validate-config" && argc == 3) {
            auto paths = programs(readConfig(argv[2]));
            std::cout << "Valid configuration: " << paths.size() << " program/path scopes\n";
            return 0;
        }
        Engine engine;
        if (command == L"--status") { status(engine.handle); return 0; }
        if (command == L"--remove") { removeGuard(engine.handle); std::cout << "App guard policy removed\n"; return 0; }
        if (argc != 3 || (command != L"--once" && command != L"--watch")) throw std::runtime_error("Invalid guard arguments");
        Config config = readConfig(argv[2]);
        auto paths = programs(config);
        UINT64 lastLuid = UINT64_MAX;
        do {
            try {
                auto luid = vpnLuid(config.adapter);
                if (luid != lastLuid) {
                    apply(engine.handle, paths, luid);
                    lastLuid = luid;
                    std::cout << "Guard active: " << paths.size() << " program/path scopes, IPv4+IPv6, VPN interface "
                              << (luid ? "available" : "absent; applications blocked") << std::endl;
                }
            } catch (const std::exception& error) {
                std::cerr << error.what() << "; existing persistent filters retained\n";
                throw; // Scheduler restarts with a fresh BFE handle; policy remains persistent.
            }
            if (command == L"--once") break;
            Sleep(1000);
        } while (true);
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << std::endl; return 1; }
}
