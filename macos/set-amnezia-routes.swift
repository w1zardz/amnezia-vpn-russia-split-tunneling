import Foundation

struct Arguments {
    let domain: String
    let statePath: String
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data(("ERROR: \(message)\n").utf8))
    exit(1)
}

func parseArguments() -> Arguments {
    let values = Array(CommandLine.arguments.dropFirst())
    var parsed: [String: String] = [:]
    var index = 0
    while index < values.count {
        guard index + 1 < values.count else { fail("missing value for \(values[index])") }
        parsed[values[index]] = values[index + 1]
        index += 2
    }
    guard let domain = parsed["--domain"], let statePath = parsed["--state"] else {
        fail("usage: --domain DOMAIN --state FILE")
    }
    return Arguments(domain: domain, statePath: statePath)
}

func loadState(_ path: String) -> [String: Any] {
    do {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        guard let result = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              result["sites"] is [String: Any] else {
            fail("\(path) is not a routing state object")
        }
        return result
    } catch {
        fail("cannot read \(path): \(error)")
    }
}

func setOrRemove(_ value: Any?, key: String, defaults: UserDefaults) {
    if value == nil || value is NSNull {
        defaults.removeObject(forKey: key)
    } else {
        defaults.set(value, forKey: key)
    }
}

func assertAmneziaStopped() {
    for name in ["AmneziaVPN", "amneziawg-go"] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-x", name]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            fail("cannot check whether Amnezia is stopped")
        }
        guard process.terminationReason == .exit && process.terminationStatus == 1 else {
            fail("Amnezia is running or process state is unknown; refusing routing write")
        }
    }
}

let arguments = parseArguments()
let state = loadState(arguments.statePath)
guard let sites = state["sites"] as? [String: Any] else {
    fail("routing state does not contain sites")
}
guard sites.count <= 4096 else {
    fail("refusing suspicious ExceptSites count: \(sites.count)")
}
assertAmneziaStopped()
guard let defaults = UserDefaults(suiteName: arguments.domain) else {
    fail("cannot open UserDefaults suite \(arguments.domain)")
}

defaults.set(sites, forKey: "Conf.ExceptSites")
setOrRemove(state["mode"], key: "Conf.routeMode", defaults: defaults)
setOrRemove(state["enabled"], key: "Conf.sitesSplitTunnelingEnabled", defaults: defaults)
guard defaults.synchronize() else {
    fail("NSUserDefaults synchronize failed")
}
assertAmneziaStopped()

guard let verifiedSites = defaults.dictionary(forKey: "Conf.ExceptSites"),
      NSDictionary(dictionary: verifiedSites).isEqual(to: sites) else {
    fail("Conf.ExceptSites mismatch after write")
}
print("Applied routing state; ExceptSites: \(verifiedSites.count)")
