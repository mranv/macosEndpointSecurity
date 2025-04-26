import Foundation
import EndpointSecurity
import Darwin

// MARK: - Constants and Definitions

// Code signing flags from kern/cs_blobs.h
let CS_VALID: UInt32 = 0x00000001
let CS_ADHOC: UInt32 = 0x00000002
let CS_GET_TASK_ALLOW: UInt32 = 0x00000004
let CS_INSTALLER: UInt32 = 0x00000008
let CS_FORCED_LV: UInt32 = 0x00000010
let CS_INVALID_ALLOWED: UInt32 = 0x00000020
let CS_HARD: UInt32 = 0x00000100
let CS_KILL: UInt32 = 0x00000200
let CS_CHECK_EXPIRATION: UInt32 = 0x00000400
let CS_RESTRICT: UInt32 = 0x00000800
let CS_ENFORCEMENT: UInt32 = 0x00001000
let CS_REQUIRE_LV: UInt32 = 0x00002000
let CS_ENTITLEMENTS_VALIDATED: UInt32 = 0x00004000
let CS_NVRAM_UNRESTRICTED: UInt32 = 0x00008000
let CS_RUNTIME: UInt32 = 0x00010000
let CS_LINKER_SIGNED: UInt32 = 0x00020000
let CS_EXEC_SET_HARD: UInt32 = 0x00100000
let CS_EXEC_SET_KILL: UInt32 = 0x00200000
let CS_EXEC_SET_ENFORCEMENT: UInt32 = 0x00400000
let CS_EXEC_INHERIT_SIP: UInt32 = 0x00800000
let CS_KILLED: UInt32 = 0x01000000
let CS_DYLD_PLATFORM: UInt32 = 0x02000000
let CS_PLATFORM_BINARY: UInt32 = 0x04000000
let CS_PLATFORM_PATH: UInt32 = 0x08000000
let CS_DEBUGGED: UInt32 = 0x10000000
let CS_SIGNED: UInt32 = 0x20000000
let CS_DEV_CODE: UInt32 = 0x40000000
let CS_DATAVAULT_CONTROLLER: UInt32 = 0x80000000

// File access flags
let O_RDONLY: Int32 = 0x0000
let O_WRONLY: Int32 = 0x0001
let O_RDWR: Int32 = 0x0002
let O_NONBLOCK: Int32 = 0x0004
let O_APPEND: Int32 = 0x0008
let O_SHLOCK: Int32 = 0x0010
let O_EXLOCK: Int32 = 0x0020
let O_ASYNC: Int32 = 0x0040
let O_NOFOLLOW: Int32 = 0x0100
let O_CREAT: Int32 = 0x0200
let O_TRUNC: Int32 = 0x0400
let O_EXCL: Int32 = 0x0800
let O_EVTONLY: Int32 = 0x8000
let O_NOCTTY: Int32 = 0x20000
let O_DIRECTORY: Int32 = 0x100000
let O_SYMLINK: Int32 = 0x200000
let O_CLOEXEC: Int32 = 0x1000000
let O_NOFOLLOW_ANY: Int32 = 0x20000000

// Memory protection flags
let PROT_NONE: Int32 = 0x00
let PROT_READ: Int32 = 0x01
let PROT_WRITE: Int32 = 0x02
let PROT_EXEC: Int32 = 0x04

// MARK: - Utility Functions

func dateFromTimeSpec(sec: Int, nsec: Int) -> String {
    let date = Date(timeIntervalSince1970: TimeInterval(sec))
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
    return "\(formatter.string(from: date)).\(nsec)"
}

func formatFlagsToString(_ flags: UInt32, _ flagsMap: [UInt32: String]) -> String {
    var result = ""
    var origValue = flags
    var remainingFlags = flags
    
    for (flag, name) in flagsMap {
        if flags & flag != 0 {
            if !result.isEmpty {
                result += "|"
            }
            result += name
            remainingFlags &= ~flag
        }
    }
    
    if remainingFlags != 0 {
        result += " [\(String(remainingFlags, radix: 16))?]"
    }
    
    return "\(result) (\(origValue))"
}

// MARK: - Event Data Models

protocol ESEvent: Codable {
    var eventTime: String { get }
    var processInfo: ProcessInfo { get }
    var isAuthentication: Bool { get }
}

struct ProcessInfo: Codable {
    var pid: pid_t
    var ppid: pid_t
    var originalPpid: pid_t
    var euid: uid_t
    var ruid: uid_t
    var egid: gid_t
    var rgid: gid_t
    var groupId: pid_t
    var sessionId: pid_t
    var codeSignFlags: UInt32
    var codeSignFlagsDesc: String
    var isPlatformBinary: Bool
    var isEsClient: Bool
    var signingId: String
    var teamId: String
    var executablePath: String
    var threadId: UInt64
    var startTime: String
    
    init(from process: UnsafeMutablePointer<es_process_t>) {
        let auditToken = process.pointee.audit_token
        self.pid = audit_token_to_pid(auditToken)
        self.euid = audit_token_to_euid(auditToken)
        self.ruid = audit_token_to_ruid(auditToken)
        self.egid = audit_token_to_egid(auditToken)
        self.rgid = audit_token_to_rgid(auditToken)
        self.ppid = process.pointee.ppid
        self.originalPpid = process.pointee.original_ppid
        self.groupId = process.pointee.group_id
        self.sessionId = process.pointee.session_id
        self.codeSignFlags = process.pointee.codesigning_flags
        
        // Create map for code signing flags
        let csFlags: [UInt32: String] = [
            CS_VALID: "CS_VALID",
            CS_ADHOC: "CS_ADHOC",
            CS_GET_TASK_ALLOW: "CS_GET_TASK_ALLOW",
            CS_INSTALLER: "CS_INSTALLER",
            CS_FORCED_LV: "CS_FORCED_LV",
            CS_INVALID_ALLOWED: "CS_INVALID_ALLOWED",
            CS_HARD: "CS_HARD",
            CS_KILL: "CS_KILL",
            CS_CHECK_EXPIRATION: "CS_CHECK_EXPIRATION",
            CS_RESTRICT: "CS_RESTRICT",
            CS_ENFORCEMENT: "CS_ENFORCEMENT",
            CS_REQUIRE_LV: "CS_REQUIRE_LV",
            CS_ENTITLEMENTS_VALIDATED: "CS_ENTITLEMENTS_VALIDATED",
            CS_NVRAM_UNRESTRICTED: "CS_NVRAM_UNRESTRICTED",
            CS_RUNTIME: "CS_RUNTIME",
            CS_LINKER_SIGNED: "CS_LINKER_SIGNED",
            CS_EXEC_SET_HARD: "CS_EXEC_SET_HARD",
            CS_EXEC_SET_KILL: "CS_EXEC_SET_KILL",
            CS_EXEC_SET_ENFORCEMENT: "CS_EXEC_SET_ENFORCEMENT",
            CS_EXEC_INHERIT_SIP: "CS_EXEC_INHERIT_SIP",
            CS_KILLED: "CS_KILLED",
            CS_DYLD_PLATFORM: "CS_DYLD_PLATFORM",
            CS_PLATFORM_BINARY: "CS_PLATFORM_BINARY",
            CS_PLATFORM_PATH: "CS_PLATFORM_PATH",
            CS_DEBUGGED: "CS_DEBUGGED",
            CS_SIGNED: "CS_SIGNED",
            CS_DEV_CODE: "CS_DEV_CODE",
            CS_DATAVAULT_CONTROLLER: "CS_DATAVAULT_CONTROLLER"
        ]
        
        self.codeSignFlagsDesc = formatFlagsToString(self.codeSignFlags, csFlags)
        self.isPlatformBinary = process.pointee.is_platform_binary
        self.isEsClient = process.pointee.is_es_client
        
        // Get signing ID
        if process.pointee.signing_id.length > 0 {
            self.signingId = String(cString: process.pointee.signing_id.data)
        } else {
            self.signingId = ""
        }
        
        // Get team ID
        if process.pointee.team_id.length > 0 {
            self.teamId = String(cString: process.pointee.team_id.data)
        } else {
            self.teamId = ""
        }
        
        // Get executable path
        if let executable = process.pointee.executable {
            self.executablePath = String(cString: executable.pointee.path.data)
        } else {
            self.executablePath = ""
        }
        
        // Set thread ID and start time
        self.threadId = 0 // We'll set this from the thread pointee later
        self.startTime = dateFromTimeSpec(sec: Int(process.pointee.start_time.tv_sec),
                                        nsec: Int(process.pointee.start_time.tv_nsec))
    }
}

struct BaseEvent: ESEvent {
    var eventType: String
    var eventTime: String
    var processInfo: ProcessInfo
    var isAuthentication: Bool
    
    init(type: String, message: UnsafePointer<es_message_t>) {
        self.eventType = type
        self.eventTime = dateFromTimeSpec(sec: Int(message.pointee.time.tv_sec),
                                        nsec: Int(message.pointee.time.tv_nsec))
        self.processInfo = ProcessInfo(from: message.pointee.process)
        self.isAuthentication = message.pointee.action_type == ES_ACTION_TYPE_AUTH
    }
}

struct ExecEvent: Codable {
    var targetProcess: ProcessInfo
    var args: [String]
    
    init(from event: UnsafePointer<es_message_t>) {
        let execEvent = event.pointee.event.exec
        self.targetProcess = ProcessInfo(from: execEvent.target)
        
        // Parse command line arguments
        var arguments: [String] = []
        let argCount = es_exec_arg_count(&event.pointee.event.exec)
        
        for i in 0..<argCount {
            let arg = es_exec_arg(&event.pointee.event.exec, i)
            arguments.append(String(cString: arg.data))
        }
        
        self.args = arguments
    }
}

struct OpenEvent: Codable {
    var filePath: String
    var fileFlags: Int32
    var fileFlagsDesc: String
    
    init(from event: UnsafePointer<es_message_t>) {
        let openEvent = event.pointee.event.open
        
        // Get file path
        if let file = openEvent.file {
            self.filePath = String(cString: file.pointee.path.data)
        } else {
            self.filePath = ""
        }
        
        self.fileFlags = openEvent.fflag
        
        // Create map for file open flags
        let flagsMap: [Int32: String] = [
            O_RDONLY: "O_RDONLY",
            O_WRONLY: "O_WRONLY",
            O_RDWR: "O_RDWR",
            O_NONBLOCK: "O_NONBLOCK",
            O_APPEND: "O_APPEND",
            O_SHLOCK: "O_SHLOCK",
            O_EXLOCK: "O_EXLOCK",
            O_ASYNC: "O_ASYNC",
            O_NOFOLLOW: "O_NOFOLLOW",
            O_CREAT: "O_CREAT",
            O_TRUNC: "O_TRUNC",
            O_EXCL: "O_EXCL",
            O_EVTONLY: "O_EVTONLY",
            O_NOCTTY: "O_NOCTTY",
            O_DIRECTORY: "O_DIRECTORY",
            O_SYMLINK: "O_SYMLINK",
            O_CLOEXEC: "O_CLOEXEC",
            O_NOFOLLOW_ANY: "O_NOFOLLOW_ANY"
        ]
        
        self.fileFlagsDesc = formatFlagsToString(UInt32(self.fileFlags), flagsMap.mapValues { $0 })
    }
}

struct CloseEvent: Codable {
    var filePath: String
    var modified: Bool
    
    init(from event: UnsafePointer<es_message_t>) {
        let closeEvent = event.pointee.event.close
        
        // Get file path
        if let file = closeEvent.target {
            self.filePath = String(cString: file.pointee.path.data)
        } else {
            self.filePath = ""
        }
        
        self.modified = closeEvent.modified
    }
}

struct ForkEvent: Codable {
    var childProcess: ProcessInfo
    
    init(from event: UnsafePointer<es_message_t>) {
        let forkEvent = event.pointee.event.fork
        self.childProcess = ProcessInfo(from: forkEvent.child)
    }
}

struct ExitEvent: Codable {
    var status: Int32
    var statusDescription: String
    
    init(from event: UnsafePointer<es_message_t>) {
        let exitEvent = event.pointee.event.exit
        self.status = exitEvent.stat
        
        // Parse the status according to wait(2)
        if WIFEXITED(Int32(self.status)) {
            self.statusDescription = "normal exit with code \(WEXITSTATUS(Int32(self.status)))"
        } else if WIFSIGNALED(Int32(self.status)) {
            let signal = WTERMSIG(Int32(self.status))
            let coreDump = WCOREDUMP(Int32(self.status)) ? " (coredump created)" : ""
            self.statusDescription = "killed by signal \(signal)\(coreDump)"
        } else {
            self.statusDescription = "unknown exit status"
        }
    }
}

struct UnlinkEvent: Codable {
    var filePath: String
    
    init(from event: UnsafePointer<es_message_t>) {
        let unlinkEvent = event.pointee.event.unlink
        
        // Get file path
        if let file = unlinkEvent.target {
            self.filePath = String(cString: file.pointee.path.data)
        } else {
            self.filePath = ""
        }
    }
}

struct ChdirEvent: Codable {
    var directoryPath: String
    
    init(from event: UnsafePointer<es_message_t>) {
        let chdirEvent = event.pointee.event.chdir
        
        // Get directory path
        if let file = chdirEvent.target {
            self.directoryPath = String(cString: file.pointee.path.data)
        } else {
            self.directoryPath = ""
        }
    }
}

struct SignalEvent: Codable {
    var targetProcess: ProcessInfo
    var signal: UInt32
    
    init(from event: UnsafePointer<es_message_t>) {
        let signalEvent = event.pointee.event.signal
        self.targetProcess = ProcessInfo(from: signalEvent.target)
        self.signal = signalEvent.sig
    }
}

struct MmapEvent: Codable {
    var filePath: String
    var filePos: UInt64
    var flags: Int32
    var flagsDesc: String
    var maxProtection: Int32
    var maxProtectionDesc: String
    var protection: Int32
    var protectionDesc: String
    
    init(from event: UnsafePointer<es_message_t>) {
        let mmapEvent = event.pointee.event.mmap
        
        // Get file path
        if let file = mmapEvent.source {
            self.filePath = String(cString: file.pointee.path.data)
        } else {
            self.filePath = ""
        }
        
        self.filePos = mmapEvent.file_pos
        self.flags = mmapEvent.flags
        self.maxProtection = mmapEvent.max_protection
        self.protection = mmapEvent.protection
        
        // Create map for mmap protection flags
        let protFlags: [Int32: String] = [
            PROT_NONE: "PROT_NONE",
            PROT_READ: "PROT_READ",
            PROT_WRITE: "PROT_WRITE",
            PROT_EXEC: "PROT_EXEC"
        ]
        
        self.maxProtectionDesc = formatFlagsToString(UInt32(self.maxProtection), protFlags.mapValues { $0 })
        self.protectionDesc = formatFlagsToString(UInt32(self.protection), protFlags.mapValues { $0 })
        
        // Create map for mmap flags (not complete, would need to add more)
        let mmapFlagsMap: [Int32: String] = [
            0x0001: "MAP_SHARED",
            0x0002: "MAP_PRIVATE",
            0x0010: "MAP_FIXED",
            0x1000: "MAP_ANON"
        ]
        
        self.flagsDesc = formatFlagsToString(UInt32(self.flags), mmapFlagsMap.mapValues { $0 })
    }
}

// MARK: - Main Event Struct

struct ComprehensiveESEvent: Codable {
    var id = UUID()
    var baseEvent: BaseEvent
    
    // Event-specific fields
    var execEvent: ExecEvent?
    var openEvent: OpenEvent?
    var closeEvent: CloseEvent?
    var forkEvent: ForkEvent?
    var exitEvent: ExitEvent?
    var unlinkEvent: UnlinkEvent?
    var chdirEvent: ChdirEvent?
    var signalEvent: SignalEvent?
    var mmapEvent: MmapEvent?
    
    init(fromRawEvent rawEvent: UnsafePointer<es_message_t>) {
        // Set thread ID in process info
        var baseEventType = "UNKNOWN"
        
        // Determine event type
        switch rawEvent.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_AUTH_EXEC:
            baseEventType = "exec"
            self.execEvent = ExecEvent(from: rawEvent)
        case ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_AUTH_OPEN:
            baseEventType = "open"
            self.openEvent = OpenEvent(from: rawEvent)
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            baseEventType = "close"
            self.closeEvent = CloseEvent(from: rawEvent)
        case ES_EVENT_TYPE_NOTIFY_FORK:
            baseEventType = "fork"
            self.forkEvent = ForkEvent(from: rawEvent)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            baseEventType = "exit"
            self.exitEvent = ExitEvent(from: rawEvent)
        case ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_AUTH_UNLINK:
            baseEventType = "unlink"
            self.unlinkEvent = UnlinkEvent(from: rawEvent)
        case ES_EVENT_TYPE_NOTIFY_CHDIR, ES_EVENT_TYPE_AUTH_CHDIR:
            baseEventType = "chdir"
            self.chdirEvent = ChdirEvent(from: rawEvent)
        case ES_EVENT_TYPE_NOTIFY_SIGNAL, ES_EVENT_TYPE_AUTH_SIGNAL:
            baseEventType = "signal"
            self.signalEvent = SignalEvent(from: rawEvent)
        case ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_AUTH_MMAP:
            baseEventType = "mmap"
            self.mmapEvent = MmapEvent(from: rawEvent)
        default:
            break
        }
        
        self.baseEvent = BaseEvent(type: baseEventType, message: rawEvent)
    }
}

// MARK: - Endpoint Security Client Manager

class ComprehensiveESMonitor {
    private var esClient: OpaquePointer?
    private var monitoredProcessPath: String?
    private var monitoredProcesses: [pid_t: Bool] = [:]
    private var excludedProcesses: [pid_t: Bool] = [:]
    
    // Configuration options
    struct Config {
        var excludeSelf: Bool = true
        var monitorProcessPath: String? = nil
        var eventTypes: [es_event_type_t] = []
        var jsonOutput: Bool = true
        var verbose: Bool = false
    }
    
    private var config = Config()
    
    // All supported event types
    let supportedEvents: [(String, [es_event_type_t])] = [
        ("access", [ES_EVENT_TYPE_NOTIFY_ACCESS]),
        ("chdir", [ES_EVENT_TYPE_NOTIFY_CHDIR, ES_EVENT_TYPE_AUTH_CHDIR]),
        ("chroot", [ES_EVENT_TYPE_NOTIFY_CHROOT, ES_EVENT_TYPE_AUTH_CHROOT]),
        ("clone", [ES_EVENT_TYPE_NOTIFY_CLONE, ES_EVENT_TYPE_AUTH_CLONE]),
        ("close", [ES_EVENT_TYPE_NOTIFY_CLOSE]),
        ("create", [ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_AUTH_CREATE]),
        ("deleteextattr", [ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, ES_EVENT_TYPE_AUTH_DELETEEXTATTR]),
        ("dup", [ES_EVENT_TYPE_NOTIFY_DUP]),
        ("exchangedata", [ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_EXCHANGEDATA]),
        ("exec", [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_AUTH_EXEC]),
        ("exit", [ES_EVENT_TYPE_NOTIFY_EXIT]),
        ("fcntl", [ES_EVENT_TYPE_NOTIFY_FCNTL, ES_EVENT_TYPE_AUTH_FCNTL]),
        ("fork", [ES_EVENT_TYPE_NOTIFY_FORK]),
        ("fsgetpath", [ES_EVENT_TYPE_NOTIFY_FSGETPATH, ES_EVENT_TYPE_AUTH_FSGETPATH]),
        ("get_task", [ES_EVENT_TYPE_NOTIFY_GET_TASK, ES_EVENT_TYPE_AUTH_GET_TASK]),
        ("iokit_open", [ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, ES_EVENT_TYPE_AUTH_IOKIT_OPEN]),
        ("link", [ES_EVENT_TYPE_NOTIFY_LINK, ES_EVENT_TYPE_AUTH_LINK]),
        ("lookup", [ES_EVENT_TYPE_NOTIFY_LOOKUP]),
        ("mmap", [ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_AUTH_MMAP]),
        ("mount", [ES_EVENT_TYPE_NOTIFY_MOUNT, ES_EVENT_TYPE_AUTH_MOUNT]),
        ("mprotect", [ES_EVENT_TYPE_NOTIFY_MPROTECT, ES_EVENT_TYPE_AUTH_MPROTECT]),
        ("open", [ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_AUTH_OPEN]),
        ("readdir", [ES_EVENT_TYPE_NOTIFY_READDIR, ES_EVENT_TYPE_AUTH_READDIR]),
        ("readlink", [ES_EVENT_TYPE_NOTIFY_READLINK, ES_EVENT_TYPE_AUTH_READLINK]),
        ("rename", [ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_AUTH_RENAME]),
        ("setextattr", [ES_EVENT_TYPE_NOTIFY_SETEXTATTR, ES_EVENT_TYPE_AUTH_SETEXTATTR]),
        ("signal", [ES_EVENT_TYPE_NOTIFY_SIGNAL, ES_EVENT_TYPE_AUTH_SIGNAL]),
        ("truncate", [ES_EVENT_TYPE_NOTIFY_TRUNCATE, ES_EVENT_TYPE_AUTH_TRUNCATE]),
        ("unlink", [ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_AUTH_UNLINK]),
        ("write", [ES_EVENT_TYPE_NOTIFY_WRITE])
    ]
    
    init(configuration: Config? = nil) {
        if let config = configuration {
            self.config = config
        }
        
        if self.config.eventTypes.isEmpty {
            // Default to subscribing to all events
            for (_, events) in supportedEvents {
                self.config.eventTypes.append(contentsOf: events)
            }
        }
        
        if let path = self.config.monitorProcessPath {
            self.monitoredProcessPath = path
        }
    }
    
    // Convert event to JSON string
    private func eventToJSON(_ event: ComprehensiveESEvent) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .withoutEscapingSlashes]
        
        do {
            let data = try encoder.encode(event)
            return String(data: data, encoding: .utf8) ?? "{\"error\":\"Failed to encode event\"}"
        } catch {
            return "{\"error\":\"Failed to encode event: \(error.localizedDescription)\"}"
        }
    }
    
    // Format event for text output
    private func formatEvent(_ event: ComprehensiveESEvent) -> String {
        var output = "event : \(event.baseEvent.eventType)\n"
        output += "  time: \(event.baseEvent.eventTime)\n"
        
        // Add event-specific details
        if let execEvent = event.execEvent {
            output += "  executable: \(execEvent.targetProcess.executablePath)\n"
            output += "  args: \(execEvent.args.joined(separator: " "))\n"
        }
        
        if let openEvent = event.openEvent {
            output += "  file: \(openEvent.filePath)\n"
            output += "  flags: \(openEvent.fileFlagsDesc)\n"
        }
        
        if let closeEvent = event.closeEvent {
            output += "  file: \(closeEvent.filePath)\n"
            output += "  modified: \(closeEvent.modified)\n"
        }
        
        if let forkEvent = event.forkEvent {
            output += "  child_pid: \(forkEvent.childProcess.pid)\n"
        }
        
        if let exitEvent = event.exitEvent {
            output += "  status: \(exitEvent.status)\n"
            output += "  reason: \(exitEvent.statusDescription)\n"
        }
        
        if let unlinkEvent = event.unlinkEvent {
            output += "  file: \(unlinkEvent.filePath)\n"
        }
        
        if let chdirEvent = event.chdirEvent {
            output += "  directory: \(chdirEvent.directoryPath)\n"
        }
        
        if let signalEvent = event.signalEvent {
            output += "  target_pid: \(signalEvent.targetProcess.pid)\n"
            output += "  signal: \(signalEvent.signal)\n"
        }
        
        if let mmapEvent = event.mmapEvent {
            output += "  file: \(mmapEvent.filePath)\n"
            output += "  protection: \(mmapEvent.protectionDesc)\n"
            output += "  flags: \(mmapEvent.flagsDesc)\n"
        }
        
        // Add process info
        output += " process:\n"
        output += "        PID: \(event.baseEvent.processInfo.pid)\n"
        output += "       EUID: \(event.baseEvent.processInfo.euid)\n"
        output += "       EGID: \(event.baseEvent.processInfo.egid)\n"
        output += "       PPID: \(event.baseEvent.processInfo.ppid)\n"
        
        if event.baseEvent.processInfo.ruid != event.baseEvent.processInfo.euid {
            output += "       RUID: \(event.baseEvent.processInfo.ruid)\n"
        }
        
        if event.baseEvent.processInfo.rgid != event.baseEvent.processInfo.egid {
            output += "       RGID: \(event.baseEvent.processInfo.rgid)\n"
        }
        
        output += "        GID: \(event.baseEvent.processInfo.groupId)\n"
        output += "        SID: \(event.baseEvent.processInfo.sessionId)\n"
        output += "       Path: \(event.baseEvent.processInfo.executablePath)\n"
        output += "    CSFlags: \(event.baseEvent.processInfo.codeSignFlagsDesc)\n"
        
        if !event.baseEvent.processInfo.signingId.isEmpty {
            output += "   SigningID: \(event.baseEvent.processInfo.signingId)\n"
        }
        
        if !event.baseEvent.processInfo.teamId.isEmpty {
            output += "     TeamID: \(event.baseEvent.processInfo.teamId)\n"
        }
        
        output += "    Started: \(event.baseEvent.processInfo.startTime)\n"
        
        let extraInfo = [
            event.baseEvent.processInfo.isPlatformBinary ? "platform_binary" : "",
            event.baseEvent.processInfo.isEsClient ? "es_client" : ""
        ].filter { !$0.isEmpty }.joined(separator: " ")
        
        if !extraInfo.isEmpty {
            output += "      Extra: \(extraInfo)\n"
        }
        
        output += "\n"
        
        return output
    }
    
    // Process events and handle authorization responses
    private func handleEvent(_ message: UnsafePointer<es_message_t>) {
        // Check if this is our own process
        let pid = audit_token_to_pid(message.pointee.process.pointee.audit_token)
        
        // Skip processing for our own process if configured
        if config.excludeSelf && pid == getpid() {
            if let client = self.esClient {
                es_mute_process(client, &message.pointee.process.pointee.audit_token)
            }
            return
        }
        
        // Skip processing for excluded processes
        if excludedProcesses[pid] == true {
            return
        }
        
        // Check if we're monitoring specific processes
        if let path = monitoredProcessPath {
            let processPath = String(cString: message.pointee.process.pointee.executable.pointee.path.data)
            if !processPath.hasPrefix(path) && monitoredProcesses[pid] != true {
                // If this is an exec event, check if the target is a monitored process
                if message.pointee.event_type == ES_EVENT_TYPE_NOTIFY_EXEC || 
                   message.pointee.event_type == ES_EVENT_TYPE_AUTH_EXEC {
                    let targetPath = String(cString: message.pointee.event.exec.target.pointee.executable.pointee.path.data)
                    if targetPath.hasPrefix(path) {
                        // Add the new process to our monitoring list
                        let targetPid = audit_token_to_pid(message.pointee.event.exec.target.pointee.audit_token)
                        monitoredProcesses[targetPid] = true
                    }
                }
                return
            }
        }
        
        // Track fork events to monitor child processes
        if message.pointee.event_type == ES_EVENT_TYPE_NOTIFY_FORK {
            let childPid = audit_token_to_pid(message.pointee.event.fork.child.pointee.audit_token)
            if monitoredProcesses[pid] == true {
                monitoredProcesses[childPid] = true
            }
        }
        
        // Handle exit events to cleanup process tracking
        if message.pointee.event_type == ES_EVENT_TYPE_NOTIFY_EXIT {
            monitoredProcesses.removeValue(forKey: pid)
        }
        
        // Create event object
        let event = ComprehensiveESEvent(fromRawEvent: message)
        
        // Log the event
        if config.jsonOutput {
            print(eventToJSON(event))
        } else {
            print(formatEvent(event))
        }
        
        // Handle authorization responses
        if message.pointee.action_type == ES_ACTION_TYPE_AUTH {
            if let client = self.esClient {
                if message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN {
                    let res = es_respond_flags_result(client, message, 0x7FFFFFFF, true)
                    if res != ES_RESPOND_RESULT_SUCCESS && config.verbose {
                        print("[ERROR] Failed to respond to AUTH_OPEN event: \(res)")
                    }
                } else {
                    let res = es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, true)
                    if res != ES_RESPOND_RESULT_SUCCESS && config.verbose {
                        print("[ERROR] Failed to respond to AUTH event: \(res)")
                    }
                }
            }
        }
    }
    
    // Create the ES client and start monitoring
    func startMonitoring() -> Bool {
        var client: OpaquePointer?
        
        // Create new ES client
        let result = es_new_client(&client) { [weak self] _, event in
            self?.handleEvent(event)
        }
        
        // Check result
        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            if config.verbose {
                print("[INFO] Successfully created ES client")
            }
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            print("[ERROR] Too many ES clients")
            return false
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            print("[ERROR] Not entitled - the EndpointSecurity entitlement is required")
            return false
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            print("[ERROR] Not permitted - check TCC permissions")
            return false
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            print("[ERROR] Not privileged - must run as root")
            return false
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            print("[ERROR] Internal error communicating with ES")
            return false
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            print("[ERROR] Invalid argument")
            return false
        default:
            print("[ERROR] Unknown error creating ES client: \(result.rawValue)")
            return false
        }
        
        self.esClient = client
        
        // Subscribe to events
        if es_subscribe(client!, self.config.eventTypes, UInt32(self.config.eventTypes.count)) != ES_RETURN_SUCCESS {
            print("[ERROR] Failed to subscribe to events")
            es_delete_client(client)
            self.esClient = nil
            return false
        }
        
        if config.verbose {
            print("[INFO] Successfully subscribed to events")
        }
        
        // Exclude our own process if needed
        if config.excludeSelf, let client = self.esClient {
            let selfPid = getpid()
            excludedProcesses[selfPid] = true
            
            // We need to get our own audit token to mute ourselves
            // This is a bit tricky in Swift, but we can use a trick to get it
            DispatchQueue.global().async {
                // Wait for events that might include our own process
                sleep(1)
            }
        }
        
        return true
    }
    
    // Stop monitoring and cleanup
    func stopMonitoring() {
        if let client = self.esClient {
            es_delete_client(client)
            self.esClient = nil
        }
    }
}

// MARK: - Command-line argument parsing

func parseCommandLineArgs() -> ComprehensiveESMonitor.Config {
    var config = ComprehensiveESMonitor.Config()
    var argIndex = 1
    
    while argIndex < CommandLine.arguments.count {
        let arg = CommandLine.arguments[argIndex]
        
        switch arg {
        case "-e", "--event":
            if argIndex + 1 < CommandLine.arguments.count {
                argIndex += 1
                let events = CommandLine.arguments[argIndex].split(separator: ",")
                
                if events.contains("all") {
                    // Subscribe to all events
                    let monitor = ComprehensiveESMonitor()
                    for (_, eventTypes) in monitor.supportedEvents {
                        config.eventTypes.append(contentsOf: eventTypes)
                    }
                } else {
                    // Parse individual events
                    let monitor = ComprehensiveESMonitor()
                    for event in events {
                        var eventName = String(event)
                        var isAuthEvent = false
                        var isRemove = false
                        
                        // Check for +/- prefix
                        if eventName.hasPrefix("+") {
                            isAuthEvent = true
                            eventName.removeFirst()
                        } else if eventName.hasPrefix("-") {
                            isRemove = true
                            eventName.removeFirst()
                        }
                        
                        // Find the event type
                        if let eventInfo = monitor.supportedEvents.first(where: { $0.0 == eventName }) {
                            if isRemove {
                                // Remove event from the list
                                let eventType = isAuthEvent ? eventInfo.1.last! : eventInfo.1.first!
                                if let index = config.eventTypes.firstIndex(of: eventType) {
                                    config.eventTypes.remove(at: index)
                                }
                            } else {
                                // Add event to the list
                                let eventType = isAuthEvent ? eventInfo.1.last! : eventInfo.1.first!
                                config.eventTypes.append(eventType)
                            }
                        } else {
                            print("Unknown event type: \(eventName)")
                        }
                    }
                }
            }
        case "-p", "--path":
            if argIndex + 1 < CommandLine.arguments.count {
                argIndex += 1
                config.monitorProcessPath = CommandLine.arguments[argIndex]
            }
        case "-j", "--json":
            config.jsonOutput = true
        case "-t", "--text":
            config.jsonOutput = false
        case "-v", "--verbose":
            config.verbose = true
        case "--include-self":
            config.excludeSelf = false
        case "-h", "--help":
            printUsage()
            exit(0)
        default:
            print("Unknown option: \(arg)")
            printUsage()
            exit(1)
        }
        
        argIndex += 1
    }
    
    return config
}

func printUsage() {
    print("""
    Usage: ComprehensiveESMonitor [options]
      -e, --event <events>  Events to monitor (comma-separated). Use 'all' for all events.
                           Prefix with '+' for auth events, '-' to remove events
      -p, --path <path>     Only monitor processes from this path
      -j, --json            Output events as JSON (default)
      -t, --text            Output events as formatted text
      -v, --verbose         Enable verbose logging
          --include-self    Include events from this process (not recommended)
      -h, --help            Show this help message
    
    Examples:
      ComprehensiveESMonitor -e all                    # Monitor all events
      ComprehensiveESMonitor -e exec,open,close -t     # Monitor specific events with text output
      ComprehensiveESMonitor -e all,-mprotect          # Monitor all events except mprotect
      ComprehensiveESMonitor -p /Applications          # Only monitor processes in /Applications
    """)
    
    // Print available events
    print("\nAvailable events:")
    let monitor = ComprehensiveESMonitor()
    for (eventName, eventTypes) in monitor.supportedEvents {
        let hasAuth = eventTypes.count > 1
        print("  \(hasAuth ? "[+]" : "   ")\(eventName)")
    }
}

// MARK: - Main function

func main() {
    // Check if running as root
    if getuid() != 0 {
        print("Error: This program must be run as root.")
        exit(1)
    }
    
    // Parse command-line arguments
    let config = parseCommandLineArgs()
    
    // Create and start the monitor
    let monitor = ComprehensiveESMonitor(configuration: config)
    if !monitor.startMonitoring() {
        print("Failed to start monitoring")
        exit(1)
    }
    
    print("Monitoring started. Press Ctrl+C to exit.")
    
    // Setup signal handler for clean exit
    signal(SIGINT) { _ in
        print("\nShutting down...")
        exit(0)
    }
    
    // Run forever until interrupted
    dispatchMain()
}

main()
