# ComprehensiveESMonitor

A powerful macOS process monitoring tool leveraging the EndpointSecurity framework to provide visibility into system events and process activity.

## Overview

ComprehensiveESMonitor is a Swift-based security monitoring tool that captures and logs system events using Apple's EndpointSecurity framework. It provides comprehensive visibility into process execution, file operations, and other system activities that are valuable for security monitoring, threat detection, and forensic analysis.

## Features

- **Extensive Event Coverage**: Monitor a wide range of system events including process executions, file operations, network activity, and more
- **Detailed Process Information**: Capture comprehensive metadata about processes including PID, executable path, code signing status, and parent/child relationships
- **Flexible Configuration**: Filter events by type or process path to focus on relevant activity
- **Multiple Output Formats**: Choose between JSON or human-readable text output
- **Authorization Handling**: Properly responds to authorization events to avoid system deadlocks
- **Process Relationship Tracking**: Follow parent/child relationships for process attribution

## Requirements

- macOS 10.15 (Catalina) or later
- Xcode 12 or later for building
- Root privileges for running
- EndpointSecurity entitlement (`com.apple.developer.endpoint-security.client`) or disabled System Integrity Protection (SIP)

## Building

```bash
# Compile the Swift code
swiftc ComprehensiveESMonitor.swift -o ComprehensiveESMonitor -framework EndpointSecurity -framework Foundation

# Code sign with entitlements (requires proper certificate)
codesign -s <identity> --entitlements es_monitor.entitlements --force ComprehensiveESMonitor
```

## Usage

```bash
# Run with root privileges
sudo ./ComprehensiveESMonitor [options]
```

### Command-line Options

```
Usage: ComprehensiveESMonitor [options]
  -e, --event <events>  Events to monitor (comma-separated). Use 'all' for all events.
                       Prefix with '+' for auth events, '-' to remove events
  -p, --path <path>     Only monitor processes from this path
  -j, --json            Output events as JSON (default)
  -t, --text            Output events as formatted text
  -v, --verbose         Enable verbose logging
      --include-self    Include events from this process (not recommended)
  -h, --help            Show this help message
```

### Examples

```bash
# Monitor all events
sudo ./ComprehensiveESMonitor -e all

# Monitor specific events with text output
sudo ./ComprehensiveESMonitor -e exec,open,close -t

# Monitor all events except mprotect
sudo ./ComprehensiveESMonitor -e all,-mprotect

# Only monitor processes in /Applications
sudo ./ComprehensiveESMonitor -p /Applications
```

## Event Types

The monitor supports numerous event types, including:

- **Process Events**: exec, fork, exit
- **File Operations**: open, close, read, write, unlink
- **Directory Operations**: chdir, readdir
- **Memory Operations**: mmap, mprotect
- **Network Operations**: connect, bind
- **Permission Events**: chown, chmod

## Security Implications

Using this tool requires careful consideration:

1. **Entitlement Requirements**: Apple restricts the EndpointSecurity entitlement to approved developers
2. **System Integrity**: Running without proper entitlements requires disabling SIP, which reduces system security
3. **Performance Impact**: Monitoring all events can impact system performance

## Integration with Security Platforms

This tool can serve as a foundation for XDR/EDR platforms by:

1. **Data Collection**: Providing rich telemetry for security analysis
2. **Behavior Analysis**: Enabling detection of suspicious activities
3. **Forensic Capabilities**: Supporting incident response with detailed event logs

## License

This project is available under the MIT License. See the LICENSE file for more information.

## Acknowledgments

- Inspired by George Yunaev's Process Tracer for macOS
- Based on Apple's EndpointSecurity framework documentation
- References Brandon Dalton's AtomicESClient example
