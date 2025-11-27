// Meterpreter Detection Test YARA Rules
//
// These rules detect meterpreter signatures in memory dumps
// captured by realtime_memdump_tool
//

rule Meterpreter_Stage_Marker {
    meta:
        description = "Detects Linux meterpreter stage marker strings"
        author = "LinProcMon Test Suite"
        date = "2025-11-26"
        
    strings:
        $linux1 = "linux/x64/meterpreter" nocase
        $linux2 = "linux/x86/meterpreter" nocase
        $core = "core_loadlib" nocase
        $socket = "socket_connect" nocase
        $meterpreter = "meterpreter_x64_linux" nocase
        
    condition:
        any of them
}

rule Meterpreter_Configuration {
    meta:
        description = "Detects meterpreter configuration strings"
        author = "LinProcMon Test Suite"
        date = "2025-11-26"
        
    strings:
        $payload_type = "windows/meterpreter/reverse_tcp" nocase
        $payload_marker = "METERPRETER_PAYLOAD_MARKER" nocase
        $lhost = /LHOST[:=]\s*[\d\.]+/ nocase
        $lport = /LPORT[:=]\s*\d+/ nocase
        $stage_url = /https?:\/\/[^\x00\s]+\/stage/ nocase
        
    condition:
        any of them
}

rule Meterpreter_MSSF_Header {
    meta:
        description = "Detects Metasploit Stream Socket Format (MSSF) header"
        author = "LinProcMon Test Suite"
        date = "2025-11-26"
        
    strings:
        $mssf = { 4D 53 53 46 }  // MSSF magic bytes
        
    condition:
        $mssf
}

rule Meterpreter_Network_Config {
    meta:
        description = "Detects meterpreter network configuration patterns"
        author = "LinProcMon Test Suite"
        date = "2025-11-26"
        
    strings:
        // IPv4 address patterns
        $ip1 = { 7F 00 00 01 }        // 127.0.0.1
        $ip2 = { C0 A8 01 ?? }        // 192.168.1.x
        
        // Common meterpreter ports in network byte order
        $port1 = { 11 5C }            // 4444
        $port2 = { 17 70 }            // 6000
        
    condition:
        ($ip1 or $ip2) and ($port1 or $port2)
}

rule Shellcode_Generic_Execve {
    meta:
        description = "Detects generic x64 execve shellcode patterns"
        author = "LinProcMon Test Suite"
        date = "2025-11-26"
        
    strings:
        // xor rdx, rdx
        $xor_rdx = { 48 31 D2 }
        
        // mov al, 59 (execve syscall)
        $execve_syscall = { B0 3B }
        
        // syscall instruction
        $syscall = { 0F 05 }
        
        // /bin/sh string (various encodings)
        $binsh1 = "/bin/sh" nocase
        $binsh2 = { 2F 62 69 6E 2F 73 68 }
        
    condition:
        ($xor_rdx and $execve_syscall and $syscall) or any of ($binsh*)
}

rule RWX_Suspicious_Pattern {
    meta:
        description = "Detects suspicious patterns in RWX memory regions"
        author = "LinProcMon Test Suite"
        date = "2025-11-26"
        
    strings:
        // Function prologue patterns
        $prologue1 = { 55 48 89 E5 }     // push rbp; mov rbp, rsp
        $prologue2 = { 48 83 EC ?? }     // sub rsp, imm8
        
        // Call instructions to suspicious locations
        $call_relative = { E8 ?? ?? ?? ?? }
        
        // Jump instructions
        $jmp_relative = { E9 ?? ?? ?? ?? }
        
        // Meterpreter-specific patterns (Linux)
        $meterpreter = "meterpreter" nocase
        $metasploit = "metasploit" nocase
        $core_loadlib = "core_loadlib" nocase
        
    condition:
        2 of ($prologue*, $call*, $jmp*) or any of ($meterpreter, $metasploit, $core_loadlib)
}

rule LD_PRELOAD_Indicators {
    meta:
        description = "Detects indicators of LD_PRELOAD hijacking"
        author = "LinProcMon Test Suite"
        date = "2025-11-26"
        
    strings:
        $ld_preload = "LD_PRELOAD" nocase
        $ld_library = "LD_LIBRARY_PATH" nocase
        $constructor = "__attribute__((constructor))" nocase
        $init_array = ".init_array" nocase
        $malicious_lib = "malicious_preload.so" nocase
        
    condition:
        any of them
}

rule Memory_Injection_Indicators {
    meta:
        description = "Detects common memory injection patterns"
        author = "LinProcMon Test Suite"
        date = "2025-11-26"
        
    strings:
        // mmap/mprotect strings
        $mmap = "mmap" nocase
        $mprotect = "mprotect" nocase
        $memfd = "memfd_create" nocase
        
        // Suspicious patterns
        $rwx = "rwx" nocase
        $executable_heap = "executable heap" nocase
        $anonymous_mapping = "anonymous executable" nocase
        
    condition:
        any of them
}
