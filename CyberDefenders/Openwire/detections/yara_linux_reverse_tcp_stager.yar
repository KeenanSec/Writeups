/*
    YARA Rule: Linux x86-64 Minimalist Reverse TCP Shellcode Stager
    Target: Handcrafted 250-byte ELF reverse TCP stager with direct in-memory execution (mmap RWX -> jmp *rsi)
    Associated Investigation: CyberDefenders OpenWire (ActiveMQ CVE-2023-46604)
    Author: Keenan (KeenanSec)
    Date: 2026-10-23
*/

rule Linux_Stager_ReverseTCP_x64 {
    meta:
        description = "Detects minimalist handcrafted Linux x86-64 reverse TCP stager with direct in-memory execution"
        author = "Keenan (KeenanSec)"
        reference = "CyberDefenders OpenWire Analysis"
        threat_level = "High"
        mitre_technique = "T1059.004, T1055, T1036.005"
        date = "2026-10-23"

    strings:
        // sys_mmap (syscall 9) with PROT_READ|PROT_WRITE|PROT_EXEC (0x7) and MAP_ANONYMOUS|MAP_PRIVATE (0x22)
        // push 0x22; pop r10; push 0x7; pop rdx; syscall
        $mmap_rwx = { 6a 22 41 5a 6a 07 5a 0f 05 }

        // sys_socket (syscall 41 / 0x29, AF_INET=2, SOCK_STREAM=1)
        // push 0x29; pop rax; cltd; push 0x2; pop rdi; push 0x1; pop rsi; syscall
        $socket = { 6a 29 58 99 6a 02 5f 6a 01 5e 0f 05 }

        // sys_connect (syscall 42 / 0x2a)
        // push 0x10; pop rdx; push 0x2a; pop rax; syscall
        $connect = { 6a 10 5a 6a 2a 58 0f 05 }

        // sys_nanosleep retry loop (syscall 35 / 0x23, 5s delay)
        // push 0x23; pop rax; push 0x0; push 0x5; mov rsp, rdi; xor rsi, rsi; syscall
        $sleep_retry = { 6a 23 58 6a 00 6a 05 48 89 e7 48 31 f6 0f 05 }

        // sys_read into mmap buffer followed by jmp *%rsi execution
        // syscall; test rax, rax; js <retry>; jmp *rsi
        $exec_jump = { 0f 05 48 85 c0 78 ?? ff e6 }

    condition:
        uint32(0) == 0x464c457f and     // ELF magic (\x7fELF)
        filesize < 2KB and              // Minimalist standalone stager
        3 of ($mmap_rwx, $socket, $connect, $sleep_retry, $exec_jump)
}
