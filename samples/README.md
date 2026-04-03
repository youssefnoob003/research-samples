# Malware Samples Catalog

This directory contains documented malware samples for educational and research purposes. Each project includes complete source code, documentation, and analysis.

## REMEMBER: Educational Use Only

Before proceeding, ensure you have read and understood the [main repository disclaimer](../README.md).

---

## Available Samples

### 1. Wallpaper C2 Malware

**Category**: Command & Control (C2) Infrastructure  
**Techniques**: Steganography, Reflective DLL Loading, HTTP C2, XOR Obfuscation  
**Language**: C, Python  
**Complexity**: Medium

#### Overview
A sophisticated C2 malware that disguises itself as an innocent wallpaper cycling application. The payload DLL is split across multiple BMP images using XOR encryption, extracted at runtime using reflective loading, and communicates with a Flask-based C2 server via HTTP.

#### Key Techniques Demonstrated
- **Steganography**: Payload embedded in RGB channels of BMP images
- **Reflective DLL Loading**: In-memory DLL loading without touching disk
- **XOR Stream Splitting**: Payload split across multiple network requests
- **HTTP C2 Communication**: Beaconing and command delivery via HTTP
- **Dynamic Key Generation**: Session keys based on system tick count
- **Evasion**: Appears as legitimate wallpaper application

#### MITRE ATT&CK Mapping
- T1027.009 - Obfuscated Files or Information: Steganography
- T1055.001 - Process Injection: Dynamic-link Library Injection
- T1071.001 - Application Layer Protocol: Web Protocols
- T1573 - Encrypted Channel
- T1620 - Reflective Code Loading

#### Components
- `mal.c` - Main executable with reflective loader
- `payload.c` - DLL with beacon generation and shellcode execution
- `serv.py` - Flask-based C2 server
- `embed.py` - Tool to embed DLL into BMP images
- `Defaults/` - Sample BMP images for wallpaper cycling, the three BMPs already contain the injected DLL.

#### Educational Value
- Understanding modern C2 infrastructure
- Learning steganography techniques
- Studying reflective loading mechanisms
- Analyzing obfuscation through XOR operations
- Defensive strategies for detecting similar threats

**[→ View Full Documentation](wallpaper-c2/README.md)**

---

### 2. CVE-2025-8061 BYOVD Exploit Chain

**Category**: Kernel Exploitation / Privilege Escalation  
**Techniques**: BYOVD, kASLR Defeat, SMEP/SMAP Bypass, Token Theft, DSE Bypass, DKOM  
**Language**: C++, MASM  
**Complexity**: High

#### Overview
A complete kernel exploitation chain targeting Windows 11 24H2 via CVE-2025-8061, a vulnerability in Lenovo's MSR I/O driver (`LnvMSRIO.sys`). The driver exposes physical memory and MSR read/write primitives to any unprivileged usermode process without authentication. Demonstrates the full BYOVD (Bring Your Own Vulnerable Driver) attack pattern.

#### Key Techniques Demonstrated
- **kASLR Defeat**: Kernel base leaked via LSTAR MSR read
- **SMEP/SMAP Bypass**: ROP chain clears CR4 bits before shellcode execution
- **Token Theft**: Ring 0 shellcode walks ActiveProcessLinks to steal System token
- **DSE Bypass**: Dynamic g_CiOptions patching via signature scanning
- **DKOM Rootkit**: Process hiding by unlinking from kernel process list

#### MITRE ATT&CK Mapping
- T1068 - Exploitation for Privilege Escalation
- T1014 - Rootkit
- T1211 - Exploitation for Defense Evasion
- T1553.006 - Code Signing Policy Modification
- T1569.002 - Service Execution

#### Components
- `phyread.cpp` / `phywrite.cpp` - Physical memory read/write primitives
- `readmsr.cpp` / `writemsr.cpp` - MSR read/write + kASLR defeat
- `privescshell.cpp` - Token theft exploit for SYSTEM shell
- `fulldsechain.cpp` - Complete chain: token theft + DSE bypass + driver load
- `PrepareStack.asm` - MASM stub for syscall hijack
- `rootkit.cpp` - DKOM kernel driver for process hiding

#### Educational Value
- Understanding BYOVD attack patterns with signed vulnerable drivers
- Learning kASLR, SMEP, SMAP, and DSE bypass mechanics
- Kernel shellcode development and ROP techniques
- Windows process model and DKOM fundamentals
- Why HVCI/VBS is critical for modern Windows security

**[→ View Full Documentation](CVE-2025-8061/README.md)**

---

## Adding New Samples

When contributing new malware samples, please ensure:

1. **Complete Documentation**: Include technical analysis and educational context
2. **Source Code**: Provide well-commented source code
3. **MITRE ATT&CK Mapping**: Map techniques to the ATT&CK framework
4. **Detection Signatures**: Include indicators for defensive purposes
5. **Ethical Guidelines**: Add appropriate disclaimers and usage warnings

---

## Further Reading

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Malware Analysis Resources](https://github.com/rshipp/awesome-malware-analysis)
- [Reverse Engineering References](https://github.com/wtsxDev/reverse-engineering)
