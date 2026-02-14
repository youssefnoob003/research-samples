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

## Adding New Samples

When contributing new malware samples, please ensure:

1. **Complete Documentation**: Include technical analysis and educational context
2. **Source Code**: Provide well-commented source code
3. **MITRE ATT&CK Mapping**: Map techniques to the ATT&CK framework
4. **Detection Signatures**: Include indicators for defensive purposes
5. **Ethical Guidelines**: Add appropriate disclaimers and usage warnings

---

## Learning Path

For those new to malware analysis, we recommend studying samples in this order:

1. **Wallpaper C2** - Comprehensive example covering multiple techniques

*(More samples will be added as the repository grows)*

---

## Further Reading

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Malware Analysis Resources](https://github.com/rshipp/awesome-malware-analysis)
- [Reverse Engineering References](https://github.com/wtsxDev/reverse-engineering)
