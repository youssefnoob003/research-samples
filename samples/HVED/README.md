# HackSys Extreme Vulnerable Driver (HEVD) Exploits

## Disclaimer

**Educational and Research Purposes Only**
This repository contains proof-of-concept (PoC) exploits for the HackSys Extreme Vulnerable Driver (HEVD). The material is provided strictly for educational purposes, security analysis, and defensive engineering. Unauthorized use against systems without explicit permission is illegal. See the [main repository disclaimer](../../README.md) for full legal information.

---

## Technical Overview

This repository demonstrates a progression of kernel-mode exploitation techniques targeting the HackSys Extreme Vulnerable Driver (HEVD). It covers a range of vulnerabilities, from classic Stack Buffer Overflows to more advanced Arbitrary Write and Data-Only attacks using Heap Grooming. 

These PoCs target modern Windows environments and implement techniques to bypass modern mitigations such as Supervisor Mode Execution Prevention (SMEP) and Kernel Address Space Layout Randomization (KASLR) (though K_BASE is hardcoded for demonstration).

### Key Capabilities

- **Stack Buffer Overflow**: Overwrites the return address on the kernel stack to execute a Return-Oriented Programming (ROP) chain, disabling SMEP and jumping to user-mode shellcode.
- **Arbitrary Write (Write-What-Where)**: Exploits an arbitrary memory overwrite to hijack the `HalDispatchTable`. Demonstrates executing a stack pivot into a crafted 32-bit ROP chain to disable hardware protections and escalate privileges.
- **Heap Grooming and Data-Only Attacks**: Exploits an Out-of-Bounds Read in the Non-Paged Pool. Uses Heap Grooming (Named Pipes spraying and hole punching) to deterministically leak the address of `_EPROCESS` structures. Escalates privileges entirely through data manipulation without hijacking the kernel execution flow.

## Repository Structure

| Path | Description |
|------|-------------|
| `exp.c` | Exploit for the Stack Buffer Overflow vulnerability. |
| `arb.c` | Exploit for the Arbitrary Write (Write-What-Where) vulnerability. |
| `dataonly.c` | Exploit demonstrating Heap Grooming and an Arbitrary Read to achieve a Data-Only privilege escalation. |
| `MALWARE_DOCUMENTATION.md` | Detailed technical documentation and walkthroughs of the exploitation methodologies. |

## Target Environment

| Environment | OS Version | Notes |
|-------------|------------|-------|
| Target | Windows 11 (26200.8328) | Target environment must run HEVD. Hardcoded offsets (e.g., K_BASE) must be updated per execution. |
| Development | Windows 10 | Visual Studio 2022, Windows SDK. |

## Execution

### 1. Driver Deployment

Ensure HEVD is loaded and running on the target machine.

### 2. Execution Options

Compile the exploits using Visual Studio. 

```cmd
# Execute Stack Buffer Overflow
exp.exe

# Execute Arbitrary Write
arb.exe

# Execute Data-Only Exploit
dataonly.exe
```

For advanced technical details regarding the exploit chains and driver internals, consult [MALWARE_DOCUMENTATION.md](MALWARE_DOCUMENTATION.md).
