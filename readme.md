# KslAll — BYOVD BOF Suite for Havoc C2

> **For authorized Red Team engagements and controlled lab environments only.**  
> Do not use against systems you do not own or have explicit written permission to test.

---

## Overview

KslAll is a suite of Beacon Object Files (BOFs) for the [Havoc C2](https://github.com/HavocFramework/Havoc) framework built around a single kernel primitive: **arbitrary physical memory read via KslD.sys**, a Microsoft-signed kernel driver shipped with Windows Defender.

The technique was originally researched and documented by **Andrea Bocchetti** ([KslDump](https://github.com/andreisss/KslDump)) and further developed by **ne1llee** ([KslKatz](https://github.com/ne1llee/xxx)). This project adapts and extends that research into a modular BOF suite for offensive operations.

---

## Why KslD.sys

KslD.sys is a kernel driver included with Microsoft Defender. It exposes an IOCTL interface (`0x222044`) that provides physical memory read access from userland. The driver is:

- **Microsoft-signed** — trusted by Windows Driver Signature Enforcement
- **Already present on disk** — ships with Defender, no files to drop
- **Excluded from the HVCI blocklist by design** — Microsoft's own drivers cannot be on their own blocklist
- **Not assigned a CVE** — Microsoft MSRC closed the report as "Not a Vulnerability" since it requires pre-existing admin privileges

The only gate to the device is an `AllowedProcessName` registry value under the driver's service key — trivially bypassed by writing our own process path before loading the driver.

---

## BOF Modules

### `ksl_lsa.o` — Credential Extraction
**Requires driver:** Yes  
**Works on:** Any system regardless of RAM  

Extracts credentials from lsass memory without calling `OpenProcess` on lsass or using any standard dumping API. No handle to lsass, no `NtReadVirtualMemory`, no `MiniDumpWriteDump`.

**Extracts:**
- MSV1_0 NT hashes (build-aware offsets for Win7–Win11)
- WDigest cleartext passwords (when enabled)
- AES-256 / 3DES LSA encryption keys
- Credential Guard detection (`isIso` flag)

**Supported builds:** Windows 7/8/10/11, Server 2016–2022

**Usage:**
```
inline-execute /path/to/out/ksl_lsa.o
```

---

### `ksl_edr.o` — EDR Reconnaissance + Hook Scanner
**Requires driver:** Yes  
**Works on:** Systems where EDR process DTB < ~4GB physical  

Three phases:

1. **EDR Process Discovery** — walks EPROCESS list locating known EDR processes (CrowdStrike, SentinelOne, Cortex XDR, Defender, Carbon Black, Tanium, and more)
2. **Injected DLL Detection** — reads the EDR process module list for known in-process monitoring DLLs
3. **Inline Hook Scanner** — scans `ntdll.dll`, `win32u.dll`, `kernel32.dll`, `kernelbase.dll` for hooked functions

Hook patterns detected: `JMP rel32`, `JMP [rip+x]`, `INT3`, `REX JMP` (SentinelOne hotpatch style), `MOV rax,imm64` trampolines.

False positives filtered: Windows hotpatch trampolines, KUSER_SHARED_DATA fast paths, ntdll forwarders to user32, GS-segment TEB accessors.

**Expected output by EDR:**
```
Defender/MDE  → 0 hooks (uses ETW + kernel callbacks, not userland hooks)
CrowdStrike   → ~15-20 hooks in ntdll
SentinelOne   → hooks in ntdll + win32u
Cortex XDR    → hooks in ntdll + kernel32 + kernelbase
```

**Usage:**
```
inline-execute /path/to/out/ksl_edr.o
```

---

### `ksl_ssdt.o` — SSDT Kernel Hook Scanner
**Requires driver:** Yes  
**Works on:** Any system regardless of RAM  

Scans the System Service Descriptor Table (SSDT) for handlers pointing outside ntoskrnl address range. A handler outside ntoskrnl means a driver is intercepting that syscall at kernel level.

Finds `KeServiceDescriptorTable` via pattern matching on `KiSystemCall64` — a public export that contains LEA RIP-relative instructions referencing the KSDT. No PDB symbols required.

**Primary use case:** Sandbox detection. Modern EDRs on Win10/11 do not hook the SSDT (PatchGuard prevents it). SSDT hooks on Win10/11 indicate sandbox infrastructure or legacy AV.

**Usage:**
```
inline-execute /path/to/out/ksl_ssdt.o
```

---

## Driver Version — Vulnerable vs Patched

Microsoft patched the running version of KslD.sys by nulling out the `MmCopyMemory` functionality, but **left the old vulnerable version sitting on disk**. Two versions coexist on most systems:

| Path | Size | Status |
|------|------|--------|
| `%SystemRoot%\System32\drivers\KslD.sys` | 333,216 bytes | **Vulnerable** — CBS-backed component store copy |
| `%ProgramData%\Microsoft\Windows Defender\Platform\<version>\wd\KslD.sys` | ~82 KB | Patched — `MmCopyMemory` nulled out |

The suite uses the vulnerable version from `System32\drivers\` by swapping the SCM `ImagePath` to point to it.

**Verify the vulnerable version is present:**

```powershell
# Check file exists and size matches
Get-Item "$env:SystemRoot\System32\drivers\KslD.sys" |
    Select-Object Name, Length

# Verify SHA256 hash
Get-FileHash "$env:SystemRoot\System32\drivers\KslD.sys" -Algorithm SHA256
```

**Expected output for the vulnerable version:**
```
Name       Length
----       ------
KslD.sys   333216

Algorithm  Hash
---------  ----
SHA256     BD17231833AA369B3B2B6963899BF05DBEFD673DB270AEC15446F2FAB4A17B5A
```

If the hash does not match or the file is not present, the vulnerable version is not available on that system and the suite will not function.

**Note:** Windows Servicing may eventually supersede the vulnerable CBS-backed copy with a patched version via a future cumulative update. As of early 2026 the vulnerable version remains present on most systems with Defender installed.

---



### KASLR Defeat

```
SubCmd 2 → IDTR register
        → IDT parse → minimum ISR address
        → scan backwards in 4KB pages → MZ header
        → ntoskrnl base confirmed via PE header + export count
```

Fallback: `NtQuerySystemInformation(SystemModuleInformation)` — returns exact kernel module base without physical memory access.

### EPROCESS Discovery

```
OpenProcess(PID 4) → NtQuerySystemInformation(class 16)
                   → handle table entry → Object = SYSTEM EPROCESS
                   → ActiveProcessLinks walk → target process
                   → DTB from EPROCESS+0x028 (kernel)
                   → UserDTB from EPROCESS+0x388 (KPTI, Win10 1809+)
```

All EPROCESS offsets detected dynamically — no hardcoded values.

### Physical Memory Read

```
vtp(dtb, va):
  PML4[va[47:39]] → PDPT base
  PDPT[va[38:30]] → PD base (or 1GB large page)
  PD[va[29:21]]   → PT base (or 2MB large page)
  PT[va[20:12]]   → physical frame
  PA = frame | va[11:0]
```

### Known Limitation

KslD.sys has an internal physical memory read limit of approximately **4GB**. On systems with more than ~4GB of RAM, userland process DTBs are typically above this limit, making `proc_read` fail silently for those processes. Kernel VA reads via `virt_read` are not affected by this limitation.

**Impact:**
- `ksl_lsa.o` — not affected (operates via kernel VA)
- `ksl_ssdt.o` — not affected (operates via kernel VA)
- `ksl_edr.o` — affected on systems with >4GB RAM where EDR process DTB is above the limit

---

## Credential Guard

When Credential Guard (VBS) is active, domain credentials are isolated in a Hyper-V enclave. The modules detect this condition (`isIso=1` in MSV1_0 structures) and report it. Physical memory primitives cannot bypass Credential Guard — the enclave memory is not accessible via normal physical addresses.

**What CG protects:** Domain account NTLM hashes, Kerberos TGTs, interactive domain session credentials.  
**What CG does NOT protect:** Local accounts, LSA Secrets, service account credentials, access tokens.

---

## Build

**Requirements:** `x86_64-w64-mingw32-gcc`

```bash
# Build all modules
make clean && make all

# Build individual modules
make ksl_lsa
make ksl_edr
make ksl_ssdt

# Stack usage check
make stack-check
```

---

## Repository Structure

```
KslAll/
├── include/
│   ├── beacon.h                  ← Havoc BOF API
│   └── common_bof.h              ← shared types, DFR, ByteBuf, SeenSet
├── src/
│   ├── bof_crt.c                 ← memset/memcpy/memcmp/memmove
│   ├── ksl_driver_bof.c          ← driver lifecycle, IOCTL wrappers
│   ├── ksl_memory_bof.c          ← page table walk, KASLR, EPROCESS
│   ├── ksl_crypto_bof.c          ← AES-CFB128, 3DES-CBC via BCrypt
│   ├── ksl_lsa_bof.c             ← LSA keys, MSV1_0, credential decryption
│   ├── ksl_lsa_go.c              ← BOF entry point for ksl_lsa
│   ├── ksl_wdigest_bof.c         ← WDigest l_LogSessList walk
│   ├── ksl_edr_bof.c             ← EDR process recon, hook scanner
│   ├── ksl_edr_go.c              ← BOF entry point for ksl_edr
│   ├── ksl_ssdt_bof.c            ← SSDT scanner, KiSystemCall64 pattern
│   ├── ksl_ssdt_go.c             ← BOF entry point for ksl_ssdt
│   ├── ksl_all_in_one_lsa.c      ← single compilation unit for ksl_lsa
│   ├── ksl_all_in_one_edr.c      ← single compilation unit for ksl_edr
│   └── ksl_all_in_one_ssdt.c     ← single compilation unit for ksl_ssdt
├── out/
│   ├── ksl_lsa.o
│   ├── ksl_edr.o
│   └── ksl_ssdt.o
└── Makefile
```

---

## Operational Workflow

```
1. Gain admin local (phishing + credentials, or other vector)
        ↓
2. ksl_ssdt.o   → sandbox detection before aggressive actions
        ↓
3. ksl_edr.o    → identify EDR, map hooked syscalls
                  adapt TTPs accordingly
        ↓
4. ksl_lsa.o    → extract credentials without lsass handle
                  no OpenProcess, no auditable API on lsass
        ↓
5. Lateral movement with extracted credentials
```

---

## Detection Considerations

The highest-visibility action in this suite is **driver loading**. Defensive recommendations:

- Alert on KslD service start outside Defender update context
- Monitor `AllowedProcessName` registry value modifications under `HKLM\SYSTEM\CurrentControlSet\Services\KslD`
- Credential Guard active prevents domain credential extraction even with this primitive
- No `OpenProcess` events on lsass are generated — detection must focus on driver load, not process access

---

## Original Research & Credits

This project is built on top of research by:

- **Andrea Bocchetti** — original KslD.sys vulnerability discovery, IOCTL reverse engineering, and Python PoC  
  → [KslDump](https://github.com/andreisss/KslDump)

- **ne1llee** — KslKatz, combining KslDump with GhostKatz-style local signature scanning  
  → [KslKatz](https://github.com/ne1llee/xxx)

**Additional references:**

- [Microsoft Vulnerable Driver Blocklist](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)
- [BYOVD Attacks and Mitigation Strategies — Halcyon](https://www.halcyon.ai/blog/understanding-byovd-attacks-and-mitigation-strategies)
- [Proactive Measures Against Vulnerable Driver Attacks — Microsoft TechCommunity](https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/strategies-to-monitor-and-prevent-vulnerable-driver-attacks/4103985)
- [BYOVD to the next level — Quarkslab](https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html)
- [LOLDrivers — Living Off The Land Drivers](https://www.loldrivers.io/)

---

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. Use only on systems you own or have explicit written permission to test. The authors are not responsible for misuse or damage caused by this software.
