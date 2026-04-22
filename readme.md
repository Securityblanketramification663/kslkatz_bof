# KslBOF — BYOVD BOF Suite for Havoc C2

> **For authorized Red Team engagements and controlled lab environments only.**  
> Do not use against systems you do not own or have explicit written permission to test.

---

## Overview

KslBOF is a Beacon Object File (BOF) for the [Havoc C2](https://github.com/HavocFramework/Havoc) framework implementing the **KslD.sys BYOVD physical memory read primitive** for credential extraction.

This is a port of the KslD.sys technique to Havoc BOF format, based on [KslKatz](https://github.com/ne1llee/xxx) and related public research. The original technique uses KslD.sys — a Microsoft-signed kernel driver shipped with Windows Defender — to read lsass memory without opening a handle to the process.

---

## What makes this different

Existing implementations of the KslD.sys technique are standalone executables. KslBOF implements the same primitive as a **Beacon Object File**:

- Runs entirely in-process within the beacon — no new process spawned
- No files dropped to disk beyond the driver already present on the system
- Integrates natively with Havoc C2 tasking and output

---

## Driver Version — Vulnerable vs Patched

Microsoft patched the running version of KslD.sys by nulling out `MmCopyMemory`, but **left the old vulnerable version on disk**. Two versions coexist on most systems:

| Path | Size | Status |
|------|------|--------|
| `%SystemRoot%\System32\drivers\KslD.sys` | 333,216 bytes | **Vulnerable** |
| `%ProgramData%\Microsoft\Windows Defender\Platform\<version>\wd\KslD.sys` | ~82 KB | Patched |

The suite uses the vulnerable version from `System32\drivers\` by swapping the SCM `ImagePath` before loading.

**Verify the vulnerable version is present:**

```powershell
Get-Item "$env:SystemRoot\System32\drivers\KslD.sys" | Select-Object Name, Length
Get-FileHash "$env:SystemRoot\System32\drivers\KslD.sys" -Algorithm SHA256
```

**Expected output:**
```
Name       Length
----       ------
KslD.sys   333216

Algorithm  Hash
---------  ----
SHA256     BD17231833AA369B3B2B6963899BF05DBEFD673DB270AEC15446F2FAB4A17B5A
```

> **Note:** Windows Servicing may eventually supersede the vulnerable CBS-backed copy. As of early 2026 the vulnerable version remains present on most systems with Defender installed.

---

## Why No CVE

The KslD.sys vulnerability was reported to Microsoft MSRC and closed as **"Not a Vulnerability"** — the attack requires pre-existing administrative privileges. No CVE was assigned, no fix was issued, the driver remains on disk.

The value of this technique is **stealth**, not privilege escalation. EDRs monitor `OpenProcess`, `NtReadVirtualMemory`, and `MiniDumpWriteDump` on lsass. None of those are called here.

---

## BOF Module

### `ksl_lsa.o` — Credential Extraction

Port of the KslD.sys credential extraction technique to Havoc BOF format.

Extracts credentials from lsass memory without calling `OpenProcess` on lsass or using any standard dumping API. No handle to lsass, no `NtReadVirtualMemory`, no `MiniDumpWriteDump`.

**What it extracts:**
- MSV1_0 NT hashes (build-aware offsets)
- WDigest cleartext passwords (when enabled, multi-signature support for Win11 24H2)
- AES-256 / 3DES LSA encryption keys
- Credential Guard detection (`isIso` flag)

**Supported builds:** Windows 7/8/10/11 (including 24H2 Build 26200+), Server 2016–2022

**PrimaryCredential offsets:**
```
Win11 24H2 (>= 26100): isIso=0x28  NT=0x46  LM=0x56  SHA1=0x66
Win11       (>= 22000): isIso=0x40  NT=0x46  LM=0x56  SHA1=0x66
Win10       (>= 9600):  isIso=0x28  NT=0x4a  LM=0x5a  SHA1=0x36
Win7/8      (<  9600):  isIso=0x28  NT=0x38  LM=0x48  SHA1=0x18
```

**Usage:**
```
inline-execute /path/to/out/ksl_lsa.o
```
<img width="530" height="626" alt="image" src="https://github.com/user-attachments/assets/6d3d9f9f-b93c-4d1d-b482-3b1eedc2811b" />

---

## Credential Guard

When Credential Guard (VBS) is active, domain credentials are isolated in a Hyper-V enclave inaccessible via physical memory primitives. The module detects this condition (`isIso=1`) and reports it.

**What CG protects:** Domain NTLM hashes, Kerberos TGTs, interactive domain session credentials.  
**What CG does NOT protect:** Local accounts, LSA Secrets, service account credentials.

---

## Technical Architecture

### KASLR Defeat
```
SubCmd 2 → IDTR → IDT → minimum ISR → scan backwards → ntoskrnl base
Fallback: NtQuerySystemInformation(SystemModuleInformation)
```

### EPROCESS Discovery
```
OpenProcess(PID 4) → NtQuerySystemInformation(class 16)
                   → handle table → SYSTEM EPROCESS
                   → ActiveProcessLinks walk → lsass
                   → DTB from EPROCESS+0x028
                   → UserDTB from EPROCESS+0x388 (KPTI, Win10 1809+)
```

All EPROCESS offsets detected dynamically — no hardcoded values.

### Physical Memory Read Limit

KslD.sys has an internal physical memory read limit of approximately **4GB physical address**. On systems with more RAM, userland process DTBs typically exceed this limit. Kernel VA reads via `virt_read` are unaffected — `ksl_lsa.o` works regardless of system RAM as it operates via kernel VA.

---

## Build

**Requirements:** `x86_64-w64-mingw32-gcc`

```bash
make clean && make ksl_lsa
```

---

## Repository Structure

```
KslBOF/
├── include/
│   ├── beacon.h
│   └── common_bof.h
├── src/
│   ├── bof_crt.c
│   ├── ksl_driver_bof.c
│   ├── ksl_memory_bof.c
│   ├── ksl_crypto_bof.c
│   ├── ksl_lsa_bof.c
│   ├── ksl_lsa_go.c
│   ├── ksl_wdigest_bof.c
│   └── ksl_all_in_one_lsa.c
├── out/
│   └── ksl_lsa.o
└── Makefile
```

---

## Roadmap

- `ksl_edr.o` — EDR process recon + inline hook scanner — *in testing*
- `ksl_ssdt.o` — SSDT kernel hook scanner — *in testing*

---

## Detection Considerations

- Alert on KslD service start outside Defender update context
- Monitor `AllowedProcessName` modifications under `HKLM\SYSTEM\CurrentControlSet\Services\KslD`
- No `OpenProcess` events on lsass are generated — detection must focus on driver load
- Credential Guard active prevents domain credential extraction

---

## Credits

Port to Havoc BOF format based on public research:

- **KslKatz** — [yenick514/KslKatz](https://github.com/yenick514/KslKatz)

If you are aware of earlier or additional research that should be credited here, please open an issue.

**References:**
- [Microsoft Vulnerable Driver Blocklist](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)
- [LOLDrivers](https://www.loldrivers.io/)
- [BYOVD Attacks and Mitigation — Halcyon](https://www.halcyon.ai/blog/understanding-byovd-attacks-and-mitigation-strategies)
- [Proactive Measures Against Vulnerable Driver Attacks — Microsoft TechCommunity](https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/strategies-to-monitor-and-prevent-vulnerable-driver-attacks/4103985)

---

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. Use only on systems you own or have explicit written permission to test.
