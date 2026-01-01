# ⛔ EDUCATIONAL KEYLOGGER ANALYSIS PROJECT

<div align="center">

## ⚠️ CRITICAL LEGAL & ETHICAL WARNING ⚠️

</div>

---

> ### 🚫 THIS SOFTWARE IS INTENTIONALLY NON-FUNCTIONAL
> 
> **This repository has been deliberately de-weaponized.**  
> It cannot be used maliciously without significant, intentional modification.

---

## 🔒 Legal Disclaimer

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║  ⚠️  YALNIZCA EĞİTİM VE GÜVENLİK ARAŞTIRMASI AMAÇLIDIR  ⚠️                   ║
║  ⚠️  FOR EDUCATIONAL AND SECURITY RESEARCH PURPOSES ONLY  ⚠️                 ║
║                                                                               ║
║  Bu yazılımın yetkisiz kullanımı YASA DIŞIDIR.                                ║
║  Unauthorized use of this software is ILLEGAL.                                ║
║                                                                               ║
║  Türk Ceza Kanunu Madde 243-245: Bilişim sistemlerine girme,                  ║
║  verileri ele geçirme veya bozma suçları 1-8 yıl hapis cezası gerektirir.     ║
║                                                                               ║
║  US Computer Fraud and Abuse Act (18 U.S.C. § 1030):                          ║
║  Unauthorized access carries penalties up to 20 years imprisonment.           ║
║                                                                               ║
║  GDPR Article 83: Data protection violations up to €20M or 4% revenue.        ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

## 🎯 Purpose of This Repository

This repository exists **ONLY** for:

| ✅ Allowed | ❌ NOT Allowed |
|-----------|---------------|
| Academic study of malware techniques | Any real-world deployment |
| Security researcher education | Testing on systems you don't own |
| Defensive security awareness | Any form of data collection |
| Understanding attacker methodologies | Personal use or distribution |
| Controlled lab environment analysis | Bypassing security controls |

---

## 🚫 What This Project Does NOT Do

This repository has been **intentionally crippled** to prevent misuse:

| Feature | Status | Why |
|---------|--------|-----|
| **Keystroke Logging** | ❌ DISABLED | `FEATURE_KEYLOGGER = 0` |
| **Screenshot Capture** | ❌ DISABLED | `FEATURE_SCREENSHOT = 0` |
| **Clipboard Monitoring** | ❌ DISABLED | `FEATURE_CLIPBOARD = 0` |
| **Network Communication** | ❌ DISABLED | `NETWORK_DISABLED = 1` |
| **Telegram C2** | ❌ DISABLED | No credentials, network off |
| **Persistence** | ❌ DISABLED | `PERSISTENCE_DISABLED = 1` |
| **Data Stealing** | ❌ DISABLED | `FEATURE_STEALERS = 0` |
| **Evasion Techniques** | ❌ DISABLED | `FEATURE_EVASION = 0` |
| **Auto-start** | ❌ DISABLED | No persistence mechanisms |

---

## 📦 Intentional Omissions

This repository is **deliberately incomplete**:

### ❌ No Binaries Provided
- No `.exe` files are included
- No pre-compiled releases
- No downloadable artifacts

### ❌ No Automatic Build System
- No `build.bat` or build scripts
- No CI/CD pipelines
- No Makefile with default targets
- Manual compilation requires intentional steps

### ❌ No Working Configuration
- `.env` file not included (only example)
- All features disabled by default
- Compilation blocked by `#error` directive

### ❌ No Network Capability
- All network functions return `false`
- No external connections possible
- Telegram API calls are no-ops

### ❌ No Persistence Capability
- All persistence functions return `false`
- No registry modifications
- No scheduled tasks
- No startup entries

---

## 🔐 Technical Safeguards

### 1. Compilation Guard
```cpp
#define EDUCATIONAL_ACKNOWLEDGED 0

#if !EDUCATIONAL_ACKNOWLEDGED
#error "COMPILATION BLOCKED: Set EDUCATIONAL_ACKNOWLEDGED to 1"
#endif
```
**Compilation will FAIL by default.**

### 2. Feature Flags (All Disabled)
```cpp
#define FEATURE_KEYLOGGER        0  // DISABLED
#define FEATURE_CLIPBOARD        0  // DISABLED
#define FEATURE_SCREENSHOT       0  // DISABLED
#define FEATURE_REMOTE_COMMANDS  0  // DISABLED
#define FEATURE_STEALERS         0  // DISABLED
#define FEATURE_PERSISTENCE      0  // DISABLED ⚠️ NEVER ENABLE
#define FEATURE_EVASION          0  // DISABLED
```

### 3. Network Guard
```cpp
#define NETWORK_DISABLED 1

bool Initialize() {
    #if NETWORK_DISABLED
    return false;  // No connection ever made
    #endif
}
```

### 4. Persistence Guard
```cpp
#define PERSISTENCE_DISABLED 1

bool InstallCOMHijack() {
    #if PERSISTENCE_DISABLED
    return false;  // Does nothing
    #endif
}
```

---

## 📚 Educational Value

This codebase demonstrates (for **defensive** understanding):

| Technique | Header File | Educational Purpose |
|-----------|-------------|---------------------|
| ETW/AMSI Bypass | `evasion.h` | Understand EDR evasion |
| Dynamic Syscalls | `syscalls.h` | Learn Hell's Gate technique |
| Ntdll Unhooking | `unhook.h` | Understand hook detection |
| COM Hijacking | `persistence.h` | Learn persistence methods |
| WMI Subscription | `persistence.h` | Event-driven persistence |
| Steganography | `stego.h` | Data hiding techniques |
| Process Hollowing | `process.h` | Memory injection methods |

**Use this knowledge to BUILD BETTER DEFENSES, not attacks.**

---

## ⚠️ Before You Consider Enabling Anything

Ask yourself:

1. ❓ Do I have **written authorization** from the system owner?
2. ❓ Am I in a **completely isolated lab environment**?
3. ❓ Am I prepared for **legal consequences** if something goes wrong?
4. ❓ Is my purpose purely **educational/defensive**?
5. ❓ Have I read and understood **all relevant laws**?

**If ANY answer is "no" or "unsure" → DO NOT PROCEED**

---

## 🏛️ Legal References

- **Turkey:** TCK 243-245 (Bilişim Suçları)
- **USA:** Computer Fraud and Abuse Act (CFAA)
- **EU:** GDPR, NIS Directive
- **UK:** Computer Misuse Act 1990
- **Global:** Budapest Convention on Cybercrime

---

## 📋 File Structure (Reference Only)

```
keylogger/
├── keylogger.cpp      # Main source (analysis only)
├── config.h           # Feature configuration (all disabled)
├── network.h          # Network manager (DISABLED)
├── persistence.h      # Persistence mechanisms (ALL DISABLED)
├── evasion.h          # Evasion techniques (for study)
├── syscalls.h         # Dynamic syscalls (for study)
├── stealers.h         # Data stealers (disabled)
├── .env.example       # Example config (placeholder values)
├── antidote.cpp       # Cleanup tool source
└── README.md          # This file
```

---

## 🔴 Final Warning

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║  Bu projeyi kötüye kullanmak SUÇTUR ve ciddi yasal sonuçlar doğurur.          ║
║  Misusing this project is a CRIME and carries serious legal consequences.    ║
║                                                                               ║
║  Bilgi güvenliği profesyonellerinin görevi SİSTEMLERİ KORUMAKTIR,             ║
║  onlara saldırmak değil.                                                      ║
║                                                                               ║
║  The job of security professionals is to PROTECT systems, not attack them.   ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

**For educational inquiries only.**

*This repository intentionally lacks functionality to prevent misuse.*