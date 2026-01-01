<div align="center">

[![⚠️ LEGAL DISCLAIMER ⚠️](https://img.shields.io/badge/⚠️_LEGAL_DISCLAIMER-MANDATED_TO_READ-red?style=for-the-badge&labelColor=darkred)](./LegalDisclaimer.md)

**[📜Read Legal Disclaimer before proceeding 📜](./LegalDisclaimer.md)**

</div>

---

# 🔐 Advanced C++ Keylogger

> ⚠️ **INTENTIONALLY NON-FUNCTIONAL**: This repository has been deliberately de-weaponized. All features are disabled by default, network functionality is blocked, and persistence mechanisms are removed. This project exists **ONLY** for educational code analysis and security research.

> ⚠️ **DISCLAIMER**: This software is intended for educational purposes and authorized penetration testing only. Unauthorized use of this software is illegal and unethical. Always obtain proper authorization before testing.

A sophisticated, feature-rich keylogger written in C++ with Telegram C2 (Command & Control) integration. Designed for educational purposes and authorized security testing only.

---

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Configuration & Build](#️-configuration--build-for-experts)
- [Telegram Commands](#-telegram-commands)
- [Architecture](#-architecture)
- [Evasion Techniques](#-evasion-techniques)
- [File Structure](#-file-structure)
- [Antidote (Removal Tool)](#-antidote-removal-tool)

---

## ✨ Features

> ⚠️ **Note**: All features below are **DISABLED by default**. This section documents the codebase capabilities for educational purposes only.

### Core Functionality
| Feature | Description | Default Status |
|---------|-------------|----------------|
| 🔤 **Keystroke Logging** | Captures all keystrokes with window context | ❌ Disabled |
| 📋 **Clipboard Monitoring** | Monitors clipboard changes in real-time | ❌ Disabled |
| 📸 **Screenshots** | Periodic and on-demand screen capture | ❌ Disabled |
| 🔌 **USB Monitoring** | Detects USB device insertions | ❌ Disabled |
| 📡 **Telegram C2** | Full remote control via Telegram bot | ❌ Disabled |

### Data Stealing Modules
| Module | Command | Description | Default Status |
|--------|---------|-------------|----------------|
| 📶 WiFi Passwords | `/wifi` | Extracts saved WiFi credentials | ❌ Disabled |
| 🔑 Browser Passwords | `/pass` | Chrome/Edge password extraction | ❌ Disabled |
| 💬 Discord Tokens | `/discord` | Discord authentication tokens | ❌ Disabled |
| 🍪 Browser Cookies | `/cookies` | Chrome cookie extraction | ❌ Disabled |
| 💰 Crypto Wallets | `/wallets` | Wallet file detection | ❌ Disabled |
| 📁 Sensitive Files | `/files` | Document exfiltration | ❌ Disabled |

### Evasion & Persistence
- 🛡️ ETW/AMSI Bypass (disabled)
- 🔄 Multiple persistence mechanisms - 7 methods (all disabled)
- 🕵️ Anti-debugging & anti-VM detection (disabled)
- 🌙 Sleep obfuscation (disabled)
- 🔧 Dynamic syscalls - Hell's Gate/Halo's Gate (disabled)
- 📝 Ntdll unhooking (disabled)

---

## 📦 Requirements

- **OS**: Windows 10/11 (x64)
- **Compiler**: MSYS2 with MinGW-w64 (g++)
- **Knowledge**: Advanced C++ and Windows internals understanding

### Installing MSYS2

1. Download from [msys2.org](https://www.msys2.org/)
2. Install and run MSYS2 UCRT64
3. Update packages:
   ```bash
   pacman -Syu
   pacman -S mingw-w64-ucrt-x86_64-gcc
   ```

---

## ⚙️ Configuration & Build (For Experts)

> ⚠️ **IMPORTANT**: This project is intentionally non-functional out of the box. The steps below are for security researchers who understand the code and accept full responsibility.

### Step 1: Acknowledge Educational Use

Edit `config.h` and change:
```cpp
#define EDUCATIONAL_ACKNOWLEDGED 0
```
to:
```cpp
#define EDUCATIONAL_ACKNOWLEDGED 1
```

Without this change, compilation will fail with an `#error` directive.

### Step 2: Enable Desired Features (Optional)

In `config.h`, features are disabled by default:
```cpp
#define FEATURE_KEYLOGGER        0  // Change to 1 to enable
#define FEATURE_CLIPBOARD        0  // Change to 1 to enable
#define FEATURE_SCREENSHOT       0  // Change to 1 to enable
#define FEATURE_USB_MONITOR      0  // Change to 1 to enable
#define FEATURE_REMOTE_COMMANDS  0  // Change to 1 to enable
#define FEATURE_STEALERS         0  // Change to 1 to enable
#define FEATURE_PERSISTENCE      0  // ⚠️ DO NOT ENABLE
#define FEATURE_EVASION          0  // Change to 1 to enable
```

### Step 3: Enable Network (If Needed)

Network is disabled by default in `network.h`:
```cpp
#define NETWORK_DISABLED 1
```

To enable (for authorized testing only), change to:
```cpp
#define NETWORK_DISABLED 0
```

### Step 4: Configure Telegram Credentials

Create a `.env` file (not provided for safety):
```env
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
```

### Step 5: Manual Build

No build scripts are provided. Compile manually:

```bash
# Set PATH to MSYS2
set PATH=C:\msys64\ucrt64\bin;%PATH%

# Compile with required libraries
g++ -std=c++17 keylogger.cpp -o keylogger.exe ^
    -mwindows -static -static-libgcc -static-libstdc++ ^
    -lwininet -lshell32 -luser32 -ladvapi32 ^
    -lgdi32 -lgdiplus -lole32 -loleaut32 ^
    -lwbemuuid -lstrmiids -lcrypt32 -ldnsapi ^
    -ldbghelp -liphlpapi -lnetapi32 ^
    -O2 -s ^
    -DTELEGRAM_BOT_TOKEN=\"YOUR_TOKEN\" ^
    -DTELEGRAM_CHAT_ID=\"YOUR_CHAT_ID\"
```

### Summary of Guards

| Guard | Location | Default | Effect |
|-------|----------|---------|--------|
| `EDUCATIONAL_ACKNOWLEDGED` | config.h | 0 | Blocks compilation |
| `FEATURE_*` | config.h | 0 | Disables all features |
| `NETWORK_DISABLED` | network.h | 1 | Blocks all network calls |
| `PERSISTENCE_DISABLED` | persistence.h | 1 | Blocks all persistence |

---

## 📱 Telegram Commands

> ⚠️ These commands only work if `FEATURE_REMOTE_COMMANDS=1` and `NETWORK_DISABLED=0`.

### System Commands
| Command | Description |
|---------|-------------|
| `/help` | Show all available commands |
| `/status` | Current bot status and uptime |
| `/info` | Detailed system information |
| `/dump` | Force send current logs |
| `/kill` | Terminate the keylogger |

### Screenshot & Media
| Command | Description |
|---------|-------------|
| `/ss` or `/screenshot` | Take screenshot |
| `/webcam` | Webcam status |

### Data Extraction
| Command | Description |
|---------|-------------|
| `/wifi` | WiFi passwords |
| `/pass` | Browser passwords |
| `/discord` | Discord tokens |
| `/cookies` | Browser cookies |
| `/wallets` | Crypto wallet files |
| `/files` | Sensitive documents |
| `/steal` | Run all stealers |

### Remote Control
| Command | Description |
|---------|-------------|
| `/cmd <command>` | Execute system command |
| `/download <url>` | Download and execute file |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    main()                           │
│  ┌───────────────────────────────────────────────┐  │
│  │ Evasion Init (ETW, AMSI, Anti-Debug)          │  │
│  └───────────────────────────────────────────────┘  │
│                      ↓                              │
│  ┌───────────────────────────────────────────────┐  │
│  │ Security Checks (VM, Sandbox, Debugger)       │  │
│  └───────────────────────────────────────────────┘  │
│                      ↓                              │
│  ┌───────────────────────────────────────────────┐  │
│  │ Persistence & Self-Hide                       │  │
│  └───────────────────────────────────────────────┘  │
│                      ↓                              │
│  ┌───────────────────────────────────────────────┐  │
│  │ Worker Threads                                │  │
│  │  ├── ReportLoop (Log sending)                 │  │
│  │  ├── ClipboardMonitorLoop                     │  │
│  │  ├── ScreenshotLoop                           │  │
│  │  ├── USBMonitorLoop                           │  │
│  │  └── RemoteCommandLoop (Telegram C2)          │  │
│  └───────────────────────────────────────────────┘  │
│                      ↓                              │
│  ┌───────────────────────────────────────────────┐  │
│  │ StartKeylogger (Hook or Polling)              │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## 🛡️ Evasion Techniques

> ⚠️ These techniques are documented for defensive understanding only.

### Layer 1: API Bypass
- **ETW Disable**: Patches `EtwEventWrite` in ntdll
- **AMSI Disable**: Patches `AmsiScanBuffer`

### Layer 2: Anti-Analysis
- **Debugger Detection**: Multiple methods (PEB, timing, hardware)
- **VM Detection**: Registry, MAC address, process checks
- **Sandbox Detection**: User interaction, uptime, resource checks

### Layer 3: Stealth
- **Sleep Obfuscation**: Encrypted sleep with fake wait objects
- **Dynamic Syscalls**: Hell's Gate for direct NT calls
- **Ntdll Unhooking**: Fresh copy from disk/KnownDlls

### Layer 4: Persistence (All Disabled)
1. Registry Run keys
2. Scheduled Tasks
3. Startup folder shortcuts
4. COM Hijacking
5. WMI Event Subscription
6. Fileless (Registry + PowerShell)
7. Watchdog process

---

## 📁 File Structure

```
keylogger/
├── keylogger.cpp       # Main source file
├── config.h            # Feature configuration (all disabled)
├── network.h           # NetworkManager (DISABLED)
├── persistence.h       # Persistence mechanisms (ALL DISABLED)
├── threadpool.h        # Thread pool implementation
├── evasion.h           # ETW/AMSI bypass, sleep obfuscation
├── syscalls.h          # Dynamic syscall resolution
├── unhook.h            # Ntdll unhooking
├── process.h           # PPID spoofing, process hollowing
├── stealers.h          # Data stealing modules
├── antidote.cpp        # Removal tool source
├── .env.example        # Example credentials (placeholder only)
└── README.md           # This file
```

---

## 🧹 Antidote (Removal Tool)

A cleanup tool to remove all traces of the keylogger from a system.

### Building Antidote

No pre-built binary is provided. Compile manually:

```bash
# Set PATH to MSYS2
set PATH=C:\msys64\ucrt64\bin;%PATH%

# Compile Antidote
g++ -o AntidoteCPP.exe antidote.cpp -std=c++17 -O2 -static -lole32 -loleaut32 -lwbemuuid -lshell32
```

### What It Removes
- All running keylogger processes
- Registry persistence entries
- Scheduled tasks
- Startup shortcuts
- COM hijacking entries
- WMI subscriptions
- Hidden files and backups
- Temp files

### Usage

After building:
```batch
.\AntidoteCPP.exe
```

---

## 📜 Legal Notice

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║  ⚠️  THIS PROJECT IS INTENTIONALLY NON-FUNCTIONAL  ⚠️                        ║
║                                                                               ║
║  This repository has been deliberately de-weaponized to prevent misuse:       ║
║  • No pre-built binaries are provided                                         ║
║  • No automated build scripts are included                                    ║
║  • All features are disabled by default                                       ║
║  • Network functionality is blocked                                           ║
║  • Persistence mechanisms are removed                                         ║
║  • Compilation requires explicit acknowledgment                               ║
║                                                                               ║
║  This software is provided for EDUCATIONAL and AUTHORIZED TESTING purposes    ║
║  ONLY. The authors are not responsible for any misuse or damage caused.       ║
║                                                                               ║
║  BEFORE ANY USE, you MUST have:                                               ║
║  • Written authorization from the system owner                                ║
║  • Compliance with all applicable local and international laws                ║
║  • A legitimate security testing or educational purpose                       ║
║                                                                               ║
║  Unauthorized use violates laws including:                                    ║
║  • Turkey: TCK 243-245 (Bilişim Suçları)                                      ║
║  • USA: Computer Fraud and Abuse Act (CFAA)                                   ║
║  • EU: GDPR, NIS Directive                                                    ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

## 🔄 Version History

| Version | Date | Changes |
|---------|------|---------|
| 3.0 | 2026-01 | De-weaponized: all features disabled, binaries removed |
| 2.1 | 2024-12 | Cache-busting fix, independent network connections |
| 2.0 | 2024-12 | Elite evasion, multi-persistence |
| 1.0 | 2024-11 | Initial release |

---

**Developed by vatannarda** | *Intentionally incomplete for safety*
