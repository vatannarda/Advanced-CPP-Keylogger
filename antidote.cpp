#define _WIN32_WINNT 0x0600
#define WINVER 0x0600

#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <wbemidl.h>
#include <comdef.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

// ==================== COM HIJACK TARGETS ====================
// Must match persistence.h targets
static const char* COM_HIJACK_CLSIDS[] = {
    "{BCDE0395-E52F-467C-8E3D-C4579291692E}",
    "{F5078F35-C551-11D3-89B9-0000F81FE221}",
    "{D5978620-5B9F-11D1-8DD2-00AA004ABD5E}"
};

// ==================== FONKSIYONLAR ====================
void PrintHeader() {
    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "   C++ Keylogger Antidote v3.0\n";
    std::cout << "   Gelismis Temizleme Araci (Evasion Update)\n";
    std::cout << "========================================\n\n";
}

bool KillProcess(const char* processName) {
    bool killed = false;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    if (TerminateProcess(hProcess, 0)) {
                        std::cout << "[+] Process sonlandirildi: " << processName << " (PID: " << pe.th32ProcessID << ")\n";
                        killed = true;
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    return killed;
}

bool DeleteFileSecure(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    
    SetFileAttributesA(path.c_str(), FILE_ATTRIBUTE_NORMAL);
    
    if (DeleteFileA(path.c_str())) {
        std::cout << "[+] Silindi: " << path << "\n";
        return true;
    } else {
        std::cout << "[-] Silinemedi: " << path << "\n";
        return false;
    }
}

bool DeleteDirectoryRecursive(const std::string& path) {
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA((path + "\\*").c_str(), &fd);
    
    if (hFind == INVALID_HANDLE_VALUE) return false;
    
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        
        std::string fullPath = path + "\\" + fd.cFileName;
        
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            DeleteDirectoryRecursive(fullPath);
        } else {
            SetFileAttributesA(fullPath.c_str(), FILE_ATTRIBUTE_NORMAL);
            DeleteFileA(fullPath.c_str());
        }
    } while (FindNextFileA(hFind, &fd));
    
    FindClose(hFind);
    
    if (RemoveDirectoryA(path.c_str())) {
        std::cout << "[+] Klasor silindi: " << path << "\n";
        return true;
    }
    return false;
}

void CleanRegistry() {
    std::cout << "\n[*] Registry temizleniyor...\n";
    
    HKEY hKey;
    
    // HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        // Eski isimler
        if (RegDeleteValueA(hKey, "SecurityHealthService") == ERROR_SUCCESS) {
            std::cout << "[+] Registry: Run\\SecurityHealthService silindi\n";
        }
        if (RegDeleteValueA(hKey, "WindowsHealthService") == ERROR_SUCCESS) {
            std::cout << "[+] Registry: Run\\WindowsHealthService silindi\n";
        }
        // Yeni isimler (Evasion Update)
        if (RegDeleteValueA(hKey, "OneDriveUpdate") == ERROR_SUCCESS) {
            std::cout << "[+] Registry: Run\\OneDriveUpdate silindi\n";
        }
        RegCloseKey(hKey);
    }
    
    // HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegDeleteValueA(hKey, "SecurityUpdate") == ERROR_SUCCESS) {
            std::cout << "[+] Registry: RunOnce\\SecurityUpdate silindi\n";
        }
        RegCloseKey(hKey);
    }
    
    // Fileless persistence registry
    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\Health");
    std::cout << "[+] Registry: Fileless persistence data silindi\n";
}

void CleanCOMHijacks() {
    std::cout << "\n[*] COM Hijack girisleri temizleniyor...\n";
    
    for (const auto& clsid : COM_HIJACK_CLSIDS) {
        std::string keyPath = std::string("Software\\Classes\\CLSID\\") + clsid;
        
        if (RegDeleteTreeA(HKEY_CURRENT_USER, keyPath.c_str()) == ERROR_SUCCESS) {
            std::cout << "[+] COM Hijack silindi: " << clsid << "\n";
        }
    }
}

void CleanWMISubscription() {
    std::cout << "\n[*] WMI Subscription temizleniyor...\n";
    
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::cout << "[-] COM baslatma basarisiz\n";
        return;
    }
    
    CoInitializeSecurity(NULL, -1, NULL, NULL, 
                         RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE, 
                         NULL, EOAC_NONE, NULL);
    
    IWbemLocator* pLocator = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (LPVOID*)&pLocator);
    
    if (SUCCEEDED(hr)) {
        IWbemServices* pServices = NULL;
        hr = pLocator->ConnectServer(_bstr_t(L"ROOT\\subscription"), 
                                      NULL, NULL, 0, NULL, 0, 0, &pServices);
        
        if (SUCCEEDED(hr)) {
            // Eski isimler
            pServices->DeleteInstance(
                _bstr_t(L"__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"SystemHealthMonitor_Filter\\\"\",Consumer=\"CommandLineEventConsumer.Name=\\\"SystemHealthMonitor_Consumer\\\"\""), 
                0, NULL, NULL);
            pServices->DeleteInstance(
                _bstr_t(L"CommandLineEventConsumer.Name=\"SystemHealthMonitor_Consumer\""), 
                0, NULL, NULL);
            pServices->DeleteInstance(
                _bstr_t(L"__EventFilter.Name=\"SystemHealthMonitor_Filter\""), 
                0, NULL, NULL);
            
            // Yeni isimler (Evasion Update)
            pServices->DeleteInstance(
                _bstr_t(L"__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"OneDriveSyncMonitor_Filter\\\"\",Consumer=\"CommandLineEventConsumer.Name=\\\"OneDriveSyncMonitor_Consumer\\\"\""), 
                0, NULL, NULL);
            pServices->DeleteInstance(
                _bstr_t(L"CommandLineEventConsumer.Name=\"OneDriveSyncMonitor_Consumer\""), 
                0, NULL, NULL);
            pServices->DeleteInstance(
                _bstr_t(L"__EventFilter.Name=\"OneDriveSyncMonitor_Filter\""), 
                0, NULL, NULL);
            
            std::cout << "[+] WMI Subscription silindi\n";
            pServices->Release();
        } else {
            std::cout << "[-] WMI baglanti basarisiz (admin gerekebilir)\n";
        }
        
        pLocator->Release();
    }
    
    CoUninitialize();
}

void CleanScheduledTasks() {
    std::cout << "\n[*] Zamanlanmis gorevler temizleniyor...\n";
    
    // Eski task
    system("schtasks /delete /tn \"SecurityHealthService\" /f >nul 2>&1");
    std::cout << "[+] Scheduled Task: SecurityHealthService silindi\n";
    
    // Eski task from persistence.h
    system("schtasks /delete /tn \"Microsoft\\Windows\\SystemHealth\\Monitor\" /f >nul 2>&1");
    std::cout << "[+] Scheduled Task: SystemHealth\\Monitor silindi\n";
    
    // Yeni task (Evasion Update)
    system("schtasks /delete /tn \"Microsoft\\OneDrive\\Update\" /f >nul 2>&1");
    std::cout << "[+] Scheduled Task: OneDrive\\Update silindi\n";
}

void CleanStartupFolder() {
    std::cout << "\n[*] Startup klasoru temizleniyor...\n";
    
    char startupPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath);
    
    // Eski isim
    DeleteFileSecure(std::string(startupPath) + "\\SecurityHealthService.lnk");
    // Yeni isim
    DeleteFileSecure(std::string(startupPath) + "\\OneDriveUpdater.lnk");
}

void CleanHiddenFiles() {
    std::cout << "\n[*] Gizli dosyalar temizleniyor...\n";
    
    char appData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appData);
    
    // Eski konumlar
    DeleteDirectoryRecursive(std::string(appData) + "\\Microsoft\\WindowsApps\\Security");
    DeleteDirectoryRecursive(std::string(appData) + "\\Microsoft\\WindowsApps\\Defender");
    
    // Yeni konum (Evasion Update)
    DeleteDirectoryRecursive(std::string(appData) + "\\Microsoft\\OneDrive\\Update");
    
    // Backup konumlari
    std::vector<std::string> backupPaths = {
        std::string(appData) + "\\Microsoft\\Windows\\Fonts\\fontcache.bin",
        std::string(appData) + "\\Microsoft\\CLR_v4.0\\UsageData.dat",
        std::string(appData) + "\\Microsoft\\Windows\\INetCache\\update.exe"
    };
    
    for (const auto& path : backupPaths) {
        DeleteFileSecure(path);
    }
}

void CleanTempFiles() {
    std::cout << "\n[*] Temp dosyalari temizleniyor...\n";
    
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    
    // mstemp_ ile baslayan klasorleri bul ve sil
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA((std::string(tempPath) + "mstemp_*").c_str(), &fd);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                std::string fullPath = std::string(tempPath) + fd.cFileName;
                DeleteDirectoryRecursive(fullPath);
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    
    // Stealer temp files
    std::vector<std::string> tempFiles = {
        std::string(tempPath) + "cookies_copy.db",
        std::string(tempPath) + "login_copy.db",
        std::string(tempPath) + "svc.exe"
    };
    
    for (const auto& file : tempFiles) {
        DeleteFileSecure(file);
    }
}

void CleanCryptedFiles() {
    std::cout << "\n[*] Crypted dosyalar temizleniyor...\n";
    
    char userProfile[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, userProfile);
    
    std::string desktopParent = std::string(userProfile) + "\\OneDrive\\Desktop";
    
    // Check common crypted output locations
    std::vector<std::string> cryptedPaths = {
        desktopParent + "\\crypted_KeyloggerCPP.exe",
        desktopParent + "\\Update.exe", 
        desktopParent + "\\EliteKeylogger.exe",
        std::string(userProfile) + "\\Desktop\\crypted_KeyloggerCPP.exe",
        std::string(userProfile) + "\\Desktop\\Update.exe",
        std::string(userProfile) + "\\Desktop\\EliteKeylogger.exe"
    };
    
    for (const auto& path : cryptedPaths) {
        DeleteFileSecure(path);
    }
}

void KillAllProcesses() {
    std::cout << "[*] Keylogger processleri sonlandiriliyor...\n";
    
    const char* processes[] = {
        // Eski isimler
        "SecurityHealthService.exe",
        "KeyloggerCPP.exe",
        "crypted_KeyloggerCPP.exe",
        "stub.exe",
        "svc.exe",
        "MsMpEng.exe",
        "EliteKeylogger.exe", // Legacy
        // Yeni isimler (Evasion Update)
        "OneDriveUpdater.exe",
        "Update.exe"
    };
    
    for (const auto& proc : processes) {
        while (KillProcess(proc)) {
            Sleep(100);
        }
    }
}

void PrintSummary() {
    std::cout << "\n========================================\n";
    std::cout << "   Temizleme Tamamlandi!\n";
    std::cout << "========================================\n\n";
    
    std::cout << "Yapilan islemler:\n";
    std::cout << "  - Keylogger processleri sonlandirildi\n";
    std::cout << "  - Registry kayitlari silindi\n";
    std::cout << "  - COM Hijack girisleri silindi\n";
    std::cout << "  - WMI Subscription silindi\n";
    std::cout << "  - Zamanlanmis gorevler silindi\n";
    std::cout << "  - Startup kisayollari silindi\n";
    std::cout << "  - Gizli dosyalar silindi\n";
    std::cout << "  - Temp dosyalari temizlendi\n";
    std::cout << "  - Crypted dosyalar silindi\n\n";
    
    std::cout << "Oneriler:\n";
    std::cout << "  - Bilgisayari yeniden baslat\n";
    std::cout << "  - Antivirus taramasi yap\n";
    std::cout << "  - TUM sifreleri degistir (ozellikle Discord, Crypto)\n";
    std::cout << "  - 2FA aktif et\n\n";
}

int main() {
    // Konsol ayarlari
    SetConsoleTitleA("C++ Keylogger Antidote v3.0");
    SetConsoleOutputCP(65001);
    
    PrintHeader();
    
    std::cout << "Bu arac C++ Keylogger'i ve tum persistence mekanizmalarini temizleyecek.\n";
    std::cout << "Temizlenecekler:\n";
    std::cout << "  - Registry Run/RunOnce kayitlari\n";
    std::cout << "  - COM Hijack girisleri\n";
    std::cout << "  - WMI Event Subscription\n";
    std::cout << "  - Scheduled Tasks\n";
    std::cout << "  - Startup kisayollari\n";
    std::cout << "  - Gizli dosyalar ve backuplar\n";
    std::cout << "  - Temp dosyalari\n\n";
    std::cout << "Devam etmek icin Enter'a basin...\n";
    std::cin.get();
    
    // 1. Processleri sonlandir
    KillAllProcesses();
    Sleep(500);
    
    // 2. Registry temizle
    CleanRegistry();
    
    // 3. COM Hijack temizle (YENİ)
    CleanCOMHijacks();
    
    // 4. WMI Subscription temizle (YENİ)
    CleanWMISubscription();
    
    // 5. Scheduled Tasks temizle
    CleanScheduledTasks();
    
    // 6. Startup klasoru temizle
    CleanStartupFolder();
    
    // 7. Gizli dosyalari temizle
    CleanHiddenFiles();
    
    // 8. Temp dosyalari temizle
    CleanTempFiles();
    
    // 9. Crypted dosyalari temizle (YENİ)
    CleanCryptedFiles();
    
    // Ozet
    PrintSummary();
    
    std::cout << "Cikis icin Enter'a basin...\n";
    std::cin.get();
    
    return 0;
}
