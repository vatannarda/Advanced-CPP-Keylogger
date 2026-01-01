#ifndef NETWORK_H
#define NETWORK_H

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                    ⚠️  EDUCATIONAL USE ONLY  ⚠️                           ║
// ║                                                                           ║
// ║  Network functionality is DISABLED for safety.                           ║
// ║  This prevents any external communication.                                ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

#include <windows.h>
#include <wininet.h>
#include <string>

// ============ NETWORK DISABLED FOR EDUCATIONAL USE ============
// Ağ işlevselliği eğitim güvenliği için varsayılan DEVRE DIŞI
// Network functionality is DISABLED by default for educational safety
#define NETWORK_DISABLED 1

// Connection Pooling ve Singleton Telegram manager
class NetworkManager {
private:
    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    CRITICAL_SECTION lock;
    bool initialized = false;
    
    NetworkManager() {
        InitializeCriticalSection(&lock);
    }
    
public:
    static NetworkManager& Instance() {
        static NetworkManager instance;
        return instance;
    }
    
    // Lazy initialization - DISABLED FOR EDUCATIONAL USE
    bool Initialize() {
        #if NETWORK_DISABLED
        // ⚠️ EDUCATIONAL BUILD: Network functionality is disabled
        // No external connections will be made
        return false;
        #else
        if (initialized && hConnect) return true;
        
        Lock();
        if (initialized && hConnect) {
            Unlock();
            return true;
        }

        if (hInternet) InternetCloseHandle(hInternet);
        
        hInternet = InternetOpenA(
            "Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, 
            NULL, NULL, 0);
            
        if (!hInternet) {
            Unlock();
            return false;
        }
        
        hConnect = InternetConnectA(
            hInternet, "api.telegram.org",
            INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL,
            INTERNET_SERVICE_HTTP, 0, 0);
            
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            hInternet = NULL;
            Unlock();
            return false;
        }
        
        initialized = true;
        Unlock();
        return true;
        #endif
    }
    
    // Baglantiyi al - RETURNS NULL WHEN DISABLED
    HINTERNET GetConnection() { 
        #if NETWORK_DISABLED
        return NULL;  // Network disabled
        #else
        if (!initialized) Initialize();
        return hConnect; 
        #endif
    }
    
    HINTERNET GetSession() {
        #if NETWORK_DISABLED
        return NULL;  // Network disabled
        #else
        if (!initialized) Initialize();
        return hInternet;
        #endif
    }
    
    void Lock() { EnterCriticalSection(&lock); }
    void Unlock() { LeaveCriticalSection(&lock); }
    
    // Baglanti koparsa resetle
    void Reset() {
        Lock();
        if (hConnect) {
            InternetCloseHandle(hConnect);
            hConnect = NULL;
        }
        if (hInternet) {
            InternetCloseHandle(hInternet);
            hInternet = NULL;
        }
        initialized = false;
        Unlock();
    }
    
    void Shutdown() {
        Reset();
        DeleteCriticalSection(&lock);
    }
};

#define NETWORK NetworkManager::Instance()

#endif // NETWORK_H
