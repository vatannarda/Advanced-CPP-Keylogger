#ifndef CONFIG_H
#define CONFIG_H

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                    ⚠️  EDUCATIONAL USE ONLY  ⚠️                           ║
// ║                                                                           ║
// ║  Bu proje YALNIZCA eğitim ve güvenlik araştırması amaçlıdır.              ║
// ║  Gerçek sistemlerde kullanımı YASA DIŞIDIR.                               ║
// ║                                                                           ║
// ║  This project is for EDUCATIONAL and SECURITY RESEARCH purposes ONLY.    ║
// ║  Use on real systems is ILLEGAL.                                         ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

// ============ EDUCATIONAL MODE GUARD ============
// Bu projeyi derlemek için aşağıdaki satırı 1 yapmanız GEREKİR.
// Bu, kodun kontrolsüz/bilinçsiz derlenmesini önler.
// 
// To compile this project, you MUST change the value below to 1.
// This prevents accidental/unintended compilation.

#define EDUCATIONAL_ACKNOWLEDGED 0

#if !EDUCATIONAL_ACKNOWLEDGED
#error "DERLEME ENGELLENDI: Bu proje egitim amaclidir. Derlemek icin config.h'de EDUCATIONAL_ACKNOWLEDGED'i 1 yapin ve riskleri kabul ettiginizi onaylayin. / COMPILATION BLOCKED: This project is educational. Set EDUCATIONAL_ACKNOWLEDGED to 1 in config.h to acknowledge risks."
#endif

// ============ FEATURE FLAGS ============
// ⚠️ VARSAYILAN: TÜM ÖZELLİKLER DEVRE DIŞI
// ⚠️ DEFAULT: ALL FEATURES DISABLED
//
// Bu proje bilinçli olarak çalışmaz halde bırakılmıştır.
// This project is intentionally left non-functional.

#define FEATURE_KEYLOGGER        0  // DEVRE DIŞI - Tuş kaydı
#define FEATURE_CLIPBOARD        0  // DEVRE DIŞI - Pano izleme
#define FEATURE_SCREENSHOT       0  // DEVRE DIŞI - Ekran görüntüsü
#define FEATURE_USB_MONITOR      0  // DEVRE DIŞI - USB takip
#define FEATURE_REMOTE_COMMANDS  0  // DEVRE DIŞI - Uzaktan komut
#define FEATURE_STEALERS         0  // DEVRE DIŞI - Veri çalma modülleri
#define FEATURE_PERSISTENCE      0  // DEVRE DIŞI - Kalıcılık (KESİNLİKLE AKTİF ETMEYİN!)
#define FEATURE_EVASION          0  // DEVRE DIŞI - Anti-analiz

// Keyboard capture mode (varsayılan polling - daha az invaziv)
#define KEYBOARD_USE_POLLING     1

// ============ STEALER ALT ÖZELLİKLERİ ============
// Tümü varsayılan KAPALI
#define FEATURE_STEAL_WIFI       0
#define FEATURE_STEAL_BROWSER    0
#define FEATURE_STEAL_DISCORD    0
#define FEATURE_STEAL_CRYPTO     0
#define FEATURE_STEAL_WEBCAM     0
#define FEATURE_STEAL_FILES      0

// ============ NETWORK GUARD ============
// Ağ iletişimi varsayılan DEVRE DIŞI
#define NETWORK_ENABLED          0

// ============ PERSISTENCE GUARD ============
// Kalıcılık özellikleri KESİNLİKLE DEVRE DIŞI
#define PERSISTENCE_ENABLED      0

// ============ TIMING (Eğitim amaçlı - yüksek değerler) ============
#ifndef REPORT_INTERVAL
#define REPORT_INTERVAL          9999    // Pratik olarak devre dışı
#endif

#ifndef SCREENSHOT_INTERVAL
#define SCREENSHOT_INTERVAL      9999    // Pratik olarak devre dışı
#endif

#ifndef COMMAND_POLL_INTERVAL
#define COMMAND_POLL_INTERVAL    9999999 // Pratik olarak devre dışı
#endif

#ifndef CLIPBOARD_CHECK_INTERVAL
#define CLIPBOARD_CHECK_INTERVAL 9999999 // Pratik olarak devre dışı
#endif

#endif // CONFIG_H
