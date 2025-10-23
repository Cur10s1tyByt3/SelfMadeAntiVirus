#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601 
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <shlobj.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <psapi.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <wintrust.h>
#include <string>
#include <filesystem>
#include <vector>
#include <thread>
#include <chrono>
#include <iostream>
#include <set>
#include <map>
#include <algorithm>
#include <cwctype>
#include <sstream>
#include <random>
#include <mutex>
#include <ctime>
#include <queue>
#include <iomanip>
#include <fstream>
#include <locale>
#include <wbemidl.h>
#include <comdef.h>
#include <Softpub.h>
#include <securitybaseapi.h>
#include <processthreadsapi.h>
#include <sddl.h>



#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "wbemuuid.lib")

#ifndef MIB_TCP_STATE_ESTABLISHED
#define MIB_TCP_STATE_ESTABLISHED 5
#endif
#ifndef MIB_TCP_STATE_SYN_SENT
#define MIB_TCP_STATE_SYN_SENT 2
#endif
#ifndef MIB_TCP_STATE_SYN_RECV
#define MIB_TCP_STATE_SYN_RECV 3
#endif

namespace fs = std::filesystem;


void QueueLog(const std::string& message);
int FullScan(const fs::path& temp_dir, HWND hwnd);
int InitialRecoveryOEMScan(const fs::path& recovery_dir, HWND hwnd);
int InitialDefendNotScan(HWND hwnd);
int InitialEngualdrapadoScan(HWND hwnd);
void TempMonitorThread(HWND hwnd);
void DefendNotMonitorThread(HWND hwnd);
void EngualdrapadoMonitorThread(HWND hwnd);
bool DeleteDirectoryContentsRecursively(const fs::path& dir_path, const fs::path& target_dir, const std::wstring& scanType);

const fs::path g_startupGlobal = L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp";
const fs::path g_roamingDir = fs::path(_wgetenv(L"APPDATA"));


static std::set<std::wstring> g_wmiSubscriptionBaseline;
static std::mutex g_wmiBaselineMutex;



bool IsFileSigned(const std::wstring& filePath);
void SnapshotWMIEventSubscriptions();
void CheckWMIEventSubscriptions(HWND hwnd);
void WMIEventSubscriptionMonitorThread(HWND hwnd);
void DllAndVbsMonitorThread(HWND hwnd);



static fs::path GetUserStartupPath()
{
    wchar_t* appdata = _wgetenv(L"APPDATA");
    if (appdata == nullptr) {
       
        wchar_t* userProfile = _wgetenv(L"USERPROFILE");
        if (userProfile == nullptr) return fs::path();
        return fs::path(userProfile) / L"AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    }
    return fs::path(appdata) / L"Microsoft\\Windows\\Start Menu\\Programs\\Startup";
}


fs::path g_startupUser;

// Suspicious persistence extensions
bool HasSuspiciousPersistenceExtension(const std::wstring& filename) {
    std::wstring lower = filename;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    const std::vector<std::wstring> bad_exts = { L".exe", L".scr", L".bat", L".cmd", L".vbs" };
    for (const auto& ext : bad_exts) {
        if (lower.size() >= ext.size() && lower.substr(lower.size() - ext.size()) == ext) {
            return true;
        }
    }
    return false;
}

bool IsOceanFolder(const std::wstring& folderName) {
    // Must start with "Ocean-" and end with ".exe"
    if (folderName.size() < 11) return false; // too short
    if (folderName.rfind(L"Ocean-", 0) != 0) return false; // doesn't start with Ocean-
    if (folderName.size() < 5 || folderName.substr(folderName.size() - 4) != L".exe") return false;

    return true;
}


bool IsFileSigned(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_IGNORE;

    LONG status = WinVerifyTrust(NULL, &policyGUID, &winTrustData);
    return (status == ERROR_SUCCESS);
}


// List of specific files to monitor 
const std::vector<std::wstring> specific_files_to_monitor = {
    L"Info.txt", L"Screenshot.png", L"Hardware.txt",
    L"Information.txt", L"Victim.txt", L"AntiVirus.txt", L"Wifi.txt"
};

// Protected extensions (won't be deleted)
const std::vector<std::wstring> protected_extensions = {
    L".rar", L".zip", L".7z", L".rsp", L".tmp", L".dll", L".pdb", L".pyd", L".node", L".pak", L".yml", L".bin", L".asar", L".cab", L".msi", L".sarif", L".exe", L"."
};

// Whitelisted extensions (safe unless they match specific names)
const std::vector<std::wstring> whitelisted_extensions = {
       L".tmp"
};

// VS-specific whitelisted folders and files
const std::vector<std::wstring> vs_whitelist_folders = {
    L"VisualStudio", L"VS", L"vsv", L"Roslyn", L"MSBuild",
    L"NuGet", L"dotnet", L"devenv", L"vctools", L"vc", L"vcpkg", L"RC", L"7z-out", L"old-install", L".ui-agent", L"ui-agent", L".ui"
};

const std::vector<std::wstring> vs_whitelist_files = {
    L"devenv.exe", L"MSBuild.exe", L"dotnet.exe", L"vstest.console.exe",
    L"roslyn", L"nuget", L"vcpkg", L"vcvarsall.bat", L"cl.exe", L"link.exe", L"rc.exe", L"elevate.exe", L"Feather Launcher.exe", L"__sentry-event"
};

// Safe process names for network connections
const std::vector<std::string> safe_discord_processes = {
    "DiscordPTB.exe", "Discord.exe", "Firefox.exe", "Chrome.exe",
    "msEdge.exe", "Zen.exe", "Opera.exe", "OperaGX.exe", "brave.exe", "smartscreen.exe", "mstsc.exe", "telegram.exe", "session.exe", "Spotify.exe"
};

fs::path getEngualdrapadoPath() {
    const char* localAppData = std::getenv("LocalAppData");
    if (localAppData == nullptr) {
        throw std::runtime_error("LocalAppData environment variable not found");
    }

    return fs::path(localAppData) / "Programs" / "engualdrapado";
}

// Defendnot is a programm which overwrites ur antivirus
const fs::path g_defendNotDir = L"C:\\Program Files\\defendnot";
const fs::path g_engualdrapadoDir = getEngualdrapadoPath();






// Global variables
HWND g_hwnd = NULL;
bool g_first_scan_completed = false;
bool g_monitoringPaused = false;
std::mutex g_notificationMutex;
std::mutex g_logMutex;
int g_totalDeletions = 0;
fs::path g_tempDir;
fs::path g_logDir;
fs::path g_recoveryOEMDir;
std::ofstream g_logFile;
std::set<uint32_t> g_blockedIPs;
std::map<uint32_t, std::string> g_ipToDomainMap;
HWND g_hBlockerWnd = NULL;
bool g_bBlockerEnabled = false;
HANDLE g_hBlockerThread = NULL;




struct AsyncTask {
    enum class Type { Log, Notification };
    Type type = Type::Log;
    std::string logMessage;
    int filesDeleted = 0;
    int foldersDeleted = 0;
    std::wstring scanType;
    std::wstring extraInfo;
};

std::queue<AsyncTask> g_asyncTaskQueue;
std::mutex g_asyncTaskMutex;


std::string GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm localTime;
    localtime_s(&localTime, &time_t_now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::ostringstream oss;
    oss << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S") << "." << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}


std::wstring GetCurrentDateForFilename() {
    std::time_t now = std::time(nullptr);
    std::tm localTime;
    localtime_s(&localTime, &now);
    std::wostringstream woss;
    woss << (localTime.tm_year + 1900) << L"-"
        << std::setfill(L'0') << std::setw(2) << (localTime.tm_mon + 1) << L"-"
        << std::setfill(L'0') << std::setw(2) << localTime.tm_mday;
    return woss.str();
}

// Convert wstring to string
std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}


bool IsElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return isElevated != FALSE;
}


std::wstring GetProcessCommandLine(DWORD pid) {
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        QueueLog("[" + GetCurrentTimestamp() + "] CoInitializeEx failed, Error: " + std::to_string(hres));
        return L"";
    }

    IWbemLocator* pLoc = nullptr;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        QueueLog("[" + GetCurrentTimestamp() + "] CoCreateInstance failed, Error: " + std::to_string(hres));
        CoUninitialize();
        return L"";
    }

    IWbemServices* pSvc = nullptr;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        QueueLog("[" + GetCurrentTimestamp() + "] ConnectServer failed, Error: " + std::to_string(hres));
        pLoc->Release();
        CoUninitialize();
        return L"";
    }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        QueueLog("[" + GetCurrentTimestamp() + "] CoSetProxyBlanket failed, Error: " + std::to_string(hres));
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return L"";
    }

    std::wstring query = L"SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + std::to_wstring(pid);
    IEnumWbemClassObject* pEnumerator = nullptr;
    hres = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hres)) {
        QueueLog("[" + GetCurrentTimestamp() + "] ExecQuery failed, Error: " + std::to_string(hres));
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return L"";
    }

    IWbemClassObject* pclsObj = nullptr;
    ULONG uReturn = 0;
    std::wstring commandLine;
    while (pEnumerator) {
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn == 0) break;

        VARIANT vtProp;
        VariantInit(&vtProp);
        hres = pclsObj->Get(L"CommandLine", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) {
            commandLine = vtProp.bstrVal;
        }
        VariantClear(&vtProp);
        pclsObj->Release();
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return commandLine;
}


DWORD GetParentProcessId(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        QueueLog("[" + GetCurrentTimestamp() + "] Failed to create process snapshot for parent PID, Error: " + std::to_string(GetLastError()));
        return 0;
    }

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (!Process32FirstW(hSnapshot, &pe32)) {
        QueueLog("[" + GetCurrentTimestamp() + "] Process32First failed for parent PID, Error: " + std::to_string(GetLastError()));
        CloseHandle(hSnapshot);
        return 0;
    }

    DWORD parentPid = 0;
    do {
        if (pe32.th32ProcessID == pid) {
            parentPid = pe32.th32ParentProcessID;
            break;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return parentPid;
}


DWORD GetProcessIdByFilePath(const std::wstring& filePath) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        QueueLog("[" + GetCurrentTimestamp() + "] Failed to create process snapshot for file path, Error: " + std::to_string(GetLastError()));
        return 0;
    }

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (!Process32FirstW(hSnapshot, &pe32)) {
        QueueLog("[" + GetCurrentTimestamp() + "] Process32First failed for file path, Error: " + std::to_string(GetLastError()));
        CloseHandle(hSnapshot);
        return 0;
    }

    DWORD pid = 0;
    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess != NULL) {
            wchar_t procPath[MAX_PATH] = { 0 };
            if (GetModuleFileNameExW(hProcess, NULL, procPath, MAX_PATH)) {
                if (_wcsicmp(procPath, filePath.c_str()) == 0) {
                    pid = pe32.th32ProcessID;
                    CloseHandle(hProcess);
                    break;
                }
            }
            CloseHandle(hProcess);
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return pid;
}


void SnapshotWMIEventSubscriptions() {
    std::lock_guard<std::mutex> lock(g_wmiBaselineMutex);
    g_wmiSubscriptionBaseline.clear();

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) return;

    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) { CoUninitialize(); return; }

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\SUBSCRIPTION"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hr)) { pLoc->Release(); CoUninitialize(); return; }

    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) { pSvc->Release(); pLoc->Release(); CoUninitialize(); return; }

    auto collectRelpaths = [&](const wchar_t* query) {
        IEnumWbemClassObject* pEnum = nullptr;
        if (SUCCEEDED(pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL, &pEnum)) && pEnum) {
            IWbemClassObject* pObj = nullptr;
            ULONG uRet = 0;
            while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet) == S_OK) {
                VARIANT vt;
                VariantInit(&vt);
                if (SUCCEEDED(pObj->Get(L"__RELPATH", 0, &vt, NULL, NULL)) && vt.vt == VT_BSTR) {
                    g_wmiSubscriptionBaseline.insert(std::wstring(vt.bstrVal));
                }
                VariantClear(&vt);
                pObj->Release();
            }
            pEnum->Release();
        }
        };

    collectRelpaths(L"SELECT * FROM __EventFilter");
    collectRelpaths(L"SELECT * FROM CommandLineEventConsumer");
    collectRelpaths(L"SELECT * FROM __FilterToConsumerBinding");

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
}



// Async task processing thread
void AsyncTaskProcessor(HWND hwnd) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    while (true) {
        AsyncTask task;
        {
            std::lock_guard<std::mutex> lock(g_asyncTaskMutex);
            if (g_asyncTaskQueue.empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            task = g_asyncTaskQueue.front();
            g_asyncTaskQueue.pop();
        }
        if (task.type == AsyncTask::Type::Log) {
            std::lock_guard<std::mutex> lock(g_logMutex);
            if (g_logFile.is_open()) {
                g_logFile << task.logMessage << "\n";
                g_logFile.flush();
            }
        }
        else if (task.type == AsyncTask::Type::Notification) {
            NOTIFYICONDATA nid = {};
            nid.cbSize = sizeof(NOTIFYICONDATA);
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_INFO;
            nid.uTimeout = 5000;
            wcscpy_s(nid.szInfoTitle, L"Temp Monitor - Protection Active");
            std::wstring msg;
            if (task.filesDeleted > 0 && task.foldersDeleted > 0) {
                msg = std::to_wstring(task.filesDeleted) + L" files + " + std::to_wstring(task.foldersDeleted) +
                    L" folders deleted\nTotal: " + std::to_wstring(g_totalDeletions) + L"\n(" + task.scanType + L")";
            }
            else if (task.filesDeleted > 0) {
                msg = std::to_wstring(task.filesDeleted) + L" files deleted\nTotal: " + std::to_wstring(g_totalDeletions) + L"\n(" + task.scanType + L")";
            }
            else if (task.foldersDeleted > 0) {
                msg = std::to_wstring(task.foldersDeleted) + L" folders deleted\nTotal: " + std::to_wstring(g_totalDeletions) + L"\n(" + task.scanType + L")";
            }
            else if (!task.extraInfo.empty()) {
                msg = task.extraInfo + L"\n(" + task.scanType + L")";
            }
            else {
                msg = L"No action taken (" + task.scanType + L")";
            }
            if (msg.length() > 255) {
                msg = msg.substr(0, 252) + L"...";
            }
            wcscpy_s(nid.szInfo, msg.c_str());
            nid.dwInfoFlags = NIIF_INFO;
            Shell_NotifyIcon(NIM_MODIFY, &nid);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// Queue log message
void QueueLog(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_asyncTaskMutex);
    g_asyncTaskQueue.push({ AsyncTask::Type::Log, message, 0, 0, L"", L"" });
}

// Queue notification
void QueueNotification(HWND hwnd, int filesDeleted, int foldersDeleted, const std::wstring& scanType, const std::wstring& extraInfo) {
    std::lock_guard<std::mutex> lock(g_asyncTaskMutex);
    g_totalDeletions += (filesDeleted + foldersDeleted);
    g_asyncTaskQueue.push({ AsyncTask::Type::Notification, "", filesDeleted, foldersDeleted, scanType, extraInfo });
}


void ResolveDomain(const char* domain, std::set<uint32_t>& ipSet) {
    struct addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* result = NULL;
    if (getaddrinfo(domain, NULL, &hints, &result) == 0) {
        for (struct addrinfo* ptr = result; ptr != NULL; ptr = ptr->ai_next) {
            if (ptr->ai_family == AF_INET) {
                struct sockaddr_in* addr = (struct sockaddr_in*)ptr->ai_addr;
                ipSet.insert(addr->sin_addr.s_addr);
                g_ipToDomainMap[addr->sin_addr.s_addr] = domain;
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr));
                QueueLog("[" + GetCurrentTimestamp() + "] Resolved " + domain + " IP: " + ipStr);
            }
        }
        freeaddrinfo(result);
    }
    else {
        QueueLog("[" + GetCurrentTimestamp() + "] Failed to resolve domain: " + domain + ", Error: " + std::to_string(WSAGetLastError()));
    }
}

// Refresh blocked IP addresses
void RefreshBlockedIPs() {
    g_blockedIPs.clear();
    g_ipToDomainMap.clear();
    ResolveDomain("ipinfo.io", g_blockedIPs);
    ResolveDomain("telegram.org", g_blockedIPs);
    ResolveDomain("t.me", g_blockedIPs);
    ResolveDomain("c3lestial.fun", g_blockedIPs);
    ResolveDomain("188.114.96.0", g_blockedIPs);
    ResolveDomain("188.114.97.0", g_blockedIPs);
    ResolveDomain("104.20.29.150", g_blockedIPs);
    ResolveDomain("ebolas.top", g_blockedIPs);
    ResolveDomain("nova-shadow.com", g_blockedIPs);
    ResolveDomain("api.ipify.org", g_blockedIPs);
    ResolveDomain("discord.com", g_blockedIPs);
    ResolveDomain("ptb.discord.com", g_blockedIPs);
    ResolveDomain("webhook.discord.com", g_blockedIPs);
    ResolveDomain("discordapp.com", g_blockedIPs);
    ResolveDomain("gofile.io", g_blockedIPs);
}

// Suspend all threads of a process
bool SuspendProcess(DWORD pid) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        QueueLog("[" + GetCurrentTimestamp() + "] Failed to create thread snapshot, Error: " + std::to_string(GetLastError()));
        return false;
    }
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hThreadSnap, &te32)) {
        QueueLog("[" + GetCurrentTimestamp() + "] Thread32First failed, Error: " + std::to_string(GetLastError()));
        CloseHandle(hThreadSnap);
        return false;
    }
    bool success = true;
    do {
        if (te32.th32OwnerProcessID == pid) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (hThread != NULL) {
                if (SuspendThread(hThread) == (DWORD)-1) {
                    success = false;
                    QueueLog("[" + GetCurrentTimestamp() + "] Failed to suspend thread ID: " + std::to_string(te32.th32ThreadID) + ", Error: " + std::to_string(GetLastError()));
                }
                CloseHandle(hThread);
            }
            else {
                success = false;
                QueueLog("[" + GetCurrentTimestamp() + "] Failed to open thread ID: " + std::to_string(te32.th32ThreadID) + ", Error: " + std::to_string(GetLastError()));
            }
        }
    } while (Thread32Next(hThreadSnap, &te32));
    CloseHandle(hThreadSnap);
    return success;
}

// Terminate process asynchronously
void TerminateProcessAsync(HWND hwnd, DWORD pid, const std::string& procNameStr, const char* procPath, const std::string& connectionInfo, const std::wstring& scanType = L"Threat Termination") {
    std::thread([hwnd, pid, procNameStr, procPath, connectionInfo, scanType]() {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess != NULL) {
            if (TerminateProcess(hProcess, 0)) {
                DeleteFileA(procPath);
                std::string logMessage = "[" + GetCurrentTimestamp() + "] PROCESS TERMINATED: " + procNameStr + " (PID: " + std::to_string(pid) + ") " + connectionInfo;
                QueueLog(logMessage);
                std::wstring procNameW(procNameStr.begin(), procNameStr.end());
                std::wstring connectionInfoW(connectionInfo.begin(), connectionInfo.end());
                std::wstring notificationMessage = procNameW + L" (PID: " + std::to_wstring(pid) + L") terminated (" + connectionInfoW + L")";
                QueueNotification(hwnd, 0, 0, scanType, notificationMessage);
            }
            else {
                QueueLog("[" + GetCurrentTimestamp() + "] Failed to terminate process PID: " + std::to_string(pid) + ", Error: " + std::to_string(GetLastError()));
            }
            CloseHandle(hProcess);
        }
        else {
            QueueLog("[" + GetCurrentTimestamp() + "] Failed to open process for termination PID: " + std::to_string(pid) + ", Error: " + std::to_string(GetLastError()));
        }
        }).detach();
}

// Terminate process creating file in C:\recovery\OEM
void TerminateProcessCreatingFile(HWND hwnd, DWORD pid, const fs::path& filePath) {
    std::thread([hwnd, pid, filePath]() {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pid);
        if (hProcess != NULL) {
            char procPath[MAX_PATH] = { 0 };
            std::string procNameStr = "Unknown";
            if (GetModuleFileNameExA(hProcess, NULL, procPath, MAX_PATH)) {
                procNameStr = PathFindFileNameA(procPath);
            }
            if (TerminateProcess(hProcess, 0)) {
                std::string pathStr = WStringToString(filePath.wstring());
                std::replace(pathStr.begin(), pathStr.end(), '\\', '/');
                std::string logMessage = "[" + GetCurrentTimestamp() + "] PROCESS TERMINATED: " + procNameStr + " (PID: " + std::to_string(pid) + ") created file: " + pathStr;
                QueueLog(logMessage);
                std::wstring procNameW(procNameStr.begin(), procNameStr.end());
                std::wstring notificationMessage = procNameW + L" (PID: " + std::to_wstring(pid) + L") terminated (created file: " + filePath.wstring() + L")";
                QueueNotification(hwnd, 0, 0, L"Recovery OEM Threat", notificationMessage);
            }
            else {
                QueueLog("[" + GetCurrentTimestamp() + "] Failed to terminate process PID: " + std::to_string(pid) + ", Error: " + std::to_string(GetLastError()));
            }
            CloseHandle(hProcess);
        }
        else {
            QueueLog("[" + GetCurrentTimestamp() + "] Failed to open process PID: " + std::to_string(pid) + ", Error: " + std::to_string(GetLastError()));
        }
        }).detach();
}




void CheckWMIEventSubscriptions(HWND hwnd) {
    std::set<std::wstring> found;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) return;

    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) { CoUninitialize(); return; }

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\SUBSCRIPTION"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hr)) { pLoc->Release(); CoUninitialize(); return; }

    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    auto queryAndCollect = [&](const wchar_t* q) {
        IEnumWbemClassObject* pEnum = nullptr;
        if (SUCCEEDED(pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(q),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL, &pEnum)) && pEnum) {
            IWbemClassObject* pObj = nullptr;
            ULONG uRet = 0;
            while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet) == S_OK) {
                VARIANT vt;
                VariantInit(&vt);
                if (SUCCEEDED(pObj->Get(L"__RELPATH", 0, &vt, NULL, NULL)) && vt.vt == VT_BSTR) {
                    found.insert(std::wstring(vt.bstrVal));
                }
                VariantClear(&vt);
                pObj->Release();
            }
            pEnum->Release();
        }
        };

    queryAndCollect(L"SELECT * FROM __EventFilter");
    queryAndCollect(L"SELECT * FROM CommandLineEventConsumer");
    queryAndCollect(L"SELECT * FROM __FilterToConsumerBinding");

    {
        std::lock_guard<std::mutex> lock(g_wmiBaselineMutex);
        for (const auto& item : found) {
            if (g_wmiSubscriptionBaseline.find(item) == g_wmiSubscriptionBaseline.end()) {
                // New subscription detected — log + notify + add to baseline
                std::wstring wsmsg = L"New WMI subscription detected: " + item;
                QueueLog("[" + GetCurrentTimestamp() + "] " + WStringToString(wsmsg));
                QueueNotification(hwnd, 0, 0, L"WMI Persistence Detected", wsmsg);
                g_wmiSubscriptionBaseline.insert(item);
            }
        }
    }

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
}



// Check for known common UAC-bypasses
// Suspend and terminate the process and its parent
void CheckAndTerminateCommonUacBypass(HWND hwnd) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        QueueLog("[" + GetCurrentTimestamp() + "] Failed to create process snapshot for UAC bypass check, Error: " + std::to_string(GetLastError()));
        return;
    }

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (!Process32FirstW(hSnapshot, &pe32)) {
        QueueLog("[" + GetCurrentTimestamp() + "] Process32First failed for UAC bypass check, Error: " + std::to_string(GetLastError()));
        CloseHandle(hSnapshot);
        return;
    }

    do {
        std::wstring procName = pe32.szExeFile;
        std::wstring procNameLower = procName;
        std::transform(procNameLower.begin(), procNameLower.end(), procNameLower.begin(), ::towlower);

        if (procNameLower == L"cmstp.exe" || procNameLower == L"fodhelper.exe") {
            DWORD pid = pe32.th32ProcessID;
            char procPath[MAX_PATH] = { 0 };
            std::string procNameStr = WStringToString(procName);

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pid);
            if (hProcess != NULL) {
                if (GetModuleFileNameExA(hProcess, NULL, procPath, MAX_PATH)) {
                    procNameStr = PathFindFileNameA(procPath);
                }
                CloseHandle(hProcess);
            }

           
            if (SuspendProcess(pid)) {
                QueueLog("[" + GetCurrentTimestamp() + "] Suspended suspected UAC bypass process: " + procNameStr + " (PID: " + std::to_string(pid) + ")");
            }
            else {
                QueueLog("[" + GetCurrentTimestamp() + "] Failed to suspend suspected UAC bypass process: " + procNameStr + " (PID: " + std::to_string(pid) + ")");
            }

           
            TerminateProcessAsync(hwnd, pid, procNameStr, procPath, "Common UAC Bypass: " + procNameStr, L"Common Uac Bypass detected");

            
            DWORD parentPid = GetParentProcessId(pid);
            if (parentPid != 0 && parentPid != pid) {
                HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, parentPid);
                std::string parentProcNameStr = "Unknown";
                char parentProcPath[MAX_PATH] = { 0 };
                if (hParent != NULL) {
                    if (GetModuleFileNameExA(hParent, NULL, parentProcPath, MAX_PATH)) {
                        parentProcNameStr = PathFindFileNameA(parentProcPath);
                    }
                    CloseHandle(hParent);
                }

                if (SuspendProcess(parentPid)) {
                    QueueLog("[" + GetCurrentTimestamp() + "] Suspended parent of UAC bypass process: " + parentProcNameStr + " (PID: " + std::to_string(parentPid) + ")");
                }
                else {
                    QueueLog("[" + GetCurrentTimestamp() + "] Failed to suspend parent PID: " + std::to_string(parentPid));
                }

                TerminateProcessAsync(hwnd, parentPid, parentProcNameStr, parentProcPath, "Parent of Common UAC Bypass: " + parentProcNameStr, L"Common Uac Bypass detected");
            }

            
            std::wstring notificationExtra = procName + L" (PID: " + std::to_wstring(pid) + L")";
            QueueNotification(hwnd, 0, 0, L"Common Uac Bypass detected", notificationExtra);
        }

    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
}


void UACBypassMonitorThread(HWND hwnd) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    while (true) {
        if (g_monitoringPaused) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        CheckAndTerminateCommonUacBypass(hwnd);
        std::this_thread::sleep_for(std::chrono::milliseconds(500)); // check twice per second
    }
}


void WMIEventSubscriptionMonitorThread(HWND hwnd) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

    
    SnapshotWMIEventSubscriptions();
    QueueLog("[" + GetCurrentTimestamp() + "] WMI subscription baseline snapshot completed.");

    while (true) {
        if (g_monitoringPaused) { 
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        CheckWMIEventSubscriptions(hwnd);

        // polling interval — tune as needed
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}


// Check for suspicious PowerShell commands
void CheckAndTerminateSuspiciousPowerShell(HWND hwnd) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        QueueLog("[" + GetCurrentTimestamp() + "] Failed to create process snapshot, Error: " + std::to_string(GetLastError()));
        return;
    }

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (!Process32FirstW(hSnapshot, &pe32)) {
        QueueLog("[" + GetCurrentTimestamp() + "] Process32First failed, Error: " + std::to_string(GetLastError()));
        CloseHandle(hSnapshot);
        return;
    }

    do {
        std::wstring procName = pe32.szExeFile;
        std::transform(procName.begin(), procName.end(), procName.begin(), ::towlower);
        if (procName == L"powershell.exe" || procName == L"pwsh.exe") { 
            DWORD pid = pe32.th32ProcessID;
            std::wstring cmdLine = GetProcessCommandLine(pid);
            QueueLog("[" + GetCurrentTimestamp() + "] PowerShell PID: " + std::to_string(pid) + " CommandLine: " + WStringToString(cmdLine));
            if (cmdLine.empty()) {
                QueueLog("[" + GetCurrentTimestamp() + "] Empty command line for PowerShell PID: " + std::to_string(pid));
                continue;
            }

            std::wstring cmdLineLower = cmdLine;
            std::transform(cmdLineLower.begin(), cmdLineLower.end(), cmdLineLower.begin(), ::towlower);

            bool isSuspicious = false;
            std::wstring suspiciousCommand = L"";

            
            std::vector<std::wstring> suspiciousKeywords = {
                L"invoke-restmethod", L"invoke-webrequest", L"api.ipify.org", L"roblox", L"hostname", L"systeminfo", L"uuid",
                L"-exclusionpath", L"set-mppreference", L"scriptblock", L"-encodedcommand", L"expandproperty", L"displayname",
                L"productkey", L"manufacturer", L"ipv4connectivity", L"ipv6connectivity", L"servername", L"Compress-Archive"
            };

           
            for (const auto& keyword : suspiciousKeywords) {
                if (!keyword.empty() && cmdLineLower.find(keyword) != std::wstring::npos) {
                    if (!isSuspicious) isSuspicious = true;
                    if (!suspiciousCommand.empty()) suspiciousCommand += L", ";
                    suspiciousCommand += keyword;
                }
            }


            size_t firstSpace = cmdLineLower.find(L' ');
            size_t searchStart = (firstSpace == std::wstring::npos) ? 0 : firstSpace + 1;

            
            size_t exePos = cmdLineLower.find(L".exe", searchStart);
            if (exePos != std::wstring::npos) {
 
                if (!isSuspicious) isSuspicious = true;
                if (!suspiciousCommand.empty()) suspiciousCommand += L", ";
                suspiciousCommand += L".exe (called from PowerShell)";
            }

            if (isSuspicious) {
                char procPath[MAX_PATH] = { 0 };
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                std::string procNameStr = "powershell.exe";
                if (hProcess != NULL) {
                    if (GetModuleFileNameExA(hProcess, NULL, procPath, MAX_PATH)) {
                        procNameStr = PathFindFileNameA(procPath);
                    }
                    CloseHandle(hProcess);
                }

                SuspendProcess(pid);
                QueueLog("[" + GetCurrentTimestamp() + "] Suspended PowerShell process: " + procNameStr + " (PID: " + std::to_string(pid) + ") executing: " + WStringToString(suspiciousCommand));

                std::string connectionInfo = "executing suspicious command: " + WStringToString(suspiciousCommand);
                TerminateProcessAsync(hwnd, pid, procNameStr, procPath, connectionInfo, L"Suspicious PowerShell command detected");

                DWORD parentPid = GetParentProcessId(pid);
                if (parentPid != 0) {
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, parentPid);
                    std::string parentProcNameStr = "Unknown";
                    char parentProcPath[MAX_PATH] = { 0 };
                    if (hProcess != NULL) {
                        if (GetModuleFileNameExA(hProcess, NULL, parentProcPath, MAX_PATH)) {
                            parentProcNameStr = PathFindFileNameA(parentProcPath);
                        }
                        CloseHandle(hProcess);
                    }

                    SuspendProcess(parentPid);
                    QueueLog("[" + GetCurrentTimestamp() + "] Suspended parent process: " + parentProcNameStr + " (PID: " + std::to_string(parentPid) + ") of PowerShell executing: " + WStringToString(suspiciousCommand));
                    TerminateProcessAsync(hwnd, parentPid, parentProcNameStr, parentProcPath, "parent of PowerShell executing: " + WStringToString(suspiciousCommand), L"Suspicious PowerShell command detected");
                }
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
}


void CheckAndTerminateSuspiciousSchtasks(HWND hwnd) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        QueueLog("[" + GetCurrentTimestamp() + "] Failed to create process snapshot for schtasks, Error: " + std::to_string(GetLastError()));
        return;
    }

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (!Process32FirstW(hSnapshot, &pe32)) {
        QueueLog("[" + GetCurrentTimestamp() + "] Process32First failed for schtasks, Error: " + std::to_string(GetLastError()));
        CloseHandle(hSnapshot);
        return;
    }

    do {
        std::wstring procName = pe32.szExeFile;
        std::transform(procName.begin(), procName.end(), procName.begin(), ::towlower);
        if (procName == L"schtasks.exe") {
            DWORD pid = pe32.th32ProcessID;
            std::wstring cmdLine = GetProcessCommandLine(pid);
            QueueLog("[" + GetCurrentTimestamp() + "] schtasks PID: " + std::to_string(pid) + " CommandLine: " + WStringToString(cmdLine));
            if (cmdLine.empty()) {
                QueueLog("[" + GetCurrentTimestamp() + "] Empty command line for schtasks PID: " + std::to_string(pid));
                continue;
            }

            std::wstring cmdLineLower = cmdLine;
            std::transform(cmdLineLower.begin(), cmdLineLower.end(), cmdLineLower.begin(), ::towlower);

            bool isSuspicious = false;
            std::wstring suspiciousReason;

           
            if (cmdLineLower.find(L"onlogon") != std::wstring::npos) {
                isSuspicious = true;
                suspiciousReason += L"OnLogon";
            }


            size_t firstSpace = cmdLineLower.find(L' ');
            size_t searchStart = (firstSpace == std::wstring::npos) ? 0 : firstSpace + 1;
            size_t exePos = cmdLineLower.find(L".exe", searchStart);
            if (exePos != std::wstring::npos) {
                // extract a small window around the match to see the executable name
                size_t start = (exePos > 64) ? exePos - 64 : 0;
                std::wstring window = cmdLineLower.substr(start, exePos - start + 4); // include ".exe"
                // if window contains "schtasks.exe" then ignore this particular match
                if (window.find(L"schtasks.exe") == std::wstring::npos) {
                    if (!isSuspicious) isSuspicious = true;
                    if (!suspiciousReason.empty()) suspiciousReason += L", ";
                    suspiciousReason += L".exe invoked";
                }
            }

            if (isSuspicious) {
                char procPath[MAX_PATH] = { 0 };
                std::string procNameStr = "schtasks.exe";
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (hProcess != NULL) {
                    if (GetModuleFileNameExA(hProcess, NULL, procPath, MAX_PATH)) {
                        procNameStr = PathFindFileNameA(procPath);
                    }
                    CloseHandle(hProcess);
                }

                SuspendProcess(pid);
                QueueLog("[" + GetCurrentTimestamp() + "] Suspended schtasks process: " + procNameStr + " (PID: " + std::to_string(pid) + ") reason: " + WStringToString(suspiciousReason));

                std::string connectionInfo = "suspicious schtasks commandline: " + WStringToString(suspiciousReason);
                TerminateProcessAsync(hwnd, pid, procNameStr, procPath, connectionInfo, L"Suspicious schtasks command detected");

                // terminate parent as well (mirror PowerShell handling)
                DWORD parentPid = GetParentProcessId(pid);
                if (parentPid != 0) {
                    HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, parentPid);
                    std::string parentProcNameStr = "Unknown";
                    char parentProcPath[MAX_PATH] = { 0 };
                    if (hParent != NULL) {
                        if (GetModuleFileNameExA(hParent, NULL, parentProcPath, MAX_PATH)) {
                            parentProcNameStr = PathFindFileNameA(parentProcPath);
                        }
                        CloseHandle(hParent);
                    }

                    SuspendProcess(parentPid);
                    QueueLog("[" + GetCurrentTimestamp() + "] Suspended parent process: " + parentProcNameStr + " (PID: " + std::to_string(parentPid) + ") of schtasks executing: " + WStringToString(suspiciousReason));
                    TerminateProcessAsync(hwnd, parentPid, parentProcNameStr, parentProcPath, "parent of schtasks executing: " + WStringToString(suspiciousReason), L"Suspicious schtasks command detected");
                }
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
}


void DllAndVbsMonitorThread(HWND hwnd) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

    while (true) {
        if (g_monitoringPaused) { // same pause flag assumption
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) { std::this_thread::sleep_for(std::chrono::milliseconds(500)); continue; }

        PROCESSENTRY32W pe32 = { sizeof(pe32) };
        if (!Process32FirstW(hSnapshot, &pe32)) { CloseHandle(hSnapshot); std::this_thread::sleep_for(std::chrono::milliseconds(500)); continue; }

        do {
            std::wstring procName = pe32.szExeFile;
            std::transform(procName.begin(), procName.end(), procName.begin(), ::towlower);

            if (procName == L"regsvr32.exe" || procName == L"wscript.exe") {
                DWORD pid = pe32.th32ProcessID;
                std::wstring cmdLine = GetProcessCommandLine(pid); // assume you have this helper

                if (procName == L"wscript.exe") {
                    std::wstring lower = cmdLine; std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                    if (lower.find(L".vbs") != std::wstring::npos) {
                        QueueLog("[" + GetCurrentTimestamp() + "] wscript.exe (PID: " + std::to_string(pid) + ") launched .vbs: " + WStringToString(cmdLine));
                        SuspendProcess(pid); // expected helper
                        QueueNotification(hwnd, 0, 0, L"Suspicious vbs file loaded", L"wscript.exe launched a .vbs script: " + cmdLine);
                        TerminateProcessAsync(hwnd, pid, "wscript.exe", "", "wscript launched .vbs", L"Suspicious vbs file loaded");
                    }
                }

                if (procName == L"regsvr32.exe") {
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                    if (hProc) {
                        HMODULE mods[1024];
                        DWORD cbNeeded = 0;
                        if (EnumProcessModules(hProc, mods, sizeof(mods), &cbNeeded)) {
                            DWORD count = cbNeeded / sizeof(HMODULE);
                            for (DWORD i = 0; i < count; ++i) {
                                wchar_t modPath[MAX_PATH] = { 0 };
                                if (GetModuleFileNameExW(hProc, mods[i], modPath, MAX_PATH)) {
                                    std::wstring path = modPath;
                                    std::wstring pathLower = path; std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);
                                    if (pathLower.size() >= 4 && pathLower.substr(pathLower.size() - 4) == L".dll") {
                                        bool signed_ok = IsFileSigned(path);
                                        if (!signed_ok) {
                                            std::string procNameStr = WStringToString(pe32.szExeFile);
                                            QueueLog("[" + GetCurrentTimestamp() + "] Unsigned DLL detected in " + procNameStr + " (PID: " + std::to_string(pid) + ") -> " + WStringToString(path));
                                            SuspendProcess(pid);
                                            QueueNotification(hwnd, 0, 0, L"Suspicious Dll injection detected", L"Unsigned DLL loaded: " + path);
                                            TerminateProcessAsync(hwnd, pid, procNameStr.c_str(), WStringToString(path).c_str(), "Unsigned DLL loaded: " + WStringToString(path), L"Suspicious Dll injection detected");
                                            break; // take action on first unsigned dll found
                                        }
                                    }
                                }
                            }
                        }
                        CloseHandle(hProc);
                    }
                }
            }

        } while (Process32NextW(hSnapshot, &pe32));

        CloseHandle(hSnapshot);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}


// PowerShell monitoring thread
void PowerShellMonitorThread(HWND hwnd) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    while (true) {
        if (g_monitoringPaused) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        CheckAndTerminateSuspiciousPowerShell(hwnd);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// Registry locations to monitor
const std::vector<std::pair<HKEY, std::wstring>> g_registryPersistenceKeys = {
    { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" },
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs" },
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" },
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" },
    // WOW64 variants
    { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" }
};

// Keep baseline of known values
std::map<std::wstring, std::wstring> g_registryBaseline;

void SnapshotRegistryPersistence() {
    for (const auto& [hive, path] : g_registryPersistenceKeys) {
        HKEY hKey;
        if (RegOpenKeyExW(hive, path.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            wchar_t valueName[512];
            wchar_t valueData[1024];
            DWORD valueNameSize, valueDataSize, type;

            while (true) {
                valueNameSize = sizeof(valueName) / sizeof(wchar_t);
                valueDataSize = sizeof(valueData);
                LONG ret = RegEnumValueW(
                    hKey, index, valueName, &valueNameSize, NULL, &type,
                    reinterpret_cast<LPBYTE>(valueData), &valueDataSize
                );
                if (ret == ERROR_NO_MORE_ITEMS) break;

                if (ret == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
                    std::wstring keyStr = path + L"\\" + valueName;
                    g_registryBaseline[keyStr] = valueData;
                }
                index++;
            }
            RegCloseKey(hKey);
        }
    }
}

void CheckRegistryPersistence(HWND hwnd) {
    for (const auto& [hive, path] : g_registryPersistenceKeys) {
        HKEY hKey;
        if (RegOpenKeyExW(hive, path.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            wchar_t valueName[512];
            wchar_t valueData[1024];
            DWORD valueNameSize, valueDataSize, type;

            while (true) {
                valueNameSize = sizeof(valueName) / sizeof(wchar_t);
                valueDataSize = sizeof(valueData);
                LONG ret = RegEnumValueW(
                    hKey, index, valueName, &valueNameSize, NULL, &type,
                    reinterpret_cast<LPBYTE>(valueData), &valueDataSize
                );
                if (ret == ERROR_NO_MORE_ITEMS) break;

                if (ret == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
                    std::wstring keyStr = path + L"\\" + valueName;
                    std::wstring newValue = valueData;

                    if (!g_registryBaseline.count(keyStr) || g_registryBaseline[keyStr] != newValue) {
                        g_registryBaseline[keyStr] = newValue;

                        std::wstring message = L"New persistence detected in " + keyStr + L" → " + newValue;
                        QueueLog("[" + GetCurrentTimestamp() + "] " + WStringToString(message));
                        QueueNotification(hwnd, 0, 0, L"Registry Persistence", message);
                    }
                }
                index++;
            }
            RegCloseKey(hKey);
        }
    }
}

// Monitoring thread
void RegistryMonitorThread(HWND hwnd) {
    SnapshotRegistryPersistence(); // Initial baseline
    while (true) {
        if (!g_monitoringPaused) {
            CheckRegistryPersistence(hwnd);
        }
        std::this_thread::sleep_for(std::chrono::seconds(2)); // adjust interval
    }
}


// schtasks monitoring thread
void SchtasksMonitorThread(HWND hwnd) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    while (true) {
        if (g_monitoringPaused) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        CheckAndTerminateSuspiciousSchtasks(hwnd);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

bool IsRunAsAdmin() {
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD size;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }
    bool isAdmin = GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)
        && elevation.TokenIsElevated;
    CloseHandle(hToken);
    return isAdmin;
}

DWORD WINAPI BlockerThread(LPVOID lpParam) {
    WNDCLASS wcBlocker = {};
    wcBlocker.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        if (msg == WM_DESTROY) {
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProc(hwnd, msg, wParam, lParam);
        };
    wcBlocker.hInstance = GetModuleHandle(NULL);
    wcBlocker.lpszClassName = L"PrivacyScreenClass";
    RegisterClass(&wcBlocker);

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    g_hBlockerWnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW,
        L"PrivacyScreenClass",
        L"PrivacyScreen",
        WS_POPUP,
        0, 0, screenWidth, screenHeight,
        NULL, NULL, GetModuleHandle(NULL), NULL);

    if (!g_hBlockerWnd) return 1;

    
    SetLayeredWindowAttributes(g_hBlockerWnd, 0, 255, LWA_ALPHA);

    // Prevent screen capture (WDA_MONITOR = 0x01)
    if (!SetWindowDisplayAffinity(g_hBlockerWnd, 0x01)) {
        DestroyWindow(g_hBlockerWnd);
        g_hBlockerWnd = NULL;
        return 1;
    }

    ShowWindow(g_hBlockerWnd, SW_SHOW);
    UpdateWindow(g_hBlockerWnd);

    // Run minimal message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}


void EnablePrivacyScreen() {
    if (g_bBlockerEnabled || g_hBlockerThread) return;
    g_bBlockerEnabled = true;
    g_hBlockerThread = CreateThread(NULL, 0, BlockerThread, NULL, 0, NULL);
}

void DisablePrivacyScreen() {
    g_bBlockerEnabled = false;
    if (g_hBlockerThread) {
        PostThreadMessage(GetThreadId(g_hBlockerThread), WM_QUIT, 0, 0);
        WaitForSingleObject(g_hBlockerThread, 1000);
        CloseHandle(g_hBlockerThread);
        g_hBlockerThread = NULL;
    }
    if (g_hBlockerWnd) {
        DestroyWindow(g_hBlockerWnd);
        g_hBlockerWnd = NULL;
    }
    UnregisterClass(L"PrivacyScreenClass", GetModuleHandle(NULL));
}






// Monitors TCP connections and terminates processes whose executable is unsigned
void CheckAndTerminateSuspicious(HWND hwnd) {
    PMIB_TCPTABLE_OWNER_PID tcpTable = nullptr;
    DWORD size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (tcpTable == nullptr) {
        return;
    }

    if (GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID* row = &tcpTable->table[i];

            // Only consider established (or close-to-established) connections
            if (row->dwState != MIB_TCP_STATE_ESTABLISHED) {
                continue;
            }

            DWORD pid = row->dwOwningPid;
            if (pid == 0) continue;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (hProcess == NULL) {
                continue;
            }

            char procPathA[MAX_PATH] = { 0 };
            if (!GetModuleFileNameExA(hProcess, NULL, procPathA, MAX_PATH)) {
                CloseHandle(hProcess);
                continue;
            }

            std::string procNameStr = PathFindFileNameA(procPathA);
            std::string procPathStr(procPathA);
            // Lowercase proc name for comparisons
            std::string procNameLower = procNameStr;
            std::transform(procNameLower.begin(), procNameLower.end(), procNameLower.begin(), ::tolower);

            // Skip known safe processes (reuse your existing list)
            bool isSafe = false;
            for (const auto& safeProc : safe_discord_processes) {
                std::string safeLower = safeProc;
                std::transform(safeLower.begin(), safeLower.end(), safeLower.begin(), ::tolower);
                if (procNameLower == safeLower) { isSafe = true; break; }
            }
            if (isSafe) {
                CloseHandle(hProcess);
                continue;
            }

            // Convert the ANSI path to wstring for IsFileSigned
            std::wstring wProcPath = fs::path(procPathStr).wstring();

           bool signed_ok = false;
try {
    signed_ok = IsFileSigned(wProcPath);
}
catch (const std::exception& e) {
    QueueLog("[" + GetCurrentTimestamp() + "] Exception while verifying signature for: " 
             + procPathStr + " : " + e.what());
    signed_ok = false;
}
catch (...) {
    QueueLog("[" + GetCurrentTimestamp() + "] Unknown exception while verifying signature for: " 
             + procPathStr);
    signed_ok = false;
}


            if (!signed_ok) {
                // build connection info for logging
                char ipStr[INET_ADDRSTRLEN] = { 0 };
                inet_ntop(AF_INET, &(row->dwRemoteAddr), ipStr, sizeof(ipStr));
                uint16_t remotePort = ntohs((u_short)row->dwRemotePort);
                std::string connectionInfo = std::string(ipStr) + ":" + std::to_string(remotePort);

                std::string logMessage = "[" + GetCurrentTimestamp() + "] UNSIGNED EXE WITH ESTABLISHED TCP: " + procNameStr
                    + " (PID: " + std::to_string(pid) + ") -> " + connectionInfo + " (path: " + procPathStr + ")";
                QueueLog(logMessage);

                
                if (SuspendProcess(pid)) {
                    QueueLog("[" + GetCurrentTimestamp() + "] Suspended process: " + procNameStr + " (PID: " + std::to_string(pid) + ")");
                }
                else {
                    QueueLog("[" + GetCurrentTimestamp() + "] Failed to suspend process: " + procNameStr + " (PID: " + std::to_string(pid) + ")");
                }

                std::string terminationInfo = "Unsigned executable had active TCP connection: " + connectionInfo;
                TerminateProcessAsync(hwnd, pid, procNameStr, procPathStr.c_str(), terminationInfo, L"Unsigned TCP connection detected");

                // send notification
                std::wstring notifyMsg = std::wstring(procNameStr.begin(), procNameStr.end()) + L" (PID: " + std::to_wstring(pid) + L") terminated (unsigned exe with TCP conn)";
                QueueNotification(hwnd, 0, 0, L"Unsigned Network Connection", notifyMsg);
            }

            CloseHandle(hProcess);
        }
    }

    free(tcpTable);
}



// Network monitoring thread
void NetworkMonitorThread(HWND hwnd) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    int refreshCounter = 0;
    const int refreshInterval = 30; // Refresh IPs every 30 seconds
    RefreshBlockedIPs();
    while (true) {
        if (g_monitoringPaused) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        if (refreshCounter >= refreshInterval * 100) {
            RefreshBlockedIPs();
            refreshCounter = 0;
        }
        CheckAndTerminateSuspicious(hwnd);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        refreshCounter++;
    }
}

// Initialize logging
bool InitializeLogging() {
    try {
        wchar_t localAppDataPath[MAX_PATH];
        if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, localAppDataPath) != S_OK) {
            return false;
        }
        g_logDir = fs::path(localAppDataPath) / L"TempMonitor";
        if (!fs::exists(g_logDir)) {
            fs::create_directory(g_logDir);
        }
        std::wstring dateStr = GetCurrentDateForFilename();
        std::wstring logFilename = L"TempMonitor_" + dateStr + L".log";
        fs::path logPath = g_logDir / logFilename;
        std::string logPathNarrow = WStringToString(logPath.wstring());
        g_logFile.open(logPathNarrow, std::ios::app | std::ios::out);
        if (g_logFile.is_open()) {
            QueueLog("=== Temp Monitor Log Started (with Network and PowerShell Monitoring) ===\nLog started: " + GetCurrentTimestamp());
            return true;
        }
    }
    catch (...) {
        return false;
    }
    return false;
}

// Log deleted item
void LogDeletedItem(const fs::path& item_path, bool is_folder, const std::wstring& scanType) {
    std::string itemType = is_folder ? "FOLDER" : "FILE";
    std::string scanTypeStr = WStringToString(scanType);
    std::string pathStr = WStringToString(item_path.wstring());
    std::replace(pathStr.begin(), pathStr.end(), '\\', '/');
    QueueLog("[" + GetCurrentTimestamp() + "] " + itemType + " DELETED - " + scanTypeStr + ": " + pathStr);
}

// Log scan summary
void LogScanSummary(int filesDeleted, int foldersDeleted, const std::wstring& scanType) {
    std::string scanTypeStr = WStringToString(scanType);
    QueueLog("\n[" + GetCurrentTimestamp() + "] SCAN SUMMARY - " + scanTypeStr + "\nFiles deleted: " +
        std::to_string(filesDeleted) + "\nFolders deleted: " + std::to_string(foldersDeleted) +
        "\n----------------------------------------");
}

// Check if path is within %TEMP%
bool IsInTempDirectory(const fs::path& item_path) {
    return item_path.wstring().find(g_tempDir.wstring()) == 0;
}

// Check if path is within C:\recovery\OEM
bool IsInRecoveryOEM(const fs::path& item_path) {
    return item_path.wstring().find(g_recoveryOEMDir.wstring()) == 0;
}

// Check if path is within C:\Program Files\defendnot
bool IsInDefendNotDirectory(const fs::path& item_path) {
    return item_path.wstring().find(g_defendNotDir.wstring()) == 0;
}


bool IsInEngualdrapadoDirectory(const fs::path& item_path) {
    return item_path.wstring().find(g_engualdrapadoDir.wstring()) == 0;
}


bool IsVSWhitelisted(const std::wstring& name, bool is_folder) {
    std::wstring lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), std::towlower);
    if (is_folder) {
        for (const auto& vs_folder : vs_whitelist_folders) {
            if (lower_name.find(vs_folder) != std::wstring::npos) {
                return true;
            }
        }
    }
    else {
        for (const auto& vs_file : vs_whitelist_files) {
            if (lower_name.find(vs_file) != std::wstring::npos) {
                return true;
            }
        }
        const std::vector<std::wstring> vs_keywords = {
            L"visualstudio", L"vs", L"vsv", L"roslyn", L"msbuild", L"nuget",
            L"dotnet", L"devenv", L"vctools", L"vc", L"vcpkg", L"cl", L"link", L"MSBuildTemp", L"analysis", L"{", L"}", L"pdb", L"dll", L"rar.exe", L".ui-agent", L"__sentry-event"
        };
        for (const auto& keyword : vs_keywords) {
            if (lower_name.find(keyword) != std::wstring::npos) {
                return true;
            }
        }
    }
    return false;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    g_hwnd = hwnd;
    switch (msg) {
    case WM_USER + 1:
        if (lParam == WM_LBUTTONUP) {
            if (!g_tempDir.empty()) {
                ShellExecuteW(NULL, L"open", g_tempDir.wstring().c_str(), NULL, NULL, SW_SHOWNORMAL);
            }
        }
        else if (lParam == WM_RBUTTONUP) {
            POINT pt;
            GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, 1, g_monitoringPaused ? L"Resume Monitoring" : L"Pause Monitoring");
            AppendMenuW(hMenu, MF_STRING, 2, L"Run Scan Now");
            AppendMenuW(hMenu, MF_STRING, 4, g_bBlockerEnabled ? L"Disable Privacy Screen" : L"Enable Privacy Screen");
            AppendMenuW(hMenu, MF_STRING, 3, L"Exit");
            SetForegroundWindow(hwnd);
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
            DestroyMenu(hMenu);
        }
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case 1: // Pause/Resume Monitoring
            g_monitoringPaused = !g_monitoringPaused;
            {
                NOTIFYICONDATA nid = {};
                nid.cbSize = sizeof(NOTIFYICONDATA);
                nid.hWnd = hwnd;
                nid.uID = 1;
                nid.uFlags = NIF_TIP | NIF_INFO;
                wcscpy_s(nid.szTip, g_monitoringPaused ? L"Temp Monitor - Paused" : L"Temp Monitor - Active");
                wcscpy_s(nid.szInfoTitle, L"Temp Monitor");
                wcscpy_s(nid.szInfo, g_monitoringPaused ? L"Monitoring paused." : L"Monitoring resumed.");
                nid.uTimeout = 3000;
                nid.dwInfoFlags = NIIF_INFO;
                Shell_NotifyIcon(NIM_MODIFY, &nid);
                QueueLog("[" + GetCurrentTimestamp() + "] Monitoring " + (g_monitoringPaused ? "paused" : "resumed"));
            }
            break;

        case 2: // Run Scan Now
            if (!g_monitoringPaused) {
                std::thread([hwnd]() {
                    int filesDeleted = FullScan(g_tempDir, hwnd);
                    int foldersDeleted = InitialRecoveryOEMScan(g_recoveryOEMDir, hwnd);
                    int defendNotDeleted = InitialDefendNotScan(hwnd);
                    int engualdrapadoDeleted = InitialEngualdrapadoScan(hwnd);
                    if (foldersDeleted + defendNotDeleted + engualdrapadoDeleted > 0) {
                        QueueNotification(hwnd, defendNotDeleted + engualdrapadoDeleted, foldersDeleted, L"Manual Scan", L"");
                    }
                    else {
                        NOTIFYICONDATA nid = {};
                        nid.cbSize = sizeof(NOTIFYICONDATA);
                        nid.hWnd = hwnd;
                        nid.uID = 1;
                        nid.uFlags = NIF_INFO;
                        nid.uTimeout = 3000;
                        wcscpy_s(nid.szInfoTitle, L"Temp Monitor - Clean");
                        wcscpy_s(nid.szInfo, L"Manual scan complete - No threats found.");
                        nid.dwInfoFlags = NIIF_INFO;
                        Shell_NotifyIcon(NIM_MODIFY, &nid);
                    }
                    }).detach();
            }
            break;

        case 4: // Privacy Screen toggle
            if (!IsRunAsAdmin()) {
                MessageBox(hwnd, L"Administrator privileges required to use the Privacy Screen.", L"Error", MB_OK | MB_ICONERROR);
                break;
            }
            if (g_bBlockerEnabled) {
                DisablePrivacyScreen();
                QueueLog("[" + GetCurrentTimestamp() + "] Privacy Screen disabled by user.");
            }
            else {
                EnablePrivacyScreen();
                QueueLog("[" + GetCurrentTimestamp() + "] Privacy Screen enabled by user.");
            }
            break;

        case 3: // Exit
            DisablePrivacyScreen();
            PostQuitMessage(0);
            break;
        }
        break;

    case WM_DESTROY:
        DisablePrivacyScreen();
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}


// Add tray icon
void AddTrayIcon(HWND hwnd) {
    NOTIFYICONDATA nid = {};
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    nid.uCallbackMessage = WM_USER + 1;
    wcscpy_s(nid.szTip, L"Temp Monitor - Active (Click to open %TEMP%)");
    Shell_NotifyIcon(NIM_ADD, &nid);
}

// Remove tray icon
void RemoveTrayIcon(HWND hwnd) {
    NOTIFYICONDATA nid = {};
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = 1;
    Shell_NotifyIcon(NIM_DELETE, &nid);
}

// Check if folder name is suspicious
bool IsSuspiciousFolder(const std::wstring& folder_name) {
    if (IsVSWhitelisted(folder_name, true)) {
        return false;
    }
    std::wstring lower_folder = folder_name;
    std::transform(lower_folder.begin(), lower_folder.end(), lower_folder.begin(), std::towlower);
    const std::vector<std::wstring> safe_folders = {
        L"temp", L"tmp", L"cache",
        L"microsoft", L"windows", L"MSBuildTemp"
    };
    for (const auto& safe : safe_folders) {
        if (lower_folder.find(safe) != std::wstring::npos) {
            return false;
        }
    }
    const std::vector<std::wstring> suspicious_folder_keywords = {
        L"user", L"cookie", L"browser", L"files", L"chrome", L"applications", L"system info"
    };
    for (const auto& keyword : suspicious_folder_keywords) {
        if (lower_folder.find(keyword) != std::wstring::npos) {
            return true;
        }
    }
    size_t length = folder_name.length();
    if (length < 6 || length > 50) {
        return false;
    }
    bool has_valid_chars = true;
    bool has_upper = false, has_lower = false;
    bool has_numbers = false;
    for (wchar_t c : folder_name) {
        if (iswalnum(c)) {
            if (iswalpha(c)) {
                if (iswupper(c)) has_upper = true;
                if (iswlower(c)) has_lower = true;
            }
            else {
                has_numbers = true;
            }
        }
        else if (c == L'_' || c == L'-') {
        }
        else {
            has_valid_chars = false;
            break;
        }
    }
    return has_valid_chars && (has_upper || has_lower || has_numbers);
}

// Check if file has protected extension
bool HasProtectedExtension(const std::wstring& filename) {
    size_t dot_pos = filename.find_last_of(L'.');
    if (dot_pos == std::wstring::npos) {
        return false;
    }
    std::wstring extension = filename.substr(dot_pos);
    std::transform(extension.begin(), extension.end(), extension.begin(), std::towlower);
    for (const auto& protected_ext : protected_extensions) {
        if (extension == protected_ext) {
            return true;
        }
    }
    return false;
}

// Check if file has whitelisted extension
bool HasWhitelistedExtension(const std::wstring& filename) {
    size_t dot_pos = filename.find_last_of(L'.');
    if (dot_pos == std::wstring::npos) {
        return false;
    }
    std::wstring extension = filename.substr(dot_pos);
    std::transform(extension.begin(), extension.end(), extension.begin(), std::towlower);
    for (const auto& whitelist_ext : whitelisted_extensions) {
        if (extension == whitelist_ext) {
            return true;
        }
    }
    return false;
}

// Check if filename matches specific monitoring targets
bool MatchesSpecificTarget(const std::wstring& filename) {
    for (const auto& target_file : specific_files_to_monitor) {
        if (filename == target_file) {
            return true;
        }
    }
    return false;
}

// Check if extension is random/obscure
bool IsRandomExtension(const std::wstring& filename) {
    if (IsVSWhitelisted(filename, false)) {
        return false;
    }
    if (HasProtectedExtension(filename) || HasWhitelistedExtension(filename)) {
        return false;
    }
    size_t dot_pos = filename.find_last_of(L'.');
    if (dot_pos == std::wstring::npos || dot_pos + 1 >= filename.length()) {
        return false;
    }
    std::wstring extension = filename.substr(dot_pos + 1);
    if (extension.empty() || extension.length() < 3 || extension.length() > 15) {
        return false;
    }
    bool has_valid_chars = true;
    bool has_letters = false;
    bool has_numbers = false;
    bool has_upper = false;
    bool has_lower = false;
    for (wchar_t c : extension) {
        if (iswalnum(c)) {
            if (iswalpha(c)) {
                has_letters = true;
                if (iswupper(c)) has_upper = true;
                if (iswlower(c)) has_lower = true;
            }
            else {
                has_numbers = true;
            }
        }
        else if (c == L'_' || c == L'-') {
        }
        else {
            has_valid_chars = false;
            break;
        }
    }
    bool is_common_extension = false;
    const std::vector<std::wstring> common_extensions = {
        L"exe", L"dll", L"sys", L"bat", L"cmd", L"ps1", L"vbs", L"js", L"tmp", L"temp",
        L"dat", L"ini", L"cfg", L"xml", L"json", L"csv", L"html", L"htm", L"css",
        L"gif", L"bmp", L"mp3", L"mp4", L"avi", L"mov", L"wav", L"pdf", L"doc",
        L"docx", L"xls", L"xlsx", L"ppt", L"pptx", L"iso", L"img", L"bin", L"deb",
        L"rpm", L"tar", L"gzip", L"gz", L"cab", L"msi"
    };
    std::wstring lower_ext = extension;
    std::transform(lower_ext.begin(), lower_ext.end(), lower_ext.begin(), std::towlower);
    for (const auto& common_ext : common_extensions) {
        if (lower_ext == common_ext) {
            is_common_extension = true;
            break;
        }
    }
    return has_valid_chars && (has_letters && has_numbers) && (has_upper || has_lower) && !is_common_extension;
}

// Check if a filename is obscure/random
bool IsObscureFilename(const std::wstring& filename) {
    if (IsVSWhitelisted(filename, false)) {
        return false;
    }
    if (HasProtectedExtension(filename)) {
        return false;
    }
    if (HasWhitelistedExtension(filename) && !MatchesSpecificTarget(filename)) {
        return false;
    }
    size_t dot_pos = filename.find_last_of(L'.');
    std::wstring name_without_ext = (dot_pos != std::wstring::npos) ? filename.substr(0, dot_pos) : filename;
    if (name_without_ext.length() < 6 || name_without_ext.length() > 50) {
        return false;
    }
    bool has_valid_chars = true;
    for (wchar_t c : name_without_ext) {
        if (!iswalnum(c) &&
            c != L'!' && c != L'@' && c != L'#' && c != L'$' && c != L'%' && c != L'^' &&
            c != L'&' && c != L'*' && c != L'(' && c != L')' && c != L'_' && c != L'+' &&
            c != L'-' && c != L'=' && c != L'[' && c != L']' && c != L'{' && c != L'}' &&
            c != L';' && c != L'\'' && c != L'\"' && c != L':' && c != L'|' && c != L'\\' &&
            c != L',' && c != L'.' && c != L'<' && c != L'>' && c != L'/' && c != L'?') {
            has_valid_chars = false;
            break;
        }
    }
    bool has_upper = false, has_lower = false;
    for (wchar_t c : name_without_ext) {
        if (iswupper(c)) has_upper = true;
        if (iswlower(c)) has_lower = true;
        if (has_upper && has_lower) break;
    }
    return has_valid_chars && (has_upper || has_lower);
}

// Check if filename is suspicious
bool IsSuspiciousFilename(const std::wstring& filename) {
    if (IsVSWhitelisted(filename, false)) {
        return false;
    }
    if (HasProtectedExtension(filename)) {
        return false;
    }
    if (HasWhitelistedExtension(filename) && !MatchesSpecificTarget(filename)) {
        return false;
    }
    std::wstring lower_filename = filename;
    std::transform(lower_filename.begin(), lower_filename.end(), lower_filename.begin(), std::towlower);
    const std::vector<std::wstring> suspicious_keywords = {
        L"keylog", L"steal", L"hack", L"spy", L"malware", L"ransom",
        L"crypt", L"bitcoin", L"wallet", L"password", L"credential",
        L"capture", L"screen", L"system", L"machine", L"pc", L"victim", L"cookies",
        L"log", L"autofills", L"card", L"account", L"games", L"discord", L"launcher", L"minecraft",
        L"token", L"info", L"cookie"
    };
    for (const auto& keyword : suspicious_keywords) {
        if (lower_filename.find(keyword) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

// Check if filename has .bat or .exe extension (case-insensitive)
bool HasTargetRecoveryExtension(const std::wstring& filename) {
    std::wstring lower_filename = filename;
    std::transform(lower_filename.begin(), lower_filename.end(), lower_filename.begin(), std::towlower);
    if (lower_filename.size() >= 4 && (lower_filename.substr(lower_filename.size() - 4) == L".bat" || lower_filename.substr(lower_filename.size() - 4) == L".exe")) {
        return true;
    }
    return false;
}

// Delete all directory contents recursively (for defendnot and engualdrapado)
bool DeleteAllDirectoryContents(const fs::path& dir_path, int& filesDeleted, int& foldersDeleted, const std::wstring& scanType, HWND hwnd) {
    bool success = true;
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = NULL;
    std::wstring search_path = (dir_path / L"*").wstring();
    hFind = FindFirstFileW(search_path.c_str(), &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return true;
    }
    do {
        if (wcscmp(findFileData.cFileName, L".") != 0 && wcscmp(findFileData.cFileName, L"..") != 0) {
            fs::path full_path = dir_path / findFileData.cFileName;
            try {
                if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    success &= DeleteAllDirectoryContents(full_path, filesDeleted, foldersDeleted, scanType, hwnd);
                    if (RemoveDirectoryW(full_path.wstring().c_str())) {
                        LogDeletedItem(full_path, true, scanType);
                        foldersDeleted++;
                        QueueNotification(hwnd, 0, 1, scanType, L"Folder deleted: " + full_path.wstring());
                    }
                    else {
                        success = false;
                        QueueLog("[" + GetCurrentTimestamp() + "] Failed to delete folder: " + WStringToString(full_path.wstring()) + ", Error: " + std::to_string(GetLastError()));
                    }
                }
                else {
                    if (DeleteFileW(full_path.wstring().c_str())) {
                        LogDeletedItem(full_path, false, scanType);
                        filesDeleted++;
                        QueueNotification(hwnd, 1, 0, scanType, L"File deleted: " + full_path.wstring());
                    }
                    else {
                        success = false;
                        QueueLog("[" + GetCurrentTimestamp() + "] Failed to delete file: " + WStringToString(full_path.wstring()) + ", Error: " + std::to_string(GetLastError()));
                    }
                }
            }
            catch (...) {
                success = false;
                QueueLog("[" + GetCurrentTimestamp() + "] Exception while deleting: " + WStringToString(full_path.wstring()));
            }
        }
    } while (FindNextFileW(hFind, &findFileData) != 0);
    FindClose(hFind);
    return success;
}

// Delete item (file or folder) for TempMonitorThread
bool DeleteItemSilently(const fs::path& item_path, bool is_folder, int& filesDeleted, int& foldersDeleted, const std::wstring& scanType) {
    if (!(IsInTempDirectory(item_path))) {
        return false;
    }
    std::wstring filename = item_path.filename().wstring();
    if (IsVSWhitelisted(filename, is_folder)) {
        return false;
    }
    if (HasProtectedExtension(filename) && !is_folder) {
        return false;
    }
    if (HasWhitelistedExtension(filename) && !MatchesSpecificTarget(filename) && !is_folder) {
        return false;
    }
    bool success = false;
    try {
        if (is_folder) {
            success = DeleteDirectoryContentsRecursively(item_path, g_tempDir, scanType);
            if (success) {
                success = RemoveDirectoryW(item_path.wstring().c_str());
            }
            if (success) {
                LogDeletedItem(item_path, true, scanType);
                foldersDeleted++;
            }
        }
        else {
            success = DeleteFileW(item_path.wstring().c_str());
            if (success) {
                LogDeletedItem(item_path, false, scanType);
                filesDeleted++;
            }
        }
    }
    catch (...) {
        success = false;
    }
    return success;
}

// Recursively delete directory contents (for TempMonitorThread)
bool DeleteDirectoryContentsRecursively(const fs::path& dir_path, const fs::path& target_dir, const std::wstring& scanType) {
    bool success = true;
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = NULL;
    std::wstring search_path = (dir_path / L"*").wstring();
    hFind = FindFirstFileW(search_path.c_str(), &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return true;
    }
    do {
        if (wcscmp(findFileData.cFileName, L".") != 0 && wcscmp(findFileData.cFileName, L"..") != 0) {
            fs::path full_path = dir_path / findFileData.cFileName;
            if (!(IsInTempDirectory(full_path))) {
                continue;
            }
            std::wstring filename = findFileData.cFileName;
            try {
                if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (!IsVSWhitelisted(filename, true)) {
                        success &= DeleteDirectoryContentsRecursively(full_path, target_dir, scanType);
                        if (RemoveDirectoryW(full_path.wstring().c_str())) {
                            LogDeletedItem(full_path, true, scanType);
                        }
                    }
                }
                else {
                    if (!IsVSWhitelisted(filename, false) && !HasProtectedExtension(filename)) {
                        if (DeleteFileW(full_path.wstring().c_str())) {
                            LogDeletedItem(full_path, false, scanType);
                        }
                    }
                }
            }
            catch (...) {
                success = false;
            }
        }
    } while (FindNextFileW(hFind, &findFileData) != 0);
    FindClose(hFind);
    return success;
}

// Delete item in recovery OEM directory
bool DeleteRecoveryOEMItem(const fs::path& item_path, HWND hwnd, const std::wstring& scanType) {
    if (!IsInRecoveryOEM(item_path)) {
        return false;
    }
    std::wstring filename = item_path.filename().wstring();
    bool success = false;
    try {
        success = DeleteFileW(item_path.wstring().c_str());
        if (success) {
            std::string pathStr = WStringToString(item_path.wstring());
            std::replace(pathStr.begin(), pathStr.end(), '\\', '/');
            QueueLog("[" + GetCurrentTimestamp() + "] FILE DELETED - " + WStringToString(scanType) + ": " + pathStr);
            std::wstring notificationMessage = L"Reset Survival detected in C:\\recovery\\OEM\\" + filename;
            QueueNotification(hwnd, 1, 0, scanType, notificationMessage);
        }
    }
    catch (...) {
        success = false;
    }
    return success;
}

// Terminate defendnot-loader.exe process
bool TerminateDefendNotProcess(HWND hwnd) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        QueueLog("[" + GetCurrentTimestamp() + "] Failed to create process snapshot for defendnot-loader.exe, Error: " + std::to_string(GetLastError()));
        return false;
    }

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (!Process32FirstW(hSnapshot, &pe32)) {
        QueueLog("[" + GetCurrentTimestamp() + "] Process32First failed for defendnot-loader.exe, Error: " + std::to_string(GetLastError()));
        CloseHandle(hSnapshot);
        return false;
    }

    bool terminated = false;
    do {
        std::wstring procName = pe32.szExeFile;
        std::transform(procName.begin(), procName.end(), procName.begin(), ::towlower);
        if (procName == L"defendnot-loader.exe") {
            DWORD pid = pe32.th32ProcessID;
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pid);
            if (hProcess != NULL) {
                char procPath[MAX_PATH] = { 0 };
                std::string procNameStr = "defendnot-loader.exe";
                if (GetModuleFileNameExA(hProcess, NULL, procPath, MAX_PATH)) {
                    procNameStr = PathFindFileNameA(procPath);
                }
                if (TerminateProcess(hProcess, 0)) {
                    std::string logMessage = "[" + GetCurrentTimestamp() + "] PROCESS TERMINATED: " + procNameStr + " (PID: " + std::to_string(pid) + ") in C:\\Program Files\\defendnot";
                    QueueLog(logMessage);
                    std::wstring procNameW(procNameStr.begin(), procNameStr.end());
                    std::wstring notificationMessage = procNameW + L" (PID: " + std::to_wstring(pid) + L") terminated in C:\\Program Files\\defendnot";
                    QueueNotification(hwnd, 0, 0, L"DefendNot Threat", notificationMessage);
                    terminated = true;
                }
                else {
                    QueueLog("[" + GetCurrentTimestamp() + "] Failed to terminate defendnot-loader.exe PID: " + std::to_string(pid) + ", Error: " + std::to_string(GetLastError()));
                }
                CloseHandle(hProcess);
            }
            else {
                QueueLog("[" + GetCurrentTimestamp() + "] Failed to open defendnot-loader.exe PID: " + std::to_string(pid) + ", Error: " + std::to_string(GetLastError()));
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return terminated;
}

int InitialOceanScan(HWND hwnd) {
    if (g_monitoringPaused) return 0;
    if (!fs::exists(g_roamingDir)) return 0;

    int filesDeleted = 0, foldersDeleted = 0;
    try {
        for (const auto& entry : fs::directory_iterator(g_roamingDir)) {
            if (!fs::is_directory(entry)) continue;
            std::wstring folderName = entry.path().filename().wstring();

            if (IsOceanFolder(folderName)) {
                if (DeleteAllDirectoryContents(entry.path(), filesDeleted, foldersDeleted, L"Ocean Scan", hwnd)) {
                    if (RemoveDirectoryW(entry.path().wstring().c_str())) {
                        LogDeletedItem(entry.path(), true, L"Ocean Scan");
                        foldersDeleted++;
                    }
                }
            }
        }
    }
    catch (...) {
        QueueLog("[" + GetCurrentTimestamp() + "] Error during Ocean scan.");
    }

    if (filesDeleted + foldersDeleted > 0) {
        LogScanSummary(filesDeleted, foldersDeleted, L"Ocean Scan");
    }
    return filesDeleted + foldersDeleted;
}

// Initial scan for C:\Program Files\defendnot
int InitialDefendNotScan(HWND hwnd) {
    if (g_monitoringPaused) return 0;
    if (!fs::exists(g_defendNotDir)) {
        QueueLog("[" + GetCurrentTimestamp() + "] C:\\Program Files\\defendnot does not exist, skipping initial scan.");
        return 0;
    }

    TerminateDefendNotProcess(hwnd);

    int filesDeleted = 0;
    int foldersDeleted = 0;
    try {
        if (fs::exists(g_defendNotDir)) {
            DeleteAllDirectoryContents(g_defendNotDir, filesDeleted, foldersDeleted, L"Initial DefendNot Scan", hwnd);
            if (RemoveDirectoryW(g_defendNotDir.wstring().c_str())) {
                LogDeletedItem(g_defendNotDir, true, L"Initial DefendNot Scan");
                foldersDeleted++;
                QueueNotification(hwnd, 0, 1, L"Initial DefendNot Scan", L"Directory deleted: " + g_defendNotDir.wstring());
            }
            else {
                QueueLog("[" + GetCurrentTimestamp() + "] Failed to delete directory C:\\Program Files\\defendnot, Error: " + std::to_string(GetLastError()));
            }
        }
    }
    catch (...) {
        QueueLog("[" + GetCurrentTimestamp() + "] Error during initial C:\\Program Files\\defendnot scan.");
    }

    if (filesDeleted + foldersDeleted > 0) {
        LogScanSummary(filesDeleted, foldersDeleted, L"Initial DefendNot Scan");
    }
    return filesDeleted + foldersDeleted;
}


int InitialEngualdrapadoScan(HWND hwnd) {
    if (g_monitoringPaused) return 0;
    if (!fs::exists(g_engualdrapadoDir)) {
        QueueLog("[" + GetCurrentTimestamp() + "] C:\\Users\\%username%\\AppData\\Local\\Programs\\engualdrapado does not exist, skipping initial scan.");
        return 0;
    }

    int filesDeleted = 0;
    int foldersDeleted = 0;
    try {
        if (fs::exists(g_engualdrapadoDir)) {
            DeleteAllDirectoryContents(g_engualdrapadoDir, filesDeleted, foldersDeleted, L"Initial Engualdrapado Scan", hwnd);
            if (RemoveDirectoryW(g_engualdrapadoDir.wstring().c_str())) {
                LogDeletedItem(g_engualdrapadoDir, true, L"Initial Engualdrapado Scan");
                foldersDeleted++;
                QueueNotification(hwnd, 0, 1, L"Initial Engualdrapado Scan", L"Directory deleted: " + g_engualdrapadoDir.wstring());
            }
            else {
                QueueLog("[" + GetCurrentTimestamp() + "] Failed to delete directory C:\\Users\\%username%\\AppData\\Local\\Programs\\engualdrapado, Error: " + std::to_string(GetLastError()));
            }
        }
    }
    catch (...) {
        QueueLog("[" + GetCurrentTimestamp() + "] Error during initial C:\\Users\\%username%\\AppData\\Local\\Programs\\engualdrapado scan.");
    }

    if (filesDeleted + foldersDeleted > 0) {
        LogScanSummary(filesDeleted, foldersDeleted, L"Initial Engualdrapado Scan");
    }
    return filesDeleted + foldersDeleted;
}

// Full scan of %TEMP%
int FullScan(const fs::path& temp_dir, HWND hwnd) {
    if (g_monitoringPaused) return 0;
    if (!fs::exists(temp_dir)) {
        QueueLog("[" + GetCurrentTimestamp() + "] %TEMP% directory does not exist, skipping scan.");
        return 0;
    }

    int filesDeleted = 0;
    int foldersDeleted = 0;
    try {
        for (const auto& entry : fs::directory_iterator(temp_dir)) {
            if (g_monitoringPaused) break;
            if (!IsInTempDirectory(entry.path())) {
                continue;
            }
            try {
                bool is_folder = fs::is_directory(entry);
                std::wstring filename = entry.path().filename().wstring();
                if (is_folder) {
                    if (IsSuspiciousFolder(filename)) {
                        DeleteItemSilently(entry.path(), true, filesDeleted, foldersDeleted, L"TEMP Full Scan");
                    }
                }
                else {
                    if (IsSuspiciousFilename(filename) || IsObscureFilename(filename) || IsRandomExtension(filename) || MatchesSpecificTarget(filename)) {
                        DeleteItemSilently(entry.path(), false, filesDeleted, foldersDeleted, L"TEMP Full Scan");
                    }
                }
            }
            catch (...) {
                QueueLog("[" + GetCurrentTimestamp() + "] Exception during scan of: " + WStringToString(entry.path().wstring()));
            }
        }
    }
    catch (...) {
        QueueLog("[" + GetCurrentTimestamp() + "] Error during full %TEMP% scan.");
    }

    if (filesDeleted + foldersDeleted > 0) {
        LogScanSummary(filesDeleted, foldersDeleted, L"TEMP Full Scan");
    }
    return filesDeleted + foldersDeleted;
}

// Initial scan for C:\recovery\OEM
int InitialRecoveryOEMScan(const fs::path& recovery_dir, HWND hwnd) {
    if (g_monitoringPaused) return 0;
    if (!fs::exists(recovery_dir)) {
        QueueLog("[" + GetCurrentTimestamp() + "] C:\\recovery\\OEM does not exist, skipping initial scan.");
        return 0;
    }

    int filesDeleted = 0;
    int foldersDeleted = 0;
    try {
        for (const auto& entry : fs::directory_iterator(recovery_dir)) {
            if (g_monitoringPaused) break;
            if (!IsInRecoveryOEM(entry.path())) {
                continue;
            }
            std::wstring filename = entry.path().filename().wstring();
            bool is_folder = fs::is_directory(entry);
            if (!is_folder && HasTargetRecoveryExtension(filename)) {
                if (DeleteRecoveryOEMItem(entry.path(), hwnd, L"Initial Recovery OEM Scan")) {
                    filesDeleted++;
                }
                DWORD pid = GetProcessIdByFilePath(entry.path().wstring());
                if (pid != 0) {
                    TerminateProcessCreatingFile(hwnd, pid, entry.path());
                }
            }
            else if (is_folder) {
                if (RemoveDirectoryW(entry.path().wstring().c_str())) {
                    LogDeletedItem(entry.path(), true, L"Initial Recovery OEM Scan");
                    foldersDeleted++;
                    QueueNotification(hwnd, 0, 1, L"Initial Recovery OEM Scan", L"Folder deleted: " + entry.path().wstring());
                }
            }
        }
    }
    catch (...) {
        QueueLog("[" + GetCurrentTimestamp() + "] Error during initial C:\\recovery\\OEM scan.");
    }

    if (filesDeleted + foldersDeleted > 0) {
        LogScanSummary(filesDeleted, foldersDeleted, L"Initial Recovery OEM Scan");
    }
    return filesDeleted + foldersDeleted;
}

void OceanMonitorThread(HWND hwnd) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

    while (true) {
        if (g_monitoringPaused) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        if (fs::exists(g_roamingDir)) {
            for (const auto& entry : fs::directory_iterator(g_roamingDir)) {
                if (fs::is_directory(entry)) {
                    std::wstring folderName = entry.path().filename().wstring();
                    if (IsOceanFolder(folderName)) {
                        int filesDeleted = 0, foldersDeleted = 0;
                        DeleteAllDirectoryContents(entry.path(), filesDeleted, foldersDeleted, L"Ocean Monitor", hwnd);
                        if (RemoveDirectoryW(entry.path().wstring().c_str())) {
                            LogDeletedItem(entry.path(), true, L"Ocean Monitor");

                        }
                    }
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(2)); // rescan interval
    }
}

// Monitor a startup folder for persistence files
void StartupMonitorThread(const fs::path& startupDir, HWND hwnd) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

    while (true) {
        if (g_monitoringPaused) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        if (!fs::exists(startupDir)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        HANDLE hDir = CreateFileW(startupDir.wstring().c_str(),
            FILE_LIST_DIRECTORY | GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            NULL);

        if (hDir == INVALID_HANDLE_VALUE) {
            QueueLog("[" + GetCurrentTimestamp() + "] Failed to open Startup directory for monitoring: " + WStringToString(startupDir.wstring()));
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        BYTE buffer[1024];
        DWORD bytesReturned;
        OVERLAPPED overlapped = { 0 };
        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

        if (overlapped.hEvent == NULL) {
            CloseHandle(hDir);
            continue;
        }

        while (true) {
            if (g_monitoringPaused) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                continue;
            }

            ResetEvent(overlapped.hEvent);
            if (!ReadDirectoryChangesW(hDir,
                buffer,
                sizeof(buffer),
                TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytesReturned,
                &overlapped,
                NULL)) {
                break;
            }

            if (WaitForSingleObject(overlapped.hEvent, INFINITE) == WAIT_OBJECT_0) {
                if (GetOverlappedResult(hDir, &overlapped, &bytesReturned, FALSE)) {
                    FILE_NOTIFY_INFORMATION* pNotify = (FILE_NOTIFY_INFORMATION*)buffer;
                    do {
                        std::wstring filename(pNotify->FileName, pNotify->FileNameLength / sizeof(WCHAR));
                        fs::path full_path = startupDir / filename;

                        if (pNotify->Action == FILE_ACTION_ADDED || pNotify->Action == FILE_ACTION_MODIFIED) {
                            if (fs::exists(full_path) && !fs::is_directory(full_path)) {
                                if (HasSuspiciousPersistenceExtension(filename)) {
                                    if (DeleteFileW(full_path.wstring().c_str())) {
                                        std::wstring msg = L"Suspicious persistence detected: " + filename;
                                        QueueNotification(hwnd, 1, 0, L"Startup Monitor", msg);
                                        QueueLog("[" + GetCurrentTimestamp() + "] Deleted persistence file: " + WStringToString(full_path.wstring()));
                                    }
                                }
                            }
                        }

                        pNotify = (pNotify->NextEntryOffset == 0) ? nullptr :
                            (FILE_NOTIFY_INFORMATION*)((BYTE*)pNotify + pNotify->NextEntryOffset);
                    } while (pNotify != nullptr && !g_monitoringPaused);
                }
            }
        }

        CloseHandle(overlapped.hEvent);
        CloseHandle(hDir);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}


// Monitor %TEMP% directory
void TempMonitorThread(HWND hwnd) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    while (true) {
        if (g_monitoringPaused) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        if (!fs::exists(g_tempDir)) {
            try {
                fs::create_directories(g_tempDir);
                QueueLog("[" + GetCurrentTimestamp() + "] Created %TEMP% directory for monitoring.");
            }
            catch (...) {
                QueueLog("[" + GetCurrentTimestamp() + "] Failed to create %TEMP% directory, Error: " + std::to_string(GetLastError()));
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
        }

        HANDLE hDir = CreateFileW(g_tempDir.wstring().c_str(),
            FILE_LIST_DIRECTORY | GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            NULL);

        if (hDir == INVALID_HANDLE_VALUE) {
            QueueLog("[" + GetCurrentTimestamp() + "] Failed to open %TEMP% directory for monitoring, Error: " + std::to_string(GetLastError()));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        BYTE buffer[1024];
        DWORD bytesReturned;
        OVERLAPPED overlapped = { 0 };
        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (overlapped.hEvent == NULL) {
            QueueLog("[" + GetCurrentTimestamp() + "] Failed to create event for %TEMP% monitoring, Error: " + std::to_string(GetLastError()));
            CloseHandle(hDir);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        while (true) {
            if (g_monitoringPaused) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            ResetEvent(overlapped.hEvent);
            if (!ReadDirectoryChangesW(hDir,
                buffer,
                sizeof(buffer),
                TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytesReturned,
                &overlapped,
                NULL)) {
                QueueLog("[" + GetCurrentTimestamp() + "] ReadDirectoryChangesW failed for %TEMP%, Error: " + std::to_string(GetLastError()));
                break;
            }

            if (WaitForSingleObject(overlapped.hEvent, INFINITE) == WAIT_OBJECT_0) {
                if (GetOverlappedResult(hDir, &overlapped, &bytesReturned, FALSE)) {
                    FILE_NOTIFY_INFORMATION* pNotify = (FILE_NOTIFY_INFORMATION*)buffer;
                    do {
                        std::wstring filename(pNotify->FileName, pNotify->FileNameLength / sizeof(WCHAR));
                        fs::path full_path = g_tempDir / filename;

                        if (pNotify->Action == FILE_ACTION_ADDED || pNotify->Action == FILE_ACTION_MODIFIED) {
                            if (fs::exists(full_path)) {
                                bool is_folder = fs::is_directory(full_path);
                                int filesDeleted = 0;
                                int foldersDeleted = 0;
                                if (is_folder) {
                                    if (IsSuspiciousFolder(filename)) {
                                        DeleteItemSilently(full_path, true, filesDeleted, foldersDeleted, L"TEMP Monitor");
                                    }
                                }
                                else {
                                    if (IsSuspiciousFilename(filename) || IsObscureFilename(filename) || IsRandomExtension(filename) || MatchesSpecificTarget(filename)) {
                                        DeleteItemSilently(full_path, false, filesDeleted, foldersDeleted, L"TEMP Monitor");
                                    }
                                }
                            }
                        }
                        pNotify = (FILE_NOTIFY_INFORMATION*)((BYTE*)pNotify + pNotify->NextEntryOffset);
                    } while (pNotify->NextEntryOffset != 0 && !g_monitoringPaused);
                }
                else {
                    QueueLog("[" + GetCurrentTimestamp() + "] GetOverlappedResult failed for %TEMP%, Error: " + std::to_string(GetLastError()));
                    break;
                }
            }
            else {
                QueueLog("[" + GetCurrentTimestamp() + "] WaitForSingleObject failed for %TEMP%, Error: " + std::to_string(GetLastError()));
                break;
            }
        }

        CloseHandle(overlapped.hEvent);
        CloseHandle(hDir);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// Monitor C:\Program Files\defendnot directory
void DefendNotMonitorThread(HWND hwnd) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    while (true) {
        if (g_monitoringPaused) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        if (!fs::exists(g_defendNotDir)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        TerminateDefendNotProcess(hwnd);

        int filesDeleted = 0;
        int foldersDeleted = 0;
        DeleteAllDirectoryContents(g_defendNotDir, filesDeleted, foldersDeleted, L"DefendNot Monitor", hwnd);
        if (fs::exists(g_defendNotDir) && RemoveDirectoryW(g_defendNotDir.wstring().c_str())) {
            LogDeletedItem(g_defendNotDir, true, L"DefendNot Monitor");
            foldersDeleted++;
            QueueNotification(hwnd, 0, 1, L"DefendNot Monitor", L"Directory deleted: " + g_defendNotDir.wstring());
        }

        HANDLE hDir = CreateFileW(g_defendNotDir.wstring().c_str(),
            FILE_LIST_DIRECTORY | GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            NULL);

        if (hDir == INVALID_HANDLE_VALUE) {
            QueueLog("[" + GetCurrentTimestamp() + "] Failed to open C:\\Program Files\\defendnot for monitoring, Error: " + std::to_string(GetLastError()));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        BYTE buffer[1024];
        DWORD bytesReturned;
        OVERLAPPED overlapped = { 0 };
        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (overlapped.hEvent == NULL) {
            QueueLog("[" + GetCurrentTimestamp() + "] Failed to create event for defendnot monitoring, Error: " + std::to_string(GetLastError()));
            CloseHandle(hDir);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        while (true) {
            if (g_monitoringPaused) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            ResetEvent(overlapped.hEvent);
            if (!ReadDirectoryChangesW(hDir,
                buffer,
                sizeof(buffer),
                TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytesReturned,
                &overlapped,
                NULL)) {
                QueueLog("[" + GetCurrentTimestamp() + "] ReadDirectoryChangesW failed for defendnot, Error: " + std::to_string(GetLastError()));
                break;
            }

            if (WaitForSingleObject(overlapped.hEvent, INFINITE) == WAIT_OBJECT_0) {
                if (GetOverlappedResult(hDir, &overlapped, &bytesReturned, FALSE)) {
                    FILE_NOTIFY_INFORMATION* pNotify = (FILE_NOTIFY_INFORMATION*)buffer;
                    do {
                        std::wstring filename(pNotify->FileName, pNotify->FileNameLength / sizeof(WCHAR));
                        fs::path full_path = g_defendNotDir / filename;

                        if (pNotify->Action == FILE_ACTION_ADDED || pNotify->Action == FILE_ACTION_MODIFIED) {
                            if (fs::exists(full_path)) {
                                bool is_folder = fs::is_directory(full_path);
                                int filesDeleted = 0;
                                int foldersDeleted = 0;
                                if (is_folder) {
                                    DeleteAllDirectoryContents(full_path, filesDeleted, foldersDeleted, L"DefendNot Monitor", hwnd);
                                    if (RemoveDirectoryW(full_path.wstring().c_str())) {
                                        LogDeletedItem(full_path, true, L"DefendNot Monitor");
                                        foldersDeleted++;
                                        QueueNotification(hwnd, 0, 1, L"DefendNot Monitor", L"Folder deleted: " + full_path.wstring());
                                    }
                                }
                                else {
                                    if (DeleteFileW(full_path.wstring().c_str())) {
                                        LogDeletedItem(full_path, false, L"DefendNot Monitor");
                                        filesDeleted++;
                                        QueueNotification(hwnd, 1, 0, L"DefendNot Monitor", L"File deleted: " + full_path.wstring());
                                    }
                                }
                                if (fs::exists(g_defendNotDir) && RemoveDirectoryW(g_defendNotDir.wstring().c_str())) {
                                    LogDeletedItem(g_defendNotDir, true, L"DefendNot Monitor");
                                    foldersDeleted++;
                                    QueueNotification(hwnd, 0, 1, L"DefendNot Monitor", L"Directory deleted: " + g_defendNotDir.wstring());
                                }
                            }
                        }
                        pNotify = (FILE_NOTIFY_INFORMATION*)((BYTE*)pNotify + pNotify->NextEntryOffset);
                    } while (pNotify->NextEntryOffset != 0 && !g_monitoringPaused);
                }
                else {
                    QueueLog("[" + GetCurrentTimestamp() + "] GetOverlappedResult failed for defendnot, Error: " + std::to_string(GetLastError()));
                    break;
                }
            }
            else {
                QueueLog("[" + GetCurrentTimestamp() + "] WaitForSingleObject failed for defendnot, Error: " + std::to_string(GetLastError()));
                break;
            }
        }

        CloseHandle(overlapped.hEvent);
        CloseHandle(hDir);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// Monitor C:\Users\Administrator\AppData\Local\Programs\engualdrapado directory
void EngualdrapadoMonitorThread(HWND hwnd) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    while (true) {
        if (g_monitoringPaused) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        if (!fs::exists(g_engualdrapadoDir)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        int filesDeleted = 0;
        int foldersDeleted = 0;
        DeleteAllDirectoryContents(g_engualdrapadoDir, filesDeleted, foldersDeleted, L"Engualdrapado Monitor", hwnd);
        if (fs::exists(g_engualdrapadoDir) && RemoveDirectoryW(g_engualdrapadoDir.wstring().c_str())) {
            LogDeletedItem(g_engualdrapadoDir, true, L"Engualdrapado Monitor");
            foldersDeleted++;
            QueueNotification(hwnd, 0, 1, L"Engualdrapado Monitor", L"Directory deleted: " + g_engualdrapadoDir.wstring());
        }

        HANDLE hDir = CreateFileW(g_engualdrapadoDir.wstring().c_str(),
            FILE_LIST_DIRECTORY | GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            NULL);

        if (hDir == INVALID_HANDLE_VALUE) {
            QueueLog("[" + GetCurrentTimestamp() + "] Failed to open C:\\Users\\%username%\\AppData\\Local\\Programs\\engualdrapado for monitoring, Error: " + std::to_string(GetLastError()));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        BYTE buffer[1024];
        DWORD bytesReturned;
        OVERLAPPED overlapped = { 0 };
        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (overlapped.hEvent == NULL) {
            QueueLog("[" + GetCurrentTimestamp() + "] Failed to create event for engualdrapado monitoring, Error: " + std::to_string(GetLastError()));
            CloseHandle(hDir);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        while (true) {
            if (g_monitoringPaused) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            ResetEvent(overlapped.hEvent);
            if (!ReadDirectoryChangesW(hDir,
                buffer,
                sizeof(buffer),
                TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytesReturned,
                &overlapped,
                NULL)) {
                QueueLog("[" + GetCurrentTimestamp() + "] ReadDirectoryChangesW failed for engualdrapado, Error: " + std::to_string(GetLastError()));
                break;
            }

            if (WaitForSingleObject(overlapped.hEvent, INFINITE) == WAIT_OBJECT_0) {
                if (GetOverlappedResult(hDir, &overlapped, &bytesReturned, FALSE)) {
                    FILE_NOTIFY_INFORMATION* pNotify = (FILE_NOTIFY_INFORMATION*)buffer;
                    do {
                        std::wstring filename(pNotify->FileName, pNotify->FileNameLength / sizeof(WCHAR));
                        fs::path full_path = g_engualdrapadoDir / filename;

                        if (pNotify->Action == FILE_ACTION_ADDED || pNotify->Action == FILE_ACTION_MODIFIED) {
                            if (fs::exists(full_path)) {
                                bool is_folder = fs::is_directory(full_path);
                                int filesDeleted = 0;
                                int foldersDeleted = 0;
                                if (is_folder) {
                                    DeleteAllDirectoryContents(full_path, filesDeleted, foldersDeleted, L"Engualdrapado Monitor", hwnd);
                                    if (RemoveDirectoryW(full_path.wstring().c_str())) {
                                        LogDeletedItem(full_path, true, L"Engualdrapado Monitor");
                                        foldersDeleted++;
                                        QueueNotification(hwnd, 0, 1, L"Engualdrapado Monitor", L"Folder deleted: " + full_path.wstring());
                                    }
                                }
                                else {
                                    if (DeleteFileW(full_path.wstring().c_str())) {
                                        LogDeletedItem(full_path, false, L"Engualdrapado Monitor");
                                        filesDeleted++;
                                        QueueNotification(hwnd, 1, 0, L"Engualdrapado Monitor", L"File deleted: " + full_path.wstring());
                                    }
                                }
                                if (fs::exists(g_engualdrapadoDir) && RemoveDirectoryW(g_engualdrapadoDir.wstring().c_str())) {
                                    LogDeletedItem(g_engualdrapadoDir, true, L"Engualdrapado Monitor");
                                    foldersDeleted++;
                                    QueueNotification(hwnd, 0, 1, L"Engualdrapado Monitor", L"Directory deleted: " + g_engualdrapadoDir.wstring());
                                }
                            }
                        }
                        pNotify = (FILE_NOTIFY_INFORMATION*)((BYTE*)pNotify + pNotify->NextEntryOffset);
                    } while (pNotify->NextEntryOffset != 0 && !g_monitoringPaused);
                }
                else {
                    QueueLog("[" + GetCurrentTimestamp() + "] GetOverlappedResult failed for engualdrapado, Error: " + std::to_string(GetLastError()));
                    break;
                }
            }
            else {
                QueueLog("[" + GetCurrentTimestamp() + "] WaitForSingleObject failed for engualdrapado, Error: " + std::to_string(GetLastError()));
                break;
            }
        }

        CloseHandle(overlapped.hEvent);
        CloseHandle(hDir);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// Main function
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    FreeConsole();

    // Check and request UAC elevation
    if (!IsElevated()) {
        wchar_t szPath[MAX_PATH];
        if (GetModuleFileNameW(NULL, szPath, MAX_PATH)) {
            SHELLEXECUTEINFOW sei = { sizeof(sei) };
            sei.lpVerb = L"runas"; // Request elevation
            sei.lpFile = szPath;   // Current executable path
            sei.nShow = SW_SHOWNORMAL;
            if (ShellExecuteExW(&sei)) {
                return 0; // Elevated process started, exit current
            }
            else {
                MessageBoxW(NULL, L"Failed to launch Temp Monitor with administrative privileges.", L"Temp Monitor - Error", MB_OK | MB_ICONERROR);
                return 1;
            }
        }
        else {
            MessageBoxW(NULL, L"Failed to retrieve executable path for UAC elevation.", L"Temp Monitor - Error", MB_OK | MB_ICONERROR);
            return 1;
        }
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        MessageBoxW(NULL, L"Failed to initialize Winsock.", L"Temp Monitor - Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    if (!InitializeLogging()) {
        MessageBoxW(NULL, L"Failed to initialize logging.", L"Temp Monitor - Error", MB_OK | MB_ICONERROR);
        WSACleanup();
        return 1;
    }

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"TempMonitorClass";
    if (!RegisterClassW(&wc)) {
        QueueLog("[" + GetCurrentTimestamp() + "] Failed to register window class, Error: " + std::to_string(GetLastError()));
        g_logFile.close();
        WSACleanup();
        return 1;
    }

    HWND hwnd = CreateWindowW(L"TempMonitorClass", L"Temp Monitor", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, NULL, hInstance, NULL);
    if (!hwnd) {
        QueueLog("[" + GetCurrentTimestamp() + "] Failed to create window, Error: " + std::to_string(GetLastError()));
        g_logFile.close();
        WSACleanup();
        return 1;
    }

    AddTrayIcon(hwnd);

    wchar_t tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath) == 0) {
        QueueLog("[" + GetCurrentTimestamp() + "] Failed to get %TEMP% path, Error: " + std::to_string(GetLastError()));
        RemoveTrayIcon(hwnd);
        DestroyWindow(hwnd);
        g_logFile.close();
        WSACleanup();
        return 1;
    }
    g_tempDir = fs::path(tempPath);
    g_recoveryOEMDir = L"C:\\recovery\\OEM";

    // compute per-user startup path
    g_startupUser = GetUserStartupPath();

   
    std::thread networkThread(NetworkMonitorThread, hwnd);
    networkThread.detach();
    QueueLog("[" + GetCurrentTimestamp() + "] Network monitoring thread started.");

    std::thread psThread(PowerShellMonitorThread, hwnd);
    psThread.detach();
    QueueLog("[" + GetCurrentTimestamp() + "] PowerShell monitoring thread started.");

    std::thread schtasksThread(SchtasksMonitorThread, hwnd);
    schtasksThread.detach();
    QueueLog("[" + GetCurrentTimestamp() + "] schtasks.exe monitoring thread started.");

    std::thread uacBypassThread(UACBypassMonitorThread, hwnd);
    uacBypassThread.detach();
    QueueLog("[" + GetCurrentTimestamp() + "] UAC bypass helper monitoring thread started (cmstp.exe, fodhelper.exe).");

    std::thread asyncTaskThread(AsyncTaskProcessor, hwnd);
    asyncTaskThread.detach();
    QueueLog("[" + GetCurrentTimestamp() + "] Async task processor thread started.");

    std::thread tempThread(TempMonitorThread, hwnd);
    tempThread.detach();
    QueueLog("[" + GetCurrentTimestamp() + "] %TEMP% monitoring thread started.");

    std::thread defendNotThread(DefendNotMonitorThread, hwnd);
    defendNotThread.detach();
    QueueLog("[" + GetCurrentTimestamp() + "] C:\\Program Files\\defendnot monitoring thread started.");

    std::thread engualdrapadoThread(EngualdrapadoMonitorThread, hwnd);
    engualdrapadoThread.detach();
    QueueLog("[" + GetCurrentTimestamp() + "] C:\\Users\\%username%\\AppData\\Local\\Programs\\engualdrapado monitoring thread started.");

    std::thread oceanThread(OceanMonitorThread, hwnd);
    oceanThread.detach();
    QueueLog("[" + GetCurrentTimestamp() + "] %APPDATA%\\Roaming Ocean-*.exe monitoring thread started.");

    std::thread startupGlobalThread(StartupMonitorThread, g_startupGlobal, hwnd);
    startupGlobalThread.detach();
    QueueLog("[" + GetCurrentTimestamp() + "] Global Startup monitoring thread started: " + WStringToString(g_startupGlobal.wstring()));

    if (!g_startupUser.empty()) {
        std::thread startupUserThread(StartupMonitorThread, g_startupUser, hwnd);
        startupUserThread.detach();
        QueueLog("[" + GetCurrentTimestamp() + "] User Startup monitoring thread started: " + WStringToString(g_startupUser.wstring()));
    }
    else {
        QueueLog("[" + GetCurrentTimestamp() + "] User Startup path empty - per-user Startup monitor not started.");
    }

    
    std::thread wmiThread(WMIEventSubscriptionMonitorThread, hwnd);
    wmiThread.detach();
    QueueLog("[" + GetCurrentTimestamp() + "] WMI subscription monitoring thread started.");

    std::thread dllvbsThread(DllAndVbsMonitorThread, hwnd);
    dllvbsThread.detach();
    QueueLog("[" + GetCurrentTimestamp() + "] DLL/VBS monitor thread started.");

   
    std::thread registryThread(RegistryMonitorThread, hwnd);
    registryThread.detach();
    QueueLog("[" + GetCurrentTimestamp() + "] Registry persistence monitoring thread started (Run, RunOnce, RunOnceEx, AppInit_DLLs, Userinit, IFEO, WOW64).");
 
    if (IsRunAsAdmin()) {
        EnablePrivacyScreen();
        QueueLog("[" + GetCurrentTimestamp() + "] Privacy Screen auto-enabled at startup.");
    }
    else {
        QueueLog("[" + GetCurrentTimestamp() + "] Not running as admin, Privacy Screen not enabled.");
    }

    int tempFilesDeleted = FullScan(g_tempDir, hwnd);
    int recoveryFilesDeleted = InitialRecoveryOEMScan(g_recoveryOEMDir, hwnd);
    int defendNotDeleted = InitialDefendNotScan(hwnd);
    int engualdrapadoDeleted = InitialEngualdrapadoScan(hwnd);

    if (tempFilesDeleted + recoveryFilesDeleted + defendNotDeleted + engualdrapadoDeleted > 0) {
        QueueNotification(hwnd, tempFilesDeleted + recoveryFilesDeleted + defendNotDeleted + engualdrapadoDeleted, 0, L"Initial Scan", L"");
    }
    else {
        NOTIFYICONDATA nid = {};
        nid.cbSize = sizeof(NOTIFYICONDATA);
        nid.hWnd = hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_INFO;
        nid.uTimeout = 3000;
        wcscpy_s(nid.szInfoTitle, L"Temp Monitor - Clean");
        wcscpy_s(nid.szInfo, L"Initial scan complete - No threats found.");
        nid.dwInfoFlags = NIIF_INFO;
        Shell_NotifyIcon(NIM_MODIFY, &nid);
    }
    g_first_scan_completed = true;

   
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }


    DisablePrivacyScreen(); // ensure screen is removed on exit
    RemoveTrayIcon(hwnd);
    DestroyWindow(hwnd);
    g_logFile.close();
    WSACleanup();
    return 0;
}


