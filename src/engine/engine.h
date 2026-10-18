/* engine.h 鈥?HookProxy 寮曟搸瀵煎嚭闈?鍘熷巶 9 瀵煎嚭 + 娴嬭瘯鎵╁睍) */
#ifndef HPX_ENGINE_H
#define HPX_ENGINE_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HPX_DEFAULT_TCP_PORT   2018
#define HPX_DEFAULT_UDP_PORT   2019
#define HPX_DRIVER_FILE_W      L"HpxDrv64.sys"

/* ---------- 鍘熷巶 9 瀵煎嚭(璇箟瑙?docs\DESIGN.md) ---------- */
BOOL WINAPI InitData(int ProxyPort, int SetPort, BOOLEAN Switch);
BOOL WINAPI CheckSocks5(int PrxTypes, char* ip, int port, char* user, char* pass);
BOOL WINAPI SetProxy(int PrxMode, const char* pid, const char* ip, const char* port,
                     const char* user, const char* pass, const char* key);
BOOL WINAPI StopProxy(DWORD pid);
BOOL WINAPI GetProcessFlow(BOOLEAN Switch, DWORD pid, unsigned long long* up, unsigned long long* down);
BOOL WINAPI AddFilterExeName(char* ProxyExe);
BOOL WINAPI FilterProcessNet(int mode, DWORD pid, void* a, void* b);
BOOL WINAPI FixNet(void);
BOOL WINAPI EmptyData(void);

/* ---------- 娴嬭瘯鎵╁睍(GUI/鎺㈤拡;闈炲師鍘傞潰) ---------- */
BOOL WINAPI HpxInstallDriverW(const wchar_t* sysPath);   /* sysPath=NULL:exe 鍚岀洰褰?*/
BOOL WINAPI HpxUninstallDriverW(void);
BOOL WINAPI HpxDriverStatusW(wchar_t* buf, int cch);
BOOL WINAPI HpxSetUdpBackMode(int mode);                 /* 0=auto 1=娉ㄥ叆 2=bind 浼€犳簮 3=鏈湴鍖?*/
BOOL WINAPI HpxUdpPreTargetA(const char* ip, int port);  /* mode3 棰勭儹 UDP 鐩爣(娑堥鍖呯珵鎬? */
BOOL WINAPI HpxDiagW(wchar_t* buf, int cch);
BOOL WINAPI HpxGetLogA(int idx, char* buf, int cch);
BOOL WINAPI HpxQueryPidFlowA(DWORD pid, unsigned long long* up, unsigned long long* down);
BOOL WINAPI HpxMakeKeyA(const char* pid, const char* ip, char* out33);
BOOL WINAPI HpxEnumProcA(int idx, DWORD* pid, char* image, int cap,
                         int* isActive, int* isAuto, int* isUserStopped);

#ifdef __cplusplus
}
#endif
#endif /* HPX_ENGINE_H */
