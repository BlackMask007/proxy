/*
 * engine.c 鈥?HookProxy 鍔熻兘閲嶅疄鐜?鐢ㄦ埛鎬佸紩鎿?x64)
 *
 * 瀹炵幇鍘熷巶 HookProxy.dll 鐨勯€忔槑浠ｇ悊鍔熻兘(鎺у埗闈?+ 鏈湴涓户):
 *   - 9 涓悓鍚嶅鍑?InitData/CheckSocks5/SetProxy/StopProxy/GetProcessFlow/
 *     AddFilterExeName/FilterProcessNet/FixNet/EmptyData),璇箟瑙?docs\DESIGN.md;
 *   - 椹卞姩鐢熷懡鍛ㄦ湡鎵╁睍瀵煎嚭(HpxInstallDriver/HpxUninstallDriver/鐘舵€佷笌璇婃柇,渚?GUI);
 *   - TCP 涓户:accept 鈫?璁ら鍘熷鐩殑 鈫?SOCKS5 CONNECT(涓婃父)鈫?鍙屽悜娉?鈫?瀛楄妭鍥炴姤;
 *   - UDP 涓户:鍚告敹鍖呰棰?椹卞姩灏炬爣鐩寸粰 flowId)鈫?姣忔祦鐙珛 UDP ASSOCIATE(RFC1928,
 *     鑺傜偣浼氳瘽閽夐涓暟鎹姤,鏁呬竴濂楁帴瀛楀嵆涓€娴佽韩浠?鈫?鍥炲寘浼€犳簮鍥炴敞(椹卞姩 200 娉ㄥ叆,
 *     澶辫触閫€鍖栦负 bind 浼€犳簮鐩存姇)鈫?瀛楄妭鍥炴姤銆? *
 * 缃戠粶杈圭晫(纭害鏉?:寮曟搸鑷韩鍙涓婃父 SOCKS5 鑺傜偣鍙戣捣杩炴帴(榛樿 10.10.10.254:1081);
 * 琚唬鐞嗚繘绋嬬殑娴侀噺鍏ㄩ儴缁忎笂娓镐腑缁?涓嶅湪鏈満鐩磋繛绗笁鏂广€? */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

/* 鏃?SDK 闂ㄥ悗闅愯棌鐨?API:杩愯鏃惰В鏋?閬垮厤瀵煎叆搴撳樊寮? */
typedef ULONG (WINAPI *PFN_AddUnicastIpAddressEntry)(const MIB_UNICASTIPADDRESS_ROW*);
typedef ULONG (WINAPI *PFN_RemoveUnicastIpAddressEntry)(const MIB_UNICASTIPADDRESS_ROW*);
static PFN_AddUnicastIpAddressEntry pAddUnicastIpAddressEntry = NULL;
static PFN_RemoveUnicastIpAddressEntry pRemoveUnicastIpAddressEntry = NULL;
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tlhelp32.h>

#include "hpx_proto.h"
#include "socks5.h"
#include "engine.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")

/* ============================ 鍏ㄥ眬鐘舵€?============================ */
static CRITICAL_SECTION g_cs;
static volatile LONG    g_csReady = 0;
static HANDLE           g_dev = INVALID_HANDLE_VALUE;
static int              g_init = 0;          /* InitData 骞傜瓑鏍囧織 */
static int              g_running = 0;       /* 寮曟搸杩愯涓?*/
static volatile LONG    g_stop = 0;
static volatile LONG    g_failOpen = 1;      /* 节点不可达时降级直连(保活):上游失败转直连,
                                               流量不断、日志明示;0=严格模式(失败即断) */
static HANDLE           g_hStopEvent = NULL;

static S5_NODE          g_node;              /* 涓婃父 SOCKS5 鑺傜偣 */
static int              g_tcpPort = HPX_DEFAULT_TCP_PORT;
static int              g_udpPort = HPX_DEFAULT_UDP_PORT;

static SOCKET           g_tcpListen = INVALID_SOCKET;
static SOCKET           g_udpSock = INVALID_SOCKET;
static HANDLE           g_hTcpAccept = NULL;
static HANDLE           g_hUdpThread = NULL;
static HANDLE           g_hEvtThread = NULL;

static int              g_udpBackMode = 0;   /* 0=auto(娉ㄥ叆浼樺厛) 1=娉ㄥ叆 2=bind 浼€犳簮 */

/* 鎸夎繘绋嬩唬鐞嗚褰?PID 鈫?椹卞姩璁¤垂璁板綍 + 娴侀噺) */
typedef struct _ENG_PROC {
    DWORD   pid;
    ULONG   recId;                 /* 椹卞姩璁¤垂璁板綍 ID(0x2201B8 鏌ヨ閿? */
    int     active;
    int     isAuto;                  /* 1 = 鏄犲儚鍚嶇櫧鍚嶅崟鑷姩鐧昏 */
    int     userStopped;           /* 1 = 鐢ㄦ埛鏄惧紡 StopProxy(杞鍣ㄤ笉鍐嶈嚜鍔ㄧ画鐧? */
    char    image[MAX_PATH];
    unsigned long long up, down;
    unsigned long long baseUp, baseDown;   /* 浼氳瘽澧為噺鍩虹嚎(GetProcessFlow Switch=1) */
} ENG_PROC;
#define MAX_PROCS 128
static ENG_PROC g_procs[MAX_PROCS];

/* 鏄犲儚鍚嶇櫧鍚嶅崟(AddFilterExeName;杩涚▼鍑虹幇鍗宠嚜鍔ㄧ櫥璁? */
#define MAX_EXES 32
static char g_exeList[MAX_EXES][MAX_PATH];
static int  g_exeCount = 0;

/* 杩囨护 IP/绔彛(FilterProcessNet;杞彂椹卞姩) */
#define MAX_FILT 32
static unsigned long g_filtIps[MAX_FILT];
static int  g_filtIpCount = 0;
static unsigned short g_filtPorts[MAX_FILT];
static int  g_filtPortCount = 0;

/* 鏃ュ織閻?GUI 鏉炵厙鑴? */
#define LOG_RING 128
#define LOG_LINE 192
static char g_log[LOG_RING][LOG_LINE];
static volatile LONG g_logIdx = 0;

/* Winsock 鑷垵濮嬪寲(骞傜瓑):
 * GUI 杩涚▼浠庝笉璋?WSAStartup;鍘嗗彶 bug = CheckSocks5 鍦?InitData 涔嬪墠璋冪敤鏃? * socket() 鍥?WSA 鏈垵濮嬪寲蹇呰触(GUI"娴嬭瘯杩炴帴"姘歌繙澶辫触,鑰岀郴缁熶唬鐞嗘甯?銆? * 鎵€鏈夐渶瑕佸鎺ュ瓧鐨勫鍑哄叆鍙ｇ粺涓€缁忔淇濊瘉;杩涚▼閫€鍑鸿嚜鍔ㄥ洖鏀?涓嶅啀 WSACleanup
 * (EmptyData 涔嬪悗鐨?CheckSocks5/HpxUdpPreTargetA 鍚屾牱瑕佽兘鐢?銆?*/
static volatile LONG g_wsaReady = 0;
static void WsaEnsure(void);           /* 鍓嶇疆澹版槑:瀹氫箟鍦?EngineLazyInit 闄勮繎 */
static void EngineLazyInit(void);
static void WsaEnsure(void)
{
    if (InterlockedCompareExchange(&g_wsaReady, 1, 0) == 0) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            InterlockedExchange(&g_wsaReady, 0);   /* 鍏佽涓嬫閲嶈瘯 */
    }
}

static void LogF(const char* fmt, ...)
{
    char msg[LOG_LINE - 16];
    char line[LOG_LINE];
    va_list ap;
    LONG idx;
    SYSTEMTIME st;
    static FILE* s_log = NULL;          /* 持久句柄:逐行 fopen/fclose 是长期运行的句柄/IO 抖动源 */
    static LONG  s_logInit = 0;
    va_start(ap, fmt);
    _vsnprintf_s(msg, sizeof(msg), _TRUNCATE, fmt, ap);
    va_end(ap);
    GetLocalTime(&st);
    _snprintf_s(line, sizeof(line), _TRUNCATE, "%02d:%02d:%02d.%03d %s",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);
    idx = InterlockedIncrement(&g_logIdx) - 1;
    memcpy(g_log[idx % LOG_RING], line, LOG_LINE);
    if (InterlockedCompareExchange(&s_logInit, 1, 0) == 0 || s_log) {
        if (!s_log) s_log = fopen("C:\\hpx\\relay.log", "a");
        if (s_log) {
            /* 轮转:超 8MB 归档为 .1,避免长期运行文件无限膨胀 */
            if (ftell(s_log) > 8 * 1024 * 1024) {
                fclose(s_log);
                s_log = NULL;
                remove("C:\\hpx\\relay.1.log");
                rename("C:\\hpx\\relay.log", "C:\\hpx\\relay.1.log");
                s_log = fopen("C:\\hpx\\relay.log", "a");
            }
            if (s_log) {
                fputs(line, s_log);
                fputc('\n', s_log);
                fflush(s_log);
            }
        }
    }
}

/* ============================ MD5(鍘熷巶 key 鍏煎) ============================ */
typedef struct { unsigned int s[4]; unsigned long long bytes; unsigned char buf[64]; } MD5CTX;
static void md5_init(MD5CTX* c) { c->s[0] = 0x67452301; c->s[1] = 0xefcdab89; c->s[2] = 0x98badcfe; c->s[3] = 0x10325476; c->bytes = 0; }
static unsigned int rol(unsigned int x, int n) { return (x << n) | (x >> (32 - n)); }
static void md5_block(MD5CTX* c, const unsigned char* p)
{
    static const unsigned int K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
    static const int R[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
    unsigned int a = c->s[0], b = c->s[1], cc = c->s[2], d = c->s[3], f, tmp, w[16];
    int i, g;
    for (i = 0; i < 16; i++)
        w[i] = (unsigned int)p[i * 4] | ((unsigned int)p[i * 4 + 1] << 8) |
               ((unsigned int)p[i * 4 + 2] << 16) | ((unsigned int)p[i * 4 + 3] << 24);
    for (i = 0; i < 64; i++) {
        if (i < 16) { f = (b & cc) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & cc); g = (5 * i + 1) % 16; }
        else if (i < 48) { f = b ^ cc ^ d; g = (3 * i + 5) % 16; }
        else { f = cc ^ (b | ~d); g = (7 * i) % 16; }
        tmp = d; d = cc; cc = b;
        b = b + rol(a + f + K[i] + w[g], R[i]);
        a = tmp;
    }
    c->s[0] += a; c->s[1] += b; c->s[2] += cc; c->s[3] += d;
}
static void md5_update(MD5CTX* c, const void* data, size_t len)
{
    const unsigned char* p = (const unsigned char*)data;
    size_t fill = (size_t)(c->bytes % 64);
    c->bytes += len;
    if (fill) {
        size_t need = 64 - fill;
        if (len < need) { memcpy(c->buf + fill, p, len); return; }
        memcpy(c->buf + fill, p, need);
        md5_block(c, c->buf);
        p += need; len -= need;
    }
    while (len >= 64) { md5_block(c, p); p += 64; len -= 64; }
    if (len) memcpy(c->buf, p, len);
}
static void md5_final(MD5CTX* c, char hex[33])
{
    static const char* hx = "0123456789abcdef";
    unsigned long long bits = c->bytes * 8;
    unsigned char pad[72];
    size_t padLen;
    int i;
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    padLen = ((c->bytes % 64) < 56) ? (56 - c->bytes % 64) : (120 - c->bytes % 64);
    md5_update(c, pad, padLen);
    for (i = 0; i < 8; i++) pad[i] = (unsigned char)(bits >> (8 * i));
    md5_update(c, pad, 8);
    for (i = 0; i < 16; i++) {
        unsigned char b = (unsigned char)(c->s[i / 4] >> (8 * (i % 4)));
        hex[i * 2] = hx[b >> 4];
        hex[i * 2 + 1] = hx[b & 15];
    }
    hex[32] = 0;
}

/* 鍘熷巶鎺堟潈 key:MD5灏忓啓hex( pidStr + ip + "VeryTiredR0Key2020" + str(瀹夸富PID*3+2000) ) */
static void MakeFactoryKey(const char* pidStr, const char* ip, char out[33])
{
    MD5CTX c;
    char hostPart[32];
    md5_init(&c);
    md5_update(&c, pidStr, strlen(pidStr));
    md5_update(&c, ip, strlen(ip));
    md5_update(&c, "VeryTiredR0Key2020", 18);
    _snprintf_s(hostPart, sizeof(hostPart), _TRUNCATE, "%u",
                (unsigned)GetCurrentProcessId() * 3 + 2000);
    md5_update(&c, hostPart, strlen(hostPart));
    md5_final(&c, out);
}

/* ============================ 椹卞姩鏈嶅姟绠＄悊 ============================ */
static BOOL ServiceExists(const wchar_t* name, DWORD* state)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE svc;
    if (!scm) return FALSE;
    svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return FALSE; }
    if (state) {
        SERVICE_STATUS_PROCESS ssp;
        DWORD need = 0;
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (BYTE*)&ssp, sizeof(ssp), &need))
            *state = ssp.dwCurrentState;
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return TRUE;
}

/* 瀹夎骞跺惎鍔ㄩ┍鍔ㄦ湇鍔?sysPath 涓虹┖鍒欑敤 exe 鍚岀洰褰?HPX_DRIVER_FILE */
BOOL WINAPI HpxInstallDriverW(const wchar_t* sysPath)
{
    wchar_t path[MAX_PATH];
    SC_HANDLE scm, svc;
    DWORD state = 0;

    if (sysPath && sysPath[0]) {
        wcsncpy_s(path, MAX_PATH, sysPath, _TRUNCATE);
    } else {
        GetModuleFileNameW(NULL, path, MAX_PATH);
        {
            wchar_t* slash = wcsrchr(path, L'\\');
            if (slash) *(slash + 1) = 0;
            wcsncat_s(path, MAX_PATH, HPX_DRIVER_FILE_W, _TRUNCATE);
        }
    }
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        LogF("install: driver file missing %ls", path);
        return FALSE;
    }

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) { LogF("install: OpenSCManager gle=%lu", GetLastError()); return FALSE; }

    svc = OpenServiceW(scm, HPX_SERVICE_NAME_W, SERVICE_ALL_ACCESS);
    if (!svc) {
        svc = CreateServiceW(scm, HPX_SERVICE_NAME_W, HPX_SERVICE_NAME_W,
                             SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                             SERVICE_ERROR_NORMAL, path, NULL, NULL, L"Tcpip\0BFE", NULL, NULL);
        if (!svc) {
            LogF("install: CreateService gle=%lu", GetLastError());
            CloseServiceHandle(scm);
            return FALSE;
        }
        LogF("install: service created %ls", path);
    } else {
        /* 指向当前路径(防旧路径残留),并把被手动禁用恢复为按需启动 */
        ChangeServiceConfigW(svc, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                             path, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    if (!StartServiceW(svc, 0, NULL)) {
        DWORD gle = GetLastError();
        if (gle == ERROR_SERVICE_DISABLED || gle == ERROR_SERVICE_MARKED_FOR_DELETE) {
            /* 禁用/标记删除不能靠 StartService 硬拉:删除后按当前路径重建 */
            LogF("install: recover disabled/deleted state gle=%lu", gle);
            if (svc) {
                DeleteService(svc);       /* ERROR_SERVICE_MARKED_FOR_DELETE 可忽略 */
                CloseServiceHandle(svc);
                svc = NULL;
            }
            svc = CreateServiceW(scm, HPX_SERVICE_NAME_W, HPX_SERVICE_NAME_W,
                                 SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                                 SERVICE_ERROR_NORMAL, path, NULL, NULL, L"Tcpip\0BFE", NULL, NULL);
            if (!svc) {
                LogF("install: recreate service gle=%lu", GetLastError());
                CloseServiceHandle(scm);
                return FALSE;
            }
            LogF("install: service recreated %ls", path);
            if (!StartServiceW(svc, 0, NULL)) {
                LogF("install: StartService after recreate gle=%lu", GetLastError());
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
                return FALSE;
            }
        } else if (gle != ERROR_SERVICE_ALREADY_RUNNING) {
            LogF("install: StartService gle=%lu", gle);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }
    /* 绛?RUNNING */
    {
        int i;
        for (i = 0; i < 50; i++) {
            SERVICE_STATUS ss;
            if (QueryServiceStatus(svc, &ss)) {
                state = ss.dwCurrentState;
                if (state == SERVICE_RUNNING) break;
            }
            Sleep(100);
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    LogF("install: state=%lu", state);
    return state == SERVICE_RUNNING;
}

BOOL WINAPI HpxUninstallDriverW(void)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS ss;
    int i;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return FALSE;
    svc = OpenServiceW(scm, HPX_SERVICE_NAME_W, SERVICE_ALL_ACCESS);
    if (!svc) { CloseServiceHandle(scm); return TRUE; }

    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    for (i = 0; i < 100; i++) {           /* 鏈€澶?10s 绛夊仠瀹?闃?pending-delete) */
        if (!QueryServiceStatus(svc, &ss)) break;
        if (ss.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(100);
    }
    if (!DeleteService(svc)) {
        DWORD gle = GetLastError();
        if (gle != ERROR_SERVICE_MARKED_FOR_DELETE) {
            LogF("uninstall: DeleteService gle=%lu", gle);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    LogF("uninstall: done");
    return TRUE;
}

BOOL WINAPI HpxDriverStatusW(wchar_t* buf, int cch)
{
    DWORD state = 0;
    BOOL exists = ServiceExists(HPX_SERVICE_NAME_W, &state);
    HANDLE dev = CreateFileW(HPX_DOS_PATH_W, GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    BOOL devOk = (dev != INVALID_HANDLE_VALUE);
    if (devOk) CloseHandle(dev);
    _snwprintf_s(buf, cch, _TRUNCATE,
        L"service=%s state=%lu device=%s",
        exists ? L"present" : L"absent", state,
        devOk ? L"openable" : L"unavailable");
    return exists && devOk;
}

/* ============================ 璁惧 IOCTL 灏佽 ============================ */
static BOOL DevControl(DWORD code, void* inBuf, DWORD inLen, void* outBuf, DWORD outLen, DWORD* retLen)
{
    DWORD br = 0;
    if (g_dev == INVALID_HANDLE_VALUE) return FALSE;
    if (!DeviceIoControl(g_dev, code, inBuf, inLen, outBuf, outLen, &br, NULL)) return FALSE;
    if (retLen) *retLen = br;
    return TRUE;
}

static BOOL CtrlCmd(ULONG cmd, ULONG param, void* out, DWORD outLen)
{
    HPX_CONTROL_IN in;
    DWORD br = 0;
    in.cmd = cmd;
    in.param = param;
    return DevControl(IOCTL_HPX_CONTROL, &in, sizeof(in), out ? out : &in, out ? outLen : sizeof(in), &br);
}

/* ===== 局域网网段推送:精确判定,访问局域网一律不代理 =====
 * 网段 = 本机各接口 on-link 前缀(地址 & 前缀掩码):凡本链路可达即局域网,
 * 公网编址的局域网同样命中;驱动侧全模式豁免(HPX_CTRL_SET_LAN 整表下发)。 */
static void LanPush(void)
{
    PMIB_UNICASTIPADDRESS_TABLE tbl = NULL;
    HPX_SET_LAN sl;
    UINT i;
    memset(&sl, 0, sizeof(sl));
    sl.cmd = HPX_CTRL_SET_LAN;
    if (GetUnicastIpAddressTable(AF_INET, &tbl) == NO_ERROR) {
        for (i = 0; i < tbl->NumEntries && sl.count < 32; i++) {
            ULONG pfx, addr, mask, net;
            if (tbl->Table[i].Address.si_family != AF_INET) continue;
            pfx = tbl->Table[i].OnLinkPrefixLength;
            if (pfx == 0 || pfx > 32) continue;
            addr = ntohl(tbl->Table[i].Address.Ipv4.sin_addr.s_addr);   /* 大端序值 */
            mask = (pfx >= 32) ? 0xFFFFFFFFu : ~((1u << (32 - pfx)) - 1);
            net = addr & mask;
            if ((net >> 24) == 127) continue;          /* 127/8 由驱动 HpxSkipDestV4 处理 */
            sl.e[sl.count].net = net;
            sl.e[sl.count].mask = mask;
            sl.count++;
        }
        FreeMibTable(tbl);
    }
    CtrlCmd(HPX_CTRL_CLEAR_LAN, 0, NULL, 0);
    DevControl(IOCTL_HPX_CONTROL, &sl, sizeof(sl), NULL, 0, NULL);
    LogF("lan: pushed %u segments", sl.count);
}

/* 璁ら鍘熷鐩殑:hdr=1 鎸?flowId(灏炬爣鐩寸粰)/hdr=3 鎸夌鐐?hdr=2 FIFO */
static BOOL ClaimDest(ULONG hdr, ULONG keyPortNet, ULONG keyIpMem, UCHAR proto,
                      HPX_REQRESP* out)
{
    HPX_REQRESP req;
    DWORD br = 0;
    memset(&req, 0, sizeof(req));
    req.hdr = hdr;
    req.flowId = keyPortNet;
    req.arg = keyIpMem;
    req.cbData = HPX_REQRESP_DATA_LEN;
    req.u.dst.protocol = proto;
    if (!DevControl(IOCTL_HPX_CLAIM_DEST, &req, sizeof(req), out ? out : &req, sizeof(req), &br))
        return FALSE;
    if (out == NULL) out = &req;
    if (br < sizeof(HPX_REQRESP)) return FALSE;
    return TRUE;
}

/* ============================ 璁板綍(鎸?PID) ============================ */
static ENG_PROC* FindProc(DWORD pid)
{
    int i;
    for (i = 0; i < MAX_PROCS; i++)
        if (g_procs[i].active && g_procs[i].pid == pid) return &g_procs[i];
    return NULL;
}
static ENG_PROC* FindProcByRecId(ULONG recId)
{
    int i;
    if (recId == 0) return NULL;
    for (i = 0; i < MAX_PROCS; i++)
        if (g_procs[i].active && g_procs[i].recId == recId) return &g_procs[i];
    return NULL;
}

/* ==================== 鏄犲儚鍚嶈嚜鍔ㄧ櫥璁?椴佹鎬ф牳蹇? ====================
 * 鍘熷巶鐢?MonitorProcess 椹卞姩鍋氳繘绋嬪垱寤洪€氱煡;鏈」鐩崟椹卞姩,鏀圭敱寮曟搸杞杩涚▼琛?
 *   鐧藉悕鍗?AddFilterExeName)鍐呯殑鏄犲儚鍚?鈫?鐜板瓨杩涚▼绔嬪嵆鐧昏銆佹柊杩涚▼ 鈮?s 鍐呰嚜鍔ㄧ櫥璁般€? *   杩涚▼閫€鍑鸿嚜鍔ㄦ敞閿€;PID 澶嶇敤闃叉姢 = 瀛樻椿椤归』鍦ㄥ揩鐓т腑浠嶅悓鍚嶃€? * GUI"娣诲姞鏄犲儚鍚?= 涓€鏉¤鍒欒鐩栧杩涚▼(濡傚涓?chrome.exe)涓庢湭鏉ユ柊杩涚▼銆?*/
static HANDLE g_hAutoThread = NULL;

static int LookupImageByPid(DWORD pid, char* out, int cap)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    int found = 0;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, out, cap, NULL, NULL);
                found = 1;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

/* 鐧藉悕鍗曞尮閰?蹇界暐澶у皬鍐?鍚嶅崟椤瑰厑璁哥渷鐣?.exe */
static int ExeNameMatch(const char* image)
{
    int i;
    char norm[MAX_PATH];
    if (!image || !image[0]) return 0;
    strncpy_s(norm, sizeof(norm), image, _TRUNCATE);
    if (!strchr(norm, '.')) strncat_s(norm, sizeof(norm), ".exe", _TRUNCATE);
    EnterCriticalSection(&g_cs);
    for (i = 0; i < g_exeCount; i++) {
        char want[MAX_PATH];
        strncpy_s(want, sizeof(want), g_exeList[i], _TRUNCATE);
        if (!strchr(want, '.')) strncat_s(want, sizeof(want), ".exe", _TRUNCATE);
        if (_stricmp(norm, want) == 0) { LeaveCriticalSection(&g_cs); return 1; }
    }
    LeaveCriticalSection(&g_cs);
    return 0;
}

/* 稳定性:周期清扫"漏网直连"(2026-10-17,IP 查询站点偶发显示未代理 IP 的根治):
 * 受代理进程的已建立 TCP 连接中,凡对端为公网且不经本引擎中继泵者必为漏网直连
 * (规则绑定前的池化/保活连接、分类边缘情形、驱动重启窗残留)。浏览器会无限期复用
 * 这种残段,导致出口呈现"未代理 IP"。判定边界:中继泵连接的对端是本机中继口
 * (127/8,引擎 accept 实证),公网对端且属受代理 PID 即为漏网;局域网/基础设施
 * 目标直连合法(访问局域网不代理)一并豁免。DELETE_TCB 后应用自动重连即回代理路径。 */
static int LocBlockedIp(ULONG ipMem);   /* 前置声明:定义见 mode-3 本地化黑名单一节 */
static int IsProxiedPid(DWORD pid)
{
    char image[MAX_PATH];
    if (pid == 0 || pid == GetCurrentProcessId()) return 0;
    if (FindProc(pid)) return 1;
    if (LookupImageByPid(pid, image, sizeof(image)) && ExeNameMatch(image)) return 1;
    return 0;
}

static void SweepStrayTcp(void)
{
    PMIB_TCPTABLE_OWNER_PID tbl = NULL;
    DWORD sz = 0, i, killed = 0;

    LogF("sweep: begin");
    if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
        LogF("sweep: size query fail");
        return;
    }
    tbl = (PMIB_TCPTABLE_OWNER_PID)malloc(sz);
    if (!tbl) { LogF("sweep: oom sz=%lu", sz); return; }
    if (GetExtendedTcpTable(tbl, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        LogF("sweep: tbl ok n=%lu", tbl->dwNumEntries);
        for (i = 0; i < tbl->dwNumEntries; i++) {
            ULONG dstMem = tbl->table[i].dwRemoteAddr;
            if (tbl->table[i].dwState != MIB_TCP_STATE_ESTAB) continue;
            if (dstMem == 0 || (ntohl(dstMem) >> 24) == 127) continue;  /* 中继泵侧/无对端 */
            if (LocBlockedIp(dstMem)) continue;                         /* 局域网/基础设施直连合法 */
            if (!IsProxiedPid(tbl->table[i].dwOwningPid)) continue;
            tbl->table[i].dwState = MIB_TCP_STATE_DELETE_TCB;
            if (SetTcpEntry((MIB_TCPROW*)&tbl->table[i]) == NO_ERROR) {
                killed++;
                LogF("sweep: killed stray direct tcp pid=%lu dst=%08x:%u",
                     tbl->table[i].dwOwningPid, dstMem,
                     ntohs((USHORT)tbl->table[i].dwRemotePort));
            } else {
                LogF("sweep: setentry fail pid=%lu dst=%08x gle=%lu",
                     tbl->table[i].dwOwningPid, dstMem, GetLastError());
            }
        }
    }
    free(tbl);
    LogF("sweep: done killed=%lu", killed);
}

static void KillTcpConnsOfPid(DWORD pid);
static void KillAllStaleTcpConns(void);

static void ProcRegisterInternal(DWORD pid, const char* image, int isAuto)
{
    ULONG out = 0;
    ENG_PROC* p;
    if (pid == 0 || pid == GetCurrentProcessId()) return;
    if (!CtrlCmd(HPX_CTRL_ADD_PID, pid, &out, sizeof(out))) return;
    EnterCriticalSection(&g_cs);
    p = FindProc(pid);
    if (!p) {
        int i;
        for (i = 0; i < MAX_PROCS && g_procs[i].active; i++) {}
        if (i < MAX_PROCS) p = &g_procs[i];
    }
    if (p) {
        ULONG prevRec = p->recId;
        if (!p->active) memset(p, 0, sizeof(*p));
        p->pid = pid;
        p->recId = out ? out : prevRec;
        p->active = 1;
        p->isAuto = isAuto;
        p->userStopped = 0;
        if (image && image[0]) strncpy_s(p->image, sizeof(p->image), image, _TRUNCATE);
        else if (!p->image[0]) LookupImageByPid(pid, p->image, sizeof(p->image));
    }
    LeaveCriticalSection(&g_cs);
    LogF("proc: registered pid=%lu rec=%lu auto=%d image=%s", pid, out, isAuto, image ? image : "?");
    /* 不在此处清存量连接:自动登记发生在进程存活期,清连接=杀活连接(实测 9/10 掉线)。
     * 存量收编只在"绑定动作"发生时执行(AddFilterExeName/SetProxy/全局开启)——
     * 映像名规则在驱动侧 classify 即时生效,登记竞态期的新连接本就被拦截,无需清。 */
}

static void ProcUnregisterInternal(DWORD pid, const char* why)
{
    int i;
    CtrlCmd(HPX_CTRL_REMOVE_PID, pid, NULL, 0);
    EnterCriticalSection(&g_cs);
    for (i = 0; i < MAX_PROCS; i++) {
        if (g_procs[i].pid == pid && g_procs[i].active) {
            g_procs[i].active = 0;
            break;
        }
    }
    LeaveCriticalSection(&g_cs);
    LogF("proc: unregistered pid=%lu (%s)", pid, why ? why : "-");
}

static void AutoScanOnce(void)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    DWORD seen[MAX_PROCS];
    int nseen = 0, i, nmatch = 0, nreg = 0;

    if (g_exeCount == 0) return;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { LogF("scan: snapshot fail err=%lu", GetLastError()); return; }
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            char image[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, image, sizeof(image), NULL, NULL);
            if (!ExeNameMatch(image)) continue;
            nmatch++;
            if (nseen < MAX_PROCS) seen[nseen++] = pe.th32ProcessID;
            if (!FindProc(pe.th32ProcessID)) {
                ProcRegisterInternal(pe.th32ProcessID, image, 1);
                nreg++;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (nmatch || nreg) LogF("scan: exeCount=%d matched=%d new=%d", g_exeCount, nmatch, nreg);

    /* 閫€鍑烘敞閿€ / PID 澶嶇敤娉ㄩ攢:鑷姩鐧昏椤归』鍦ㄦ湰娆″揩鐓т腑浠嶅悓鍚嶅瓨娲?*/
    /* 生命周期注销只认"确认退出":OpenProcess+退出码(快照缺席不作数——Toolhelp
     * 快照天生竞态,曾致存活进程被误销绑定=用户感知"代理偶尔掉");存活再验
     * 映像名防 PID 复用。手动绑定(isAuto=0)永不动,直到手动移除。 */
    for (i = 0; i < MAX_PROCS; i++) {
        HANDLE h;
        DWORD code = 0;
        if (!g_procs[i].active || !g_procs[i].isAuto || g_procs[i].userStopped) continue;
        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_procs[i].pid);
        if (h == NULL) {
            ProcUnregisterInternal(g_procs[i].pid, "exit-confirmed");
            continue;
        }
        if (GetExitCodeProcess(h, &code) && code != STILL_ACTIVE) {
            CloseHandle(h);
            ProcUnregisterInternal(g_procs[i].pid, "exit-confirmed");
            continue;
        }
        {
            wchar_t wpath[MAX_PATH];
            DWORD n = MAX_PATH;
            char now[MAX_PATH], *base;
            if (QueryFullProcessImageNameW(h, 0, wpath, &n)) {
                WideCharToMultiByte(CP_UTF8, 0, wpath, -1, now, sizeof(now), NULL, NULL);
                base = strrchr(now, '\\');
                base = base ? base + 1 : now;
                if (_stricmp(base, g_procs[i].image) != 0)
                    ProcUnregisterInternal(g_procs[i].pid, "pid-reuse");
            }
        }
        CloseHandle(h);
    }
}

static DWORD WINAPI AutoRegThread(LPVOID unused)
{
    (void)unused;
    LogF("auto: thread started");
    {
        int sweepTick = 0;
        while (!InterlockedCompareExchange(&g_stop, 0, 0)) {
            if (g_hStopEvent)
                WaitForSingleObject(g_hStopEvent, 1000);
            else
                Sleep(1000);
            if (InterlockedCompareExchange(&g_stop, 0, 0)) break;
            if (g_running) {
                AutoScanOnce();
                if (++sweepTick >= 10) {
                    sweepTick = 0;
                    __try {
                        SweepStrayTcp();
                    } __except (1 /* EXCEPTION_EXECUTE_HANDLER */) {
                        LogF("sweep: EXCEPTION %08x", GetExceptionCode());
                    }
                }
            }
        }
    }
    return 0;
}

/* 鏋氫妇鐧昏椤?GUI 娴侀噺琛ㄦ暟鎹簮):line = "pid|image|active|auto|userStopped" */
BOOL WINAPI HpxEnumProcA(int idx, DWORD* pid, char* image, int cap,
                         int* isActive, int* outIsAuto, int* isUserStopped)
{
    int i, k = 0;
    EngineLazyInit();
    if (idx < 0) return 0;
    EnterCriticalSection(&g_cs);
    for (i = 0; i < MAX_PROCS; i++) {
        if (g_procs[i].pid == 0 && !g_procs[i].active) continue;
        if (k == idx) {
            if (pid) *pid = g_procs[i].pid;
            if (image && cap > 0) strncpy_s(image, cap, g_procs[i].image, _TRUNCATE);
            if (isActive) *isActive = g_procs[i].active;
            if (outIsAuto) *outIsAuto = g_procs[i].isAuto;
            if (isUserStopped) *isUserStopped = g_procs[i].userStopped;
            LeaveCriticalSection(&g_cs);
            return 1;
        }
        k++;
    }
    LeaveCriticalSection(&g_cs);
    return 0;
}

/* ============================ TCP 涓户 ============================ */
typedef struct _TCP_WORKER_ARG {
    SOCKET s;
    struct sockaddr_in peer;
} TCP_WORKER_ARG;

static void ReportBytes(ULONG recId, DWORD up, DWORD down)
{
    HPX_REPORT rep;
    rep.upDelta = up;
    rep.downDelta = down;
    rep.id = recId;
    DevControl(IOCTL_HPX_TCP_REPORT, &rep, sizeof(rep), NULL, 0, NULL);
}

/* 窥视应用首包,提取 TLS SNI 或 HTTP Host(防 DNS 污染:上行按域名交节点解析)。
 * 只 PEEK 不消费;取不到返回 -1(回退按 IP 直连目标)。等待上限 250ms。 */
static int PeekHost(SOCKET s, char* out, int cap)
{
    unsigned char buf[2048];
    fd_set rf;
    struct timeval tv;
    int n, i;

    FD_ZERO(&rf);
    FD_SET(s, &rf);
    tv.tv_sec = 0;
    tv.tv_usec = 250000;
    if (select(0, &rf, NULL, NULL, &tv) <= 0) return -1;
    n = recv(s, (char*)buf, sizeof(buf), MSG_PEEK);
    if (n < 8) return -1;

    /* TLS 记录(ContentType=0x16 handshake,版本 0x03 xx)→ ClientHello → SNI 扩展 */
    if (buf[0] == 0x16 && buf[1] == 0x03) {
        int recLen = (buf[3] << 8) | buf[4];
        int off = 5, sidLen, csLen, cmLen, extLen, end;
        if (recLen + 5 > n || buf[off] != 0x01) return -1;
        off += 4;                     /* handshake header */
        off += 2 + 32;                /* client_version + random */
        if (off >= n) return -1;
        sidLen = buf[off];
        off += 1 + sidLen;
        if (off + 2 > n) return -1;
        csLen = (buf[off] << 8) | buf[off + 1];
        off += 2 + csLen;
        if (off >= n) return -1;
        cmLen = buf[off];
        off += 1 + cmLen;
        if (off + 2 > n) return -1;
        extLen = (buf[off] << 8) | buf[off + 1];
        off += 2;
        end = off + extLen;
        if (end > n) end = n;
        while (off + 4 <= end) {
            int et = (buf[off] << 8) | buf[off + 1];
            int el = (buf[off + 2] << 8) | buf[off + 3];
            off += 4;
            if (et == 0 && off + 5 <= end) {          /* server_name */
                int nl;
                if (buf[off + 2] != 0) return -1;     /* name_type != host_name */
                nl = (buf[off + 3] << 8) | buf[off + 4];
                if (nl <= 0 || nl >= cap || off + 5 + nl > end) return -1;
                memcpy(out, buf + off + 5, (size_t)nl);
                out[nl] = 0;
                return 0;
            }
            off += el;
        }
        return -1;
    }

    /* 明文 HTTP 请求 → Host 头 */
    for (i = 0; i + 7 < n; i++) {
        if (buf[i] == '\n' && (buf[i + 1] == 'H' || buf[i + 1] == 'h') &&
            memcmp(buf + i + 2, "ost:", 4) == 0) {
            int j = i + 6, k;
            while (j < n && (buf[j] == ' ' || buf[j] == '\t')) j++;
            k = j;
            while (k < n && buf[k] != '\r' && buf[k] != '\n' && buf[k] != ':' && k - j < cap - 1) k++;
            if (k == j) return -1;
            memcpy(out, buf + j, (size_t)(k - j));
            out[k - j] = 0;
            {
                /* Host 必须是带点的真域名(测试桩常用占位 Host 如 "probe"),否则回退按 IP 直连 */
                int d;
                for (d = 0; out[d]; d++) if (out[d] == '.') break;
                if (!out[d]) return -1;
            }
            return 0;
        }
    }
    return -1;
}

/* 降级直连:节点不可达时直连原始目标,保住流量(可选保活语义);超时毫秒 */
static SOCKET DirectConnect(const struct sockaddr_in* dst, int timeoutMs)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    u_long nb = 1;
    fd_set wf;
    struct timeval tv;
    int err = 0, elen = sizeof(err);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    ioctlsocket(s, FIONBIO, &nb);
    if (connect(s, (const struct sockaddr*)dst, sizeof(*dst)) != 0) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) { closesocket(s); return INVALID_SOCKET; }
        FD_ZERO(&wf);
        FD_SET(s, &wf);
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        if (select(0, NULL, &wf, NULL, &tv) <= 0) { closesocket(s); return INVALID_SOCKET; }
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &elen);
        if (err != 0) { closesocket(s); return INVALID_SOCKET; }
    }
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    return s;
}

static DWORD WINAPI TcpWorker(LPVOID arg)
{
    TCP_WORKER_ARG* wa = (TCP_WORKER_ARG*)arg;
    SOCKET app = wa->s;
    struct sockaddr_in peer = wa->peer;
    SOCKET up = INVALID_SOCKET;
    HPX_REQRESP claim;
    struct sockaddr_in tgt;
    ENG_PROC* proc;
    ULONG recId = 0;
    unsigned long long upBytes = 0, downBytes = 0;
    char buf[65536];
    int alive = 1;

    free(wa);

    /* 璁ら鍘熷鐩殑:浼樺厛鎸夊簲鐢ㄦ湰鍦扮鐐?accept 鐨勫绔?,澶辫触閫€ FIFO */
    memset(&claim, 0, sizeof(claim));
    if (!ClaimDest(HPX_REQ_BY_ENDPOINT,
                   (ULONG)peer.sin_port, (ULONG)peer.sin_addr.s_addr, 6, &claim) ||
        claim.u.dst.protocol != 6) {
        if (!ClaimDest(HPX_REQ_FIFO, 0, 0, 6, &claim) || claim.u.dst.protocol != 6) {
            LogF("tcp: claim fail peer=%08x:%u", peer.sin_addr.s_addr, ntohs(peer.sin_port));
            closesocket(app);
            return 0;
        }
    }
    memset(&tgt, 0, sizeof(tgt));
    tgt.sin_family = AF_INET;
    tgt.sin_addr.s_addr = claim.u.dst.remoteIpV4;
    tgt.sin_port = htons((unsigned short)claim.u.dst.remotePort);
    proc = FindProc(claim.u.dst.pid);
    if (proc) recId = proc->recId;
    LogF("tcp: claim ok dst=%08x:%u pid=%u", tgt.sin_addr.s_addr, claim.u.dst.remotePort, claim.u.dst.pid);

    {
        char host[256];
        int useHost = (PeekHost(app, host, sizeof(host)) == 0);
        int attempt;
        int okUp = 0;
    if (useHost) LogF("tcp: sni-host=%s:%u (domain connect)", host, claim.u.dst.remotePort);
        /* 上游连 3 次(300ms 退避):吸收节点偶发抖动,减少用户感知的"掉线" */
        for (attempt = 0; attempt < 3 && !okUp; attempt++) {
            if (attempt) Sleep(300);
            if (s5_open(&g_node, &up) == 0 &&
                (useHost ? s5_connect_host(up, host, (unsigned short)claim.u.dst.remotePort)
                         : s5_connect(up, &tgt)) == 0) {
                okUp = 1;
            } else {
                if (up != INVALID_SOCKET) { closesocket(up); up = INVALID_SOCKET; }
            }
        }
        if (!okUp && g_failOpen) {
            /* 降级直连(保活):节点不可达时直连原始目标,流量不断、日志明示 */
            up = DirectConnect(&tgt, 5000);
            if (up != INVALID_SOCKET)
                LogF("tcp: degraded-direct %08x:%u (node unreachable)",
                     tgt.sin_addr.s_addr, claim.u.dst.remotePort);
        }
        if (!okUp && up == INVALID_SOCKET) {
            LogF("tcp: upstream fail %s:%d -> %08x:%u%s%s", g_node.ip, g_node.port,
                 tgt.sin_addr.s_addr, claim.u.dst.remotePort,
                 useHost ? " host=" : "", useHost ? host : "");
            closesocket(app);
            if (recId) ReportBytes(recId, 0, 0);
            return 0;
        }
        /* 握手完成后放宽套接字超时:8s 是握手期口径,大块传输遇节点慢速时
         * 会被误杀(用户"上传失败"根因之一);放宽到 300s 无进展才判死,
         * 慢但活着的传输一律跑完,只有真死连接才回收 */
        {
            int bulkTo = 300000;
            setsockopt(up, SOL_SOCKET, SO_SNDTIMEO, (const char*)&bulkTo, sizeof(bulkTo));
            setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, (const char*)&bulkTo, sizeof(bulkTo));
            setsockopt(app, SOL_SOCKET, SO_SNDTIMEO, (const char*)&bulkTo, sizeof(bulkTo));
            setsockopt(app, SOL_SOCKET, SO_RCVTIMEO, (const char*)&bulkTo, sizeof(bulkTo));
        }
    }

    /* 鍙屽悜娉?1s 鍒嗙墖 select,鍋滄満 1s 鍐呴€€鍑?*/
    while (alive && !InterlockedCompareExchange(&g_stop, 0, 0)) {
        fd_set rf;
        struct timeval tv;
        int r;
        FD_ZERO(&rf);
        FD_SET(app, &rf);
        FD_SET(up, &rf);
        tv.tv_sec = 1; tv.tv_usec = 0;
        r = select(0, &rf, NULL, NULL, &tv);
        if (r < 0) break;
        if (r == 0) {
            if (upBytes || downBytes) {
                ReportBytes(recId, (DWORD)(upBytes > 0xFFFFFFFF ? 0xFFFFFFFF : upBytes),
                                    (DWORD)(downBytes > 0xFFFFFFFF ? 0xFFFFFFFF : downBytes));
                upBytes = downBytes = 0;
            }
            continue;
        }
        if (FD_ISSET(app, &rf)) {
            int n = recv(app, buf, sizeof(buf), 0);
            if (n <= 0) { alive = 0; break; }
            /* 聚合读:把此刻已到达的数据一次收干再大块转发——小块转发会触发
             * 每块一次系统调用 + 小包序列,实测吞吐砍半 */
            {
                u_long avail = 0;
                ioctlsocket(app, FIONREAD, &avail);
                while (avail > 0 && n < (int)sizeof(buf)) {
                    int want = (avail > sizeof(buf) - (size_t)n) ? (int)(sizeof(buf) - n) : (int)avail;
                    int m = recv(app, buf + n, want, 0);
                    if (m <= 0) break;
                    n += m;
                    avail -= m;
                }
            }
            if (s5_sendn(up, buf, n) < 0) { LogF("tcp: pump up-send fail"); alive = 0; break; }
            upBytes += n;
        }
        if (FD_ISSET(up, &rf)) {
            int n = recv(up, buf, sizeof(buf), 0);
            if (n <= 0) { alive = 0; break; }
            {
                u_long avail = 0;
                ioctlsocket(up, FIONREAD, &avail);
                while (avail > 0 && n < (int)sizeof(buf)) {
                    int want = (avail > sizeof(buf) - (size_t)n) ? (int)(sizeof(buf) - n) : (int)avail;
                    int m = recv(up, buf + n, want, 0);
                    if (m <= 0) break;
                    n += m;
                    avail -= m;
                }
            }
            if (s5_sendn(app, buf, n) < 0) { LogF("tcp: pump app-send fail"); alive = 0; break; }
            downBytes += n;
        }
    }
    if (upBytes || downBytes)
        ReportBytes(recId, (DWORD)upBytes, (DWORD)downBytes);
    ReportBytes(recId, 0, 0);        /* 鍏抽棴閫氱煡 */
    {
        ENG_PROC* p = FindProcByRecId(recId);
        if (p) {
            EnterCriticalSection(&g_cs);
            p->up += upBytes;                    /* 绱宸插湪涓婇潰鍥炴姤,鏈湴浠呭睍绀?*/
            p->down += downBytes;
            LeaveCriticalSection(&g_cs);
        }
    }
    shutdown(up, SD_BOTH);
    closesocket(up);
    shutdown(app, SD_BOTH);
    closesocket(app);
    LogF("tcp: done up=%llu down=%llu", upBytes, downBytes);
    return 0;
}

static DWORD WINAPI TcpAcceptThread(LPVOID unused)
{
    (void)unused;
    while (!InterlockedCompareExchange(&g_stop, 0, 0)) {
        fd_set rf;
        struct timeval tv;
        struct sockaddr_in peer;
        int plen = sizeof(peer);
        SOCKET s;
        FD_ZERO(&rf);
        FD_SET(g_tcpListen, &rf);
        tv.tv_sec = 1; tv.tv_usec = 0;
        if (select(0, &rf, NULL, NULL, &tv) <= 0) continue;
        s = accept(g_tcpListen, (struct sockaddr*)&peer, &plen);
        if (s == INVALID_SOCKET) continue;
        {
            int big = 1 << 20, nodelay = 1;
            setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char*)&big, sizeof(big));
            setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char*)&big, sizeof(big));
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
        }
        {
            TCP_WORKER_ARG* wa = (TCP_WORKER_ARG*)malloc(sizeof(*wa));
            HANDLE th;
            if (!wa) { closesocket(s); continue; }
            wa->s = s;
            wa->peer = peer;
            th = CreateThread(NULL, 0, TcpWorker, wa, 0, NULL);
            if (th) CloseHandle(th);
            else { closesocket(s); free(wa); }
        }
    }
    return 0;
}

/* ============================ UDP 涓户(閲嶇偣) ============================ */
#define MAX_UDP_FLOWS 64
typedef struct _UDP_FLOW {
    int      active;
    struct sockaddr_in app;        /* 搴旂敤绔偣(鍥炵▼鐩殑) */
    struct sockaddr_in tgt;        /* 鍘熷鐩殑(浼€犳簮) */
    SOCKET   ctrl;                 /* SOCKS5 鎺у埗杩炴帴(鍏宠仈鐢熷懡鍛ㄦ湡) */
    SOCKET   us;                   /* 涓婅 UDP 濂楁帴瀛?娴佽韩浠?鑺傜偣閽夐涓暟鎹姤) */
    SOCKET   loc;                  /* 鐩爣缁戝畾濂楁帴瀛?mode 3 鏈湴鍖栧洖绋嬬敤) */
    int      locMode;              /* 1 = 鏈湴鍖栨ā寮?鍥炵▼鐩存帴 sendto) */
    struct sockaddr_in bnd;        /* 鑺傜偣 UDP 涓户绔偣 */
    ULONG    recId;                /* 椹卞姩璁¤垂璁板綍 ID */
    ULONG    pid;
    unsigned long long up, down;
    DWORD    lastTick;
    int      reported;
} UDP_FLOW;
static UDP_FLOW g_flows[MAX_UDP_FLOWS];

/* ===== mode 3:鐩爣 IP 鏈湴鍖?鐩爣钀芥垚鏈満闄勫姞鍦板潃 + 缁戠洰鏍囩鐐规敹鍙? =====
 * 鏈哄埗:鐩爣 IP 鍔犱负鏈満鐜洖鎺ュ彛鐨?/32 闄勫姞鍦板潃 鈫?bind(鐩爣 ip:port) 鐨勫鎺ュ瓧
 * 鐩存帴鏀跺埌搴旂敤鏁版嵁鎶?婧?搴旂敤绔偣)鈫?SOCKS 杞彂;鍥炵▼浠庡悓涓€濂楁帴瀛?sendto(搴旂敤),
 * 婧愬ぉ鐒舵槸鐩爣绔偣 鈥斺€?闆堕┍鍔ㄦ暟鎹潰,connected 璇箟鍘熺敓婊¤冻銆? * 鍓嶇疆(瀹炶瘉):bind 浼€犳簮浠呭湪"鐩爣 IP 宸叉湰鍦板寲"鏃舵垚绔?10049 鍚﹀垯)銆?*/
#define MAX_LOCTGT 32
typedef struct {
    int      active;
    struct sockaddr_in T;
    SOCKET   s;
    int      ipRef;                /* 鍚?IP 寮曠敤璁℃暟(鍚?IP 澶氱鍙? */
    DWORD    lastTick;
} LOCTGT;
static LOCTGT   g_locTgts[MAX_LOCTGT];
static NET_LUID g_LoopLuid;
static int      g_LoopLuidOk = 0;
static CRITICAL_SECTION g_locCs;

/* ===== 基础设施 IP 黑名单:一律拒绝本地化 =====
 * 事故(2026-10-17,虚拟机"网络又断了"):某条 UDP 流的目标10.10.10.254(上游节点)
 * 被本地化为回环 /32 后,引擎发往节点:1081 的上游 TCP 全部被本机协议栈吞掉(拒连)
 * -> 代理全灭、DNS 全灭;强杀进程又跳过清理,残留 /32 持续劫持,重启不自愈。
 * 规则:127/8、组播、ANY/广播、链路本地、RFC1918 私网、本机各接口地址、默认网关、
 * 上游节点 IP 一律拒绝本地化;LocInit 时清理上进程残留的回环 /32(本引擎是唯一添加者)。 */
#define MAX_LOCBLOCK 16
static ULONG g_locBlock[MAX_LOCBLOCK];       /* 本机地址 + 默认网关(LocInit 采集) */
static int   g_locBlockN = 0;
static volatile LONG g_locNodeIpMem = 0;     /* g_node.ip 镜像(内存序,免锁读) */

static void LocSetNodeIp(const char* ip)
{
    struct in_addr a;
    a.s_addr = 0;
    if (ip && inet_pton(AF_INET, ip, &a) != 1) a.s_addr = 0;
    InterlockedExchange(&g_locNodeIpMem, (LONG)a.s_addr);
}

static void LocCollectBlock(void)
{
    PMIB_UNICASTIPADDRESS_TABLE tbl = NULL;
    MIB_IPFORWARDROW fr;
    UINT i;
    g_locBlockN = 0;
    if (GetUnicastIpAddressTable(AF_INET, &tbl) == NO_ERROR) {
        for (i = 0; i < tbl->NumEntries && g_locBlockN < MAX_LOCBLOCK; i++)
            if (tbl->Table[i].Address.si_family == AF_INET)
                g_locBlock[g_locBlockN++] = tbl->Table[i].Address.Ipv4.sin_addr.s_addr;
        FreeMibTable(tbl);
    }
    if (GetBestRoute(0, 0, &fr) == NO_ERROR && g_locBlockN < MAX_LOCBLOCK)
        g_locBlock[g_locBlockN++] = fr.dwForwardNextHop;
    LogF("loc: block n=%d", g_locBlockN);
}

static int LocBlockedIp(ULONG ipMem)
{
    ULONG a = ntohl(ipMem);
    ULONG node = (ULONG)InterlockedCompareExchange(&g_locNodeIpMem, 0, 0);
    int i;
    if ((a & 0xFF000000u) == 0x7F000000u) return 1;        /* 127/8 */
    if ((a & 0xF0000000u) == 0xE0000000u) return 1;        /* 224/4 组播 */
    if (a == 0 || a == 0xFFFFFFFFu) return 1;              /* ANY / 广播 */
    if ((a & 0xFFFF0000u) == 0xA9FE0000u) return 1;        /* 169.254/16 */
    if ((a & 0xFF000000u) == 0x0A000000u) return 1;        /* 10/8 私网 */
    if ((a & 0xFFF00000u) == 0xAC100000u) return 1;        /* 172.16/12 私网 */
    if ((a & 0xFFFF0000u) == 0xC0A80000u) return 1;        /* 192.168/16 私网 */
    if (node && node == ipMem) return 1;                    /* 上游节点 */
    for (i = 0; i < g_locBlockN; i++)
        if (g_locBlock[i] == ipMem) return 1;               /* 本机地址 / 默认网关 */
    return 0;
}

/* 寮曟搸鎯版€у垵濮嬪寲(骞傜瓑,鎵€鏈夊鍑哄叆鍙ｇ粺涓€璋冪敤)銆? * 鍘嗗彶 bug(GUI"娴嬭瘯杩炴帴"姘歌繙澶辫触 / 鎴愬姛鍚庡伓鍙戝穿婧?:
 *   鈶?WSAStartup 鍙湪 InitData 閲屽仛 鈫?CheckSocks5 鍏堜簬 InitData 璋冪敤鏃?socket() 蹇呰触;
 *   鈶?g_cs/g_locCs 鍙湪 InitData/StartRelay 閲屽垵濮嬪寲 鈫?鍚屽満鏅垚鍔熻矾寰? *      EnterCriticalSection(&g_cs) 浣滅敤浜庢湭鍒濆鍖栧璞?= 宕╂簝銆?*/
static volatile LONG g_locCsReady = 0;
static void EngineLazyInit(void)
{
    if (InterlockedCompareExchange(&g_csReady, 1, 0) == 0)
        InitializeCriticalSection(&g_cs);
    if (InterlockedCompareExchange(&g_locCsReady, 1, 0) == 0)
        InitializeCriticalSection(&g_locCs);
    if (g_hStopEvent == NULL) {
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        InterlockedCompareExchangePointer((PVOID*)&g_hStopEvent, ev, NULL);
    }
    WsaEnsure();
}

static int LocInit(void)
{
    PMIB_UNICASTIPADDRESS_TABLE tbl = NULL;
    UINT i;
    HMODULE hIp = LoadLibraryW(L"iphlpapi.dll");
    if (hIp) {
        pAddUnicastIpAddressEntry = (PFN_AddUnicastIpAddressEntry)GetProcAddress(hIp, "CreateUnicastIpAddressEntry");
        if (!pAddUnicastIpAddressEntry)
            pAddUnicastIpAddressEntry = (PFN_AddUnicastIpAddressEntry)GetProcAddress(hIp, "AddUnicastIpAddressEntry");
        pRemoveUnicastIpAddressEntry = (PFN_RemoveUnicastIpAddressEntry)GetProcAddress(hIp, "DeleteUnicastIpAddressEntry");
        if (!pRemoveUnicastIpAddressEntry)
            pRemoveUnicastIpAddressEntry = (PFN_RemoveUnicastIpAddressEntry)GetProcAddress(hIp, "RemoveUnicastIpAddressEntry");
        LogF("loc: api add=%p del=%p", pAddUnicastIpAddressEntry, pRemoveUnicastIpAddressEntry);
    }
    if (GetUnicastIpAddressTable(AF_INET, &tbl) != NO_ERROR) return -1;
    for (i = 0; i < tbl->NumEntries; i++) {
        if (tbl->Table[i].Address.si_family == AF_INET &&
            tbl->Table[i].Address.Ipv4.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
            g_LoopLuid = tbl->Table[i].InterfaceLuid;
            g_LoopLuidOk = 1;
            break;
        }
    }
    /* 自愈:清理残留(强杀/崩溃遗留)的回环 /32 —— 本引擎是此类地址的唯一添加者 */
    if (g_LoopLuidOk && pRemoveUnicastIpAddressEntry) {
        for (i = 0; i < tbl->NumEntries; i++) {
            if (tbl->Table[i].Address.si_family == AF_INET &&
                tbl->Table[i].InterfaceLuid.Value == g_LoopLuid.Value &&
                (ntohl(tbl->Table[i].Address.Ipv4.sin_addr.s_addr) >> 24) != 127) {
                MIB_UNICASTIPADDRESS_ROW row = tbl->Table[i];
                if (pRemoveUnicastIpAddressEntry(&row) == NO_ERROR)
                    LogF("loc: purge stale ip %08x", row.Address.Ipv4.sin_addr.s_addr);
            }
        }
    }
    FreeMibTable(tbl);
    LocCollectBlock();
    return g_LoopLuidOk ? 0 : -1;
}

static int LocIpRef(ULONG ipMem, int add)
{
    MIB_UNICASTIPADDRESS_ROW row;
    int i, refs = 0;
    for (i = 0; i < MAX_LOCTGT; i++)
        if (g_locTgts[i].active && g_locTgts[i].T.sin_addr.s_addr == ipMem) refs++;
    if (add) {
        if (refs == 0) {
            DWORD err;
            if (!pAddUnicastIpAddressEntry) return -1;
            InitializeUnicastIpAddressEntry(&row);
            row.Address.si_family = AF_INET;
            row.Address.Ipv4.sin_addr.s_addr = ipMem;
            row.OnLinkPrefixLength = 32;
            row.InterfaceLuid = g_LoopLuid;
            row.DadState = IpDadStatePreferred;
            err = pAddUnicastIpAddressEntry(&row);
            if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
                LogF("loc: add ip %08x err=%lu", ipMem, err);
                return -1;
            }
            LogF("loc: ip %08x localized", ipMem);
        }
        return 0;
    }
    if (refs <= 1) {
        InitializeUnicastIpAddressEntry(&row);
        row.Address.si_family = AF_INET;
        row.Address.Ipv4.sin_addr.s_addr = ipMem;
        row.OnLinkPrefixLength = 32;
        row.InterfaceLuid = g_LoopLuid;
        if (pRemoveUnicastIpAddressEntry) pRemoveUnicastIpAddressEntry(&row);
        LogF("loc: ip %08x removed", ipMem);
    }
    return 0;
}

static LOCTGT* LocEnsureTarget(const struct sockaddr_in* T)
{
    int i;
    LOCTGT* freeSlot = NULL;
    if (LocBlockedIp(T->sin_addr.s_addr)) {
        LogF("loc: refuse infra ip %08x:%u", T->sin_addr.s_addr, ntohs(T->sin_port));
        return NULL;
    }
    EnterCriticalSection(&g_locCs);
    for (i = 0; i < MAX_LOCTGT; i++) {
        if (g_locTgts[i].active &&
            g_locTgts[i].T.sin_addr.s_addr == T->sin_addr.s_addr &&
            g_locTgts[i].T.sin_port == T->sin_port) {
            g_locTgts[i].lastTick = GetTickCount();
            LeaveCriticalSection(&g_locCs);
            return &g_locTgts[i];
        }
        if (!g_locTgts[i].active && !freeSlot) freeSlot = &g_locTgts[i];
    }
    if (!freeSlot) {
        /* 娣樻卑鏈€涔呮湭娲诲姩 */
        int oldest = 0;
        for (i = 1; i < MAX_LOCTGT; i++)
            if (g_locTgts[i].lastTick < g_locTgts[oldest].lastTick) oldest = i;
        freeSlot = &g_locTgts[oldest];
        if (freeSlot->s != INVALID_SOCKET) closesocket(freeSlot->s);
        LocIpRef(freeSlot->T.sin_addr.s_addr, 0);
        freeSlot->active = 0;
    }
    memset(freeSlot, 0, sizeof(*freeSlot));
    freeSlot->T = *T;
    freeSlot->s = INVALID_SOCKET;
    if (LocIpRef(T->sin_addr.s_addr, 1) != 0) {
        LeaveCriticalSection(&g_locCs);
        return NULL;
    }
    freeSlot->s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (freeSlot->s == INVALID_SOCKET) {
        LocIpRef(T->sin_addr.s_addr, 0);
        LeaveCriticalSection(&g_locCs);
        return NULL;
    }
    {
        BOOL reuse = TRUE;
        setsockopt(freeSlot->s, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
    }
    if (bind(freeSlot->s, (struct sockaddr*)&freeSlot->T, sizeof(freeSlot->T)) != 0) {
        LogF("loc: bind fail %08x:%u err=%d", T->sin_addr.s_addr, ntohs(T->sin_port), WSAGetLastError());
        closesocket(freeSlot->s);
        LocIpRef(T->sin_addr.s_addr, 0);
        freeSlot->s = INVALID_SOCKET;
        LeaveCriticalSection(&g_locCs);
        return NULL;
    }
    freeSlot->active = 1;
    freeSlot->lastTick = GetTickCount();
    LogF("loc: target ready %08x:%u", T->sin_addr.s_addr, ntohs(T->sin_port));
    LeaveCriticalSection(&g_locCs);
    return freeSlot;
}

static void UdpReport(ULONG recId, DWORD up, DWORD down)
{
    HPX_REPORT rep;
    rep.upDelta = up;
    rep.downDelta = down;
    rep.id = recId;
    DevControl(IOCTL_HPX_UDP_REPORT, &rep, sizeof(rep), NULL, 0, NULL);
}

/* 鍥炲寘鑵?鎶婃潵鑷師濮嬬洰鏍?浼€犳簮)鐨勬暟鎹姤鎶曢€掔粰搴旂敤绔偣銆? * 妯″紡 1/0:椹卞姩娉ㄥ叆(缃戠粶鎺ユ敹娉ㄥ叆,浼€犳簮 = 鍘熷鐩爣);
 * 妯″紡 2:鐢ㄦ埛鎬?bind 浼€犳簮鐩存姇(鐩爣 IP 宸叉湰鍦板寲鏃跺繀鎴?銆?*/
static int UdpDeliverToApp(UDP_FLOW* f, const void* payload, int plen)
{
    int ok = 0;

    /* mode 3(鏈湴鍖?:浠庣洰鏍囩粦瀹氬鎺ュ瓧鍥炲彂 鈥斺€?婧愬ぉ鐒舵槸鍘熷鐩爣绔偣 */
    if (f->locMode && f->loc != INVALID_SOCKET) {
        if (sendto(f->loc, (const char*)payload, plen, 0,
                   (struct sockaddr*)&f->app, sizeof(f->app)) == plen)
            return 1;
        LogF("udp: loc deliver fail err=%d", WSAGetLastError());
        return 0;
    }

    if (g_udpBackMode != 2) {
        DWORD msgLen = (DWORD)(sizeof(HPX_UDP_INJECT_HDR) + plen);
        HPX_UDP_INJECT_HDR* msg = (HPX_UDP_INJECT_HDR*)malloc(msgLen);
        if (msg) {
            DWORD br = 0;
            memset(msg, 0, sizeof(*msg));
            msg->cmd = HPX_CTRL_UDP_INJECT;
            msg->payloadLen = plen;
            msg->srcIp = f->tgt.sin_addr.s_addr;      /* 鍐呭瓨搴忕洿鍏?*/
            memcpy(&msg->srcPortNet, &f->tgt.sin_port, 2);   /* 缃戠粶搴忓師濮嬪瓧鑺?*/
            msg->dstIp = f->app.sin_addr.s_addr;
            memcpy(&msg->dstPortNet, &f->app.sin_port, 2);
            if (plen) memcpy((unsigned char*)msg + sizeof(HPX_UDP_INJECT_HDR), payload, plen);
            if (DevControl(IOCTL_HPX_CONTROL, msg, msgLen, msg, msgLen, &br))
                ok = 1;
            free(msg);
        }
        if (ok) return 1;
        if (g_udpBackMode == 1) return 0;                 /* 寮哄埗娉ㄥ叆妯″紡:涓嶉€€鍖?*/
    }

    /* 澶囬€?姣忓寘鏂板缓濂楁帴瀛楃粦鍘熷鐩爣(浼€犳簮)鈫?sendto 搴旂敤绔偣 */
    {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s != INVALID_SOCKET) {
            BOOL reuse = TRUE;
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
            if (bind(s, (struct sockaddr*)&f->tgt, sizeof(f->tgt)) == 0) {
                if (sendto(s, (const char*)payload, plen, 0,
                           (struct sockaddr*)&f->app, sizeof(f->app)) == plen)
                    ok = 1;
            } else {
                LogF("udp: bind-forged fail tgt=%08x:%u gle=%lu",
                     f->tgt.sin_addr.s_addr, ntohs(f->tgt.sin_port), WSAGetLastError());
            }
            closesocket(s);
        }
    }
    return ok;
}

static UDP_FLOW* UdpFindFlowBySocket(SOCKET us)
{
    int i;
    for (i = 0; i < MAX_UDP_FLOWS; i++)
        if (g_flows[i].active && g_flows[i].us == us) return &g_flows[i];
    return NULL;
}

static UDP_FLOW* UdpFindFlow(const struct sockaddr_in* app, const struct sockaddr_in* tgt)
{
    int i;
    for (i = 0; i < MAX_UDP_FLOWS; i++) {
        if (!g_flows[i].active) continue;
        if (g_flows[i].app.sin_addr.s_addr == app->sin_addr.s_addr &&
            g_flows[i].app.sin_port == app->sin_port &&
            g_flows[i].tgt.sin_addr.s_addr == tgt->sin_addr.s_addr &&
            g_flows[i].tgt.sin_port == tgt->sin_port)
            return &g_flows[i];
    }
    return NULL;
}

static UDP_FLOW* UdpAllocFlow(void)
{
    int i;
    DWORD now = GetTickCount();
    for (i = 0; i < MAX_UDP_FLOWS; i++)
        if (!g_flows[i].active) return &g_flows[i];
    /* 娣樻卑鏈€涔呮湭娲诲姩娴?鍏堢粨绠? */
    {
        int oldest = 0;
        for (i = 1; i < MAX_UDP_FLOWS; i++)
            if (g_flows[i].lastTick < g_flows[oldest].lastTick) oldest = i;
        if (now - g_flows[oldest].lastTick > 1000) {
            UDP_FLOW* f = &g_flows[oldest];
            if (f->up || f->down)
                UdpReport(f->recId, (DWORD)f->up, (DWORD)f->down);
            UdpReport(f->recId, 0, 0);
            if (f->us != INVALID_SOCKET) closesocket(f->us);
            if (f->ctrl != INVALID_SOCKET) closesocket(f->ctrl);
            f->active = 0;
            return f;
        }
    }
    return NULL;
}

static void UdpCloseFlow(UDP_FLOW* f, const char* why)
{
    if (!f->active) return;
    if (f->up || f->down)
        UdpReport(f->recId, (DWORD)f->up, (DWORD)f->down);
    UdpReport(f->recId, 0, 0);
    if (f->us != INVALID_SOCKET) closesocket(f->us);
    if (f->ctrl != INVALID_SOCKET) closesocket(f->ctrl);
    LogF("udp: close %s up=%llu down=%llu", why, f->up, f->down);
    f->active = 0;
}

/* 搴旂敤鏁版嵁鎶ュ鐞?娉ㄥ叆璺緞涓庢湰鍦板寲璺緞鍏辩敤):
 * from=搴旂敤绔偣, tgt=鍘熷鐩殑, loc=鏈湴鍖栫洰鏍囧鎺ュ瓧(mode 3 鏃堕潪绌? */
static void UdpHandleAppDatagram(const struct sockaddr_in* from,
                                 const struct sockaddr_in* tgtIn,
                                 const char* payload, int plen, SOCKET loc,
                                 ULONG recIdIn)
{
    struct sockaddr_in tgt = *tgtIn;
    UDP_FLOW* f = UdpFindFlow(from, &tgt);
    if (f == NULL) {
        f = UdpAllocFlow();
        if (f == NULL) { LogF("udp: flow table full"); return; }
        memset(f, 0, sizeof(*f));
        f->app = *from;
        f->tgt = tgt;
        f->ctrl = INVALID_SOCKET;
        f->us = INVALID_SOCKET;
        f->loc = loc;
        f->locMode = (loc != INVALID_SOCKET);
        f->recId = recIdIn;
        if (f->locMode && f->recId == 0) {
            /* 鏈湴鍖栬矾寰?鐢辩洰鏍囧鎺ュ瓧鐨勯┍鍔ㄤ簨浠舵淳鐢?璁¤垂璁板綍鎸?PID 鎵炬渶鏂?*/
            int i;
            for (i = 0; i < MAX_PROCS; i++) {
                if (g_procs[i].active) { f->recId = g_procs[i].recId; f->pid = g_procs[i].pid; }
            }
        } else {
            /* 非本地化路径:recId 已由调用方按 claim 的 PID 解析传入 */
        }
        /* 姣忔祦鐙珛 UDP ASSOCIATE + 绉佹湁涓婅濂楁帴瀛?鑺傜偣閽夐涓暟鎹姤) */
        /* 上游关联重试 3 次(300ms 退避):吸收节点 UDP ASSOCIATE 偶发抖动 */
        {
            int uatt;
            int okAssoc = 0;
            for (uatt = 0; uatt < 3 && !okAssoc; uatt++) {
                if (uatt) {
                    if (f->ctrl != INVALID_SOCKET) closesocket(f->ctrl);
                    f->ctrl = INVALID_SOCKET;
                    Sleep(300);
                }
                if (s5_open(&g_node, &f->ctrl) == 0 &&
                    s5_associate(f->ctrl, &f->bnd) == 0)
                    okAssoc = 1;
            }
            if (!okAssoc) {
                LogF("udp: associate fail err=%d", WSAGetLastError());
                if (f->ctrl != INVALID_SOCKET) closesocket(f->ctrl);
                f->active = 0;
                return;
            }
        }
        f->us = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (f->us == INVALID_SOCKET) {
            closesocket(f->ctrl);
            f->active = 0;
            return;
        }
        {
            int big = 1 << 20;
            setsockopt(f->us, SOL_SOCKET, SO_RCVBUF, (const char*)&big, sizeof(big));
            setsockopt(f->us, SOL_SOCKET, SO_SNDBUF, (const char*)&big, sizeof(big));
        }
        f->active = 1;
        f->lastTick = GetTickCount();
        LogF("udp: flow up app=%08x:%u dst=%08x:%u mode=%d",
             from->sin_addr.s_addr, ntohs(from->sin_port),
             tgt.sin_addr.s_addr, ntohs(tgt.sin_port), f->locMode);
    }
    {
        char encap[65536];
        int elen = s5_udp_encap(&f->tgt, payload, plen, encap, sizeof(encap));
        if (elen > 0 && sendto(f->us, encap, elen, 0,
                               (struct sockaddr*)&f->bnd, sizeof(f->bnd)) == elen) {
            f->up += plen;
            f->lastTick = GetTickCount();
            if (f->up >= 1) {
                UdpReport(f->recId, (DWORD)f->up, 0);
                f->up = 0;
            }
        } else {
            LogF("udp: fwd fail err=%d", WSAGetLastError());
        }
    }
}

static DWORD WINAPI UdpThread(LPVOID unused)
{
    char pkt[65536];
    (void)unused;
    while (!InterlockedCompareExchange(&g_stop, 0, 0)) {
        fd_set rf;
        struct timeval tv;
        int r, i;
        FD_ZERO(&rf);
        if (g_udpSock != INVALID_SOCKET) FD_SET(g_udpSock, &rf);
        for (i = 0; i < MAX_LOCTGT; i++)
            if (g_locTgts[i].active && g_locTgts[i].s != INVALID_SOCKET) FD_SET(g_locTgts[i].s, &rf);
        for (i = 0; i < MAX_UDP_FLOWS; i++)
            if (g_flows[i].active && g_flows[i].us != INVALID_SOCKET) FD_SET(g_flows[i].us, &rf);
        tv.tv_sec = 1; tv.tv_usec = 0;
        r = select(0, &rf, NULL, NULL, &tv);
        if (r < 0) break;
        if (r == 0) {
            DWORD now = GetTickCount();
            for (i = 0; i < MAX_UDP_FLOWS; i++)
                if (g_flows[i].active && now - g_flows[i].lastTick > 90000)
                    UdpCloseFlow(&g_flows[i], "idle");
            continue;
        }

        /* 娉ㄥ叆璺緞:椹卞姩鍚告敹鍖?甯﹀熬鏍?鈫?璁ら */
        if (g_udpSock != INVALID_SOCKET && FD_ISSET(g_udpSock, &rf)) {
            struct sockaddr_in from;
            int flen = sizeof(from), n;
            n = recvfrom(g_udpSock, pkt, sizeof(pkt), 0, (struct sockaddr*)&from, &flen);
            if (n > 0) {
                ULONG flowId = 0;
                HPX_REQRESP claim;
                struct sockaddr_in tgt;
                const char* payload = pkt;
                int plen = n;
                LogF("udp: in n=%d from=%08x:%u", n, from.sin_addr.s_addr, ntohs(from.sin_port));

                if (n >= 12 && memcmp(pkt + n - 12, "HPXTRAIL", 8) == 0) {
                    memcpy(&flowId, pkt + n - 4, 4);
                    plen = n - 12;
                }
                memset(&claim, 0, sizeof(claim));
                if (flowId) {
                    if (!ClaimDest(HPX_REQ_BY_ID, flowId, 0, 17, &claim) ||
                        claim.u.dst.protocol != 17) {
                        LogF("udp: claim-by-id fail id=%u", flowId);
                        continue;
                    }
                } else if (!ClaimDest(HPX_REQ_BY_ENDPOINT,
                                      (ULONG)from.sin_port, (ULONG)from.sin_addr.s_addr, 17, &claim) ||
                           claim.u.dst.protocol != 17) {
                    LogF("udp: claim fail from=%08x:%u", from.sin_addr.s_addr, ntohs(from.sin_port));
                    continue;
                }
                memset(&tgt, 0, sizeof(tgt));
                tgt.sin_family = AF_INET;
                tgt.sin_addr.s_addr = claim.u.dst.remoteIpV4;
                tgt.sin_port = htons((unsigned short)claim.u.dst.remotePort);
                {
                    ENG_PROC* ep = FindProc(claim.u.dst.pid);
                    UdpHandleAppDatagram(&from, &tgt, payload, plen, INVALID_SOCKET,
                                         ep ? ep->recId : 0);
                }
            }
        }

        /* 鏈湴鍖栬矾寰?鐩爣濂楁帴瀛楃洿鎺ユ敹鍒板簲鐢ㄦ暟鎹姤(婧?搴旂敤绔偣) */
        for (i = 0; i < MAX_LOCTGT; i++) {
            if (!g_locTgts[i].active || g_locTgts[i].s == INVALID_SOCKET ||
                !FD_ISSET(g_locTgts[i].s, &rf)) continue;
            {
                struct sockaddr_in from;
                int flen = sizeof(from), n;
                n = recvfrom(g_locTgts[i].s, pkt, sizeof(pkt), 0, (struct sockaddr*)&from, &flen);
                if (n > 0) {
                    g_locTgts[i].lastTick = GetTickCount();
                    UdpHandleAppDatagram(&from, &g_locTgts[i].T, pkt, n, g_locTgts[i].s, 0);
                }
            }
        }

        for (i = 0; i < MAX_UDP_FLOWS; i++) {
            UDP_FLOW* f = &g_flows[i];
            if (!f->active || f->us == INVALID_SOCKET || !FD_ISSET(f->us, &rf)) continue;
            {
                struct sockaddr_in src;
                int slen = sizeof(src), n;
                char rbuf[65536];
                n = recvfrom(f->us, rbuf, sizeof(rbuf), 0, (struct sockaddr*)&src, &slen);
                if (n > 0) {
                    struct sockaddr_in inner;
                    const void* payload;
                    int plen;
                    if (s5_udp_decap(rbuf, n, &inner, &payload, &plen) == 0) {
                        if (UdpDeliverToApp(f, payload, plen)) {
                            f->down += plen;
                            f->lastTick = GetTickCount();
                            if (1) {          /* 灏忔祦鍗虫姤:璁¤垂鍙婃椂鍙 */
                                UdpReport(f->recId, (DWORD)f->up, (DWORD)f->down);
                                f->up = f->down = 0;
                            }
                        } else {
                            LogF("udp: deliver fail plen=%d", plen);
                        }
                    }
                }
            }
        }
    }
    return 0;
}

/* ============================ 浜嬩欢娉?============================ */
static DWORD WINAPI EventThread(LPVOID unused)
{
    ULONG cursor = 0;
    (void)unused;
    while (!InterlockedCompareExchange(&g_stop, 0, 0)) {
        unsigned char buf[HPX_EVENT_BUFFER_SIZE];
        DWORD br = 0;
        if (!DevControl(IOCTL_HPX_POLL_EVENTS, &cursor, sizeof(cursor), buf, sizeof(buf), &br)) {
            Sleep(200);
            continue;
        }
        if (br >= sizeof(HPX_EVENT)) {
            DWORD off = 0;
            while (off + sizeof(HPX_EVENT) <= br) {
                HPX_EVENT* e = (HPX_EVENT*)(buf + off);
                cursor = e->cursor;
                if (e->type == EV_RECORD_ADDED)
                    LogF("evt: record added id=%u pid=%u", e->u.status.code, e->u.status.reserved[0]);
                else if (e->type == EV_RECORD_REMOVED)
                    LogF("evt: record removed id=%u", e->u.status.code);
                else if (e->type == EV_LIMIT_REACHED)
                    LogF("evt: limit reached id=%u pid=%u", e->u.status.code, e->u.status.reserved[0]);
                else if (e->type == EV_FLOW_REDIRECTED) {
                    /* 鏈湴鍖栨ā寮?mode 3):UDP 鐩爣鍑虹幇鍗抽缃洰鏍囩鐐瑰鎺ュ瓧 */
                    ULONG packed = e->u.status.reserved[2];
                    UCHAR proto = (UCHAR)(packed & 0xFF);
                    USHORT tport = (USHORT)(packed >> 8);
                    LogF("evt: flow redirected id=%u pid=%u ip=%08x port=%u proto=%u",
                         e->u.status.code, e->u.status.reserved[0],
                         e->u.status.reserved[1], tport, proto);
                    if (g_udpBackMode == 3 && proto == 17 && g_LoopLuidOk) {
                        struct sockaddr_in T;
                        memset(&T, 0, sizeof(T));
                        T.sin_family = AF_INET;
                        T.sin_addr.s_addr = e->u.status.reserved[1];   /* sin_addr 鍐呭瓨搴?*/
                        T.sin_port = htons(tport);
                        if (LocEnsureTarget(&T) == NULL)
                            LogF("evt: loc target fail %08x:%u", T.sin_addr.s_addr, tport);
                    }
                }
                off += e->size ? e->size : sizeof(HPX_EVENT);
            }
        } else {
            Sleep(200);
        }
    }
    return 0;
}

/* ============================ 鐢熷懡鍛ㄦ湡 ============================ */
static int StartRelay(void)
{
    struct sockaddr_in sa;
    u_long nb = 1;

    g_tcpListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_tcpListen == INVALID_SOCKET) return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* 鏈湴閲嶅畾鍚戞寜绮剧‘缁戝畾閫掍氦 */
    sa.sin_port = htons((unsigned short)g_tcpPort);
    if (bind(g_tcpListen, (struct sockaddr*)&sa, sizeof(sa)) != 0 ||
        listen(g_tcpListen, 64) != 0) {
        LogF("relay: tcp bind/listen fail port=%d err=%d", g_tcpPort, WSAGetLastError());
        closesocket(g_tcpListen);
        g_tcpListen = INVALID_SOCKET;
        return -1;
    }

    g_udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_udpSock == INVALID_SOCKET) return -1;
    {
        int big = 1 << 20;
        setsockopt(g_udpSock, SOL_SOCKET, SO_RCVBUF, (const char*)&big, sizeof(big));
        setsockopt(g_udpSock, SOL_SOCKET, SO_SNDBUF, (const char*)&big, sizeof(big));
    }
    sa.sin_port = htons((unsigned short)g_udpPort);
    if (bind(g_udpSock, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        LogF("relay: udp bind fail port=%d err=%d", g_udpPort, WSAGetLastError());
        closesocket(g_udpSock);
        g_udpSock = INVALID_SOCKET;
        return -1;
    }
    ioctlsocket(g_udpSock, FIONBIO, &nb);

    LanPush();                          /* 局域网网段下发:访问局域网一律不代理 */
    if (g_udpBackMode == 3) {
        if (LocInit() != 0) LogF("relay: loc init fail(loopback LUID not found)");
    }

    InterlockedExchange(&g_stop, 0);
    if (g_hStopEvent) ResetEvent(g_hStopEvent);   /* 复位停止事件:残留置位会让 auto 线程的
                                                    WaitForSingleObject 立即返回 → 500Hz 空转扫描 */
    g_hTcpAccept = CreateThread(NULL, 0, TcpAcceptThread, NULL, 0, NULL);
    g_hUdpThread = CreateThread(NULL, 0, UdpThread, NULL, 0, NULL);
    g_hEvtThread = CreateThread(NULL, 0, EventThread, NULL, 0, NULL);
    g_hAutoThread = CreateThread(NULL, 0, AutoRegThread, NULL, 0, NULL);
    /* 映像名规则重推驱动(自愈):重启/清空后驱动侧规则仍完整,
     * 新进程自第一个 connect 起即被 classify 接管,无登记竞态窗口 */
    {
        int gi;
        EnterCriticalSection(&g_cs);
        for (gi = 0; gi < g_exeCount; gi++) {
            struct { ULONG cmd; ULONG pad; WCHAR name[64]; } ir;
            int k;
            memset(&ir, 0, sizeof(ir));
            ir.cmd = HPX_CTRL_ADD_IMG;
            for (k = 0; k < 63 && g_exeList[gi][k]; k++) ir.name[k] = (WCHAR)(unsigned char)g_exeList[gi][k];
            DevControl(IOCTL_HPX_CONTROL, &ir, sizeof(ir), NULL, 0, NULL);
        }
        LeaveCriticalSection(&g_cs);
    }
    CtrlCmd(HPX_CTRL_RELAY_UP, (ULONG)GetCurrentProcessId(), NULL, 0);  /* 监听就绪后才登记为存活中继 */
    AutoScanOnce();                 /* 鍚姩鍗崇櫥璁扮櫧鍚嶅崟鐜版湁杩涚▼,涓嶇瓑棣栦釜杞 */
    LogF("relay: started tcp=%d udp=%d backMode=%d", g_tcpPort, g_udpPort, g_udpBackMode);
    return 0;
}

static void StopRelay(void)
{
    int i;
    InterlockedExchange(&g_stop, 1);
    if (g_hStopEvent) SetEvent(g_hStopEvent);

    /* 鍏堝叧鐩戝惉/涓户濂楁帴瀛楁墦鐮撮樆濉?*/
    if (g_tcpListen != INVALID_SOCKET) { closesocket(g_tcpListen); g_tcpListen = INVALID_SOCKET; }
    if (g_udpSock != INVALID_SOCKET) { closesocket(g_udpSock); g_udpSock = INVALID_SOCKET; }
    for (i = 0; i < MAX_UDP_FLOWS; i++)
        if (g_flows[i].active) UdpCloseFlow(&g_flows[i], "stop");

    if (g_hTcpAccept) { WaitForSingleObject(g_hTcpAccept, 5000); CloseHandle(g_hTcpAccept); g_hTcpAccept = NULL; }
    if (g_hUdpThread) { WaitForSingleObject(g_hUdpThread, 5000); CloseHandle(g_hUdpThread); g_hUdpThread = NULL; }
    if (g_hEvtThread) { WaitForSingleObject(g_hEvtThread, 2000); CloseHandle(g_hEvtThread); g_hEvtThread = NULL; }
    if (g_hAutoThread) { WaitForSingleObject(g_hAutoThread, 5000); CloseHandle(g_hAutoThread); g_hAutoThread = NULL; }
    if (g_udpBackMode == 3) {
        int i;
        EnterCriticalSection(&g_locCs);
        for (i = 0; i < MAX_LOCTGT; i++) {
            if (g_locTgts[i].active) {
                if (g_locTgts[i].s != INVALID_SOCKET) closesocket(g_locTgts[i].s);
                LocIpRef(g_locTgts[i].T.sin_addr.s_addr, 0);
                g_locTgts[i].active = 0;
            }
        }
        LeaveCriticalSection(&g_locCs);
    }
    CtrlCmd(HPX_CTRL_RELAY_DOWN, (ULONG)GetCurrentProcessId(), NULL, 0); /* 注销本实例;不影响其他在运中继 */
    LogF("relay: stopped");
}

static int OpenDevice(void)
{
    if (g_dev != INVALID_HANDLE_VALUE) return 0;
    g_dev = CreateFileW(HPX_DOS_PATH_W, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) return -1;
    return 0;
}

/* ============================ 瀵煎嚭:9 涓師鍘?API ============================ */

/* InitData:骞傜瓑;ProxyPort<10 鈫?榛樿 TCP 涓户鍙?SetPort<10 鈫?榛樿 UDP 涓户鍙?*/
BOOL WINAPI InitData(int ProxyPort, int SetPort, BOOLEAN Switch)
{
    HPX_HANDSHAKE hs;
    DWORD br = 0;

    (void)Switch;
    if (g_init) return 1;

    EngineLazyInit();

    if (ProxyPort >= 10 && ProxyPort <= 0xFFFF) g_tcpPort = ProxyPort;
    if (SetPort >= 10 && SetPort <= 0xFFFF) g_udpPort = SetPort;

    /* 椹卞姩灏变綅(宸茶鍒欏鐢?鏈涓斿悓鐩綍鏈?.sys 鍒欒嚜鍔ㄨ,瀵归綈鍘熷巶鑷儴缃? */
    {
        DWORD state = 0;
        if (!ServiceExists(HPX_SERVICE_NAME_W, &state)) {
            if (!HpxInstallDriverW(NULL)) {
                LogF("InitData: driver not available");
                /*WSACleanup 宸茬Щ闄?EmptyData/澶辫触璺緞涔嬪悗 CheckSocks5 绛夋帴鍙ｄ粛闇€ Winsock*/
                return 0;
            }
        } else if (state != SERVICE_RUNNING) {
            if (!HpxInstallDriverW(NULL)) {
                LogF("InitData: driver start fail");
                /*WSACleanup 宸茬Щ闄?EmptyData/澶辫触璺緞涔嬪悗 CheckSocks5 绛夋帴鍙ｄ粛闇€ Winsock*/
                return 0;
            }
        }
    }

    if (OpenDevice() != 0) {
        LogF("InitData: open device fail gle=%lu", GetLastError());
        /*WSACleanup 宸茬Щ闄?EmptyData/澶辫触璺緞涔嬪悗 CheckSocks5 绛夋帴鍙ｄ粛闇€ Winsock*/
        return 0;
    }

    memset(&hs, 0, sizeof(hs));
    hs.cbSize = HPX_HANDSHAKE_SIZE;
    hs.driverVersion = HPX_DRIVER_VERSION;
    hs.apiVersion = HPX_API_VERSION;
    if (!DevControl(IOCTL_HPX_HANDSHAKE, &hs, sizeof(hs), &hs, sizeof(hs), &br)) {
        LogF("InitData: handshake fail gle=%lu", GetLastError());
        CloseHandle(g_dev);
        g_dev = INVALID_HANDLE_VALUE;
        /*WSACleanup 宸茬Щ闄?EmptyData/澶辫触璺緞涔嬪悗 CheckSocks5 绛夋帴鍙ｄ粛闇€ Winsock*/
        return 0;
    }

    CtrlCmd(HPX_CTRL_SET_TCP_PORT, (ULONG)g_tcpPort, NULL, 0);
    CtrlCmd(HPX_CTRL_SET_UDP_PORT, (ULONG)g_udpPort, NULL, 0);
    LanPush();                              /* 局域网网段下发:访问局域网一律不代理 */

    if (StartRelay() != 0) {
        CloseHandle(g_dev);
        g_dev = INVALID_HANDLE_VALUE;
        /*WSACleanup 宸茬Щ闄?EmptyData/澶辫触璺緞涔嬪悗 CheckSocks5 绛夋帴鍙ｄ粛闇€ Winsock*/
        return 0;
    }
    CtrlCmd(HPX_CTRL_ENABLE, 1, NULL, 0);
    g_init = 1;
    g_running = 1;
    LogF("InitData: ok tcp=%d udp=%d", g_tcpPort, g_udpPort);
    return 1;
}

/* CheckSocks5:杩炶妭鐐瑰仛 SOCKS5 鎻℃墜鎺㈡祴;鎴愬姛缂撳瓨鑺傜偣閰嶇疆 */
BOOL WINAPI CheckSocks5(int PrxTypes, char* ip, int port, char* user, char* pass)
{
    S5_NODE node;
    SOCKET s;
    (void)PrxTypes;
    EngineLazyInit();
    if (!ip || port <= 0 || port > 65535) return 0;
    memset(&node, 0, sizeof(node));
    strncpy_s(node.ip, sizeof(node.ip), ip, _TRUNCATE);
    node.port = port;
    if (user) strncpy_s(node.user, sizeof(node.user), user, _TRUNCATE);
    if (pass) strncpy_s(node.pass, sizeof(node.pass), pass, _TRUNCATE);
    if (s5_open(&node, &s) != 0) {
        LogF("CheckSocks5: fail %s:%d err=%d", node.ip, node.port, WSAGetLastError());
        return 0;
    }
    closesocket(s);
    EnterCriticalSection(&g_cs);
    g_node = node;
    LocSetNodeIp(node.ip);
    LeaveCriticalSection(&g_cs);
    LogF("CheckSocks5: ok %s:%d", node.ip, node.port);
    return 1;
}

/* SetProxy:key 鏍￠獙(鍘熷巶 MD5 鍏紡)鈫?鐧昏 PID 鈫?瀛樿妭鐐?鈫?璁鹃檺棰?*/
/* 绑定即接管:切断该进程的存量 TCP 连接。池化/保活连接建立于代理启动之前,
 * 不再走 connect → 绕过透明拦截(用户感知"绑定后仍显示未代理 IP");
 * 断开后应用随即重连,新连接即在内核层被拦截 */
static void KillTcpConnsOfPid(DWORD pid)
{
    PMIB_TCPTABLE_OWNER_PID tbl = NULL;
    DWORD sz = 0, i, killed = 0;

    if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;
    tbl = (PMIB_TCPTABLE_OWNER_PID)malloc(sz);
    if (!tbl) return;
    if (GetExtendedTcpTable(tbl, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (i = 0; i < tbl->dwNumEntries; i++) {
            if (tbl->table[i].dwOwningPid != pid) continue;
            tbl->table[i].dwState = MIB_TCP_STATE_DELETE_TCB;
            if (SetTcpEntry((MIB_TCPROW*)&tbl->table[i]) == NO_ERROR) killed++;
        }
    }
    free(tbl);
    if (killed) LogF("stale-tcp: killed %lu conns pid=%lu", killed, pid);
}

/* 绑定动作(映像名规则):切断现存同名进程的存量连接(池化连接建立于绑定前不走 connect) */
static void KillTcpConnsOfImage(const char* image)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    char name[MAX_PATH];
    DWORD self = GetCurrentProcessId();

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == self) continue;
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), NULL, NULL);
            if (_stricmp(name, image) == 0) KillTcpConnsOfPid(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

/* 全局模式:清掉除本中继进程外所有进程的存量 TCP 连接(同上理由) */
static void KillAllStaleTcpConns(void)
{
    PMIB_TCPTABLE_OWNER_PID tbl = NULL;
    DWORD sz = 0, i, killed = 0;
    DWORD self = GetCurrentProcessId();

    if (GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;
    tbl = (PMIB_TCPTABLE_OWNER_PID)malloc(sz);
    if (!tbl) return;
    if (GetExtendedTcpTable(tbl, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (i = 0; i < tbl->dwNumEntries; i++) {
            if (tbl->table[i].dwOwningPid == self) continue;
            tbl->table[i].dwState = MIB_TCP_STATE_DELETE_TCB;
            if (SetTcpEntry((MIB_TCPROW*)&tbl->table[i]) == NO_ERROR) killed++;
        }
    }
    free(tbl);
    if (killed) LogF("stale-tcp: killed %lu conns (global)", killed);
}

BOOL WINAPI SetProxy(int PrxMode, const char* pid, const char* ip, const char* port,
                     const char* user, const char* pass, const char* key)
{
    char expect[33];
    DWORD pidVal;
    int portVal;
    ULONG recId = 0;
    ULONG out = 0;
    DWORD br = 0;

    EngineLazyInit();
    (void)PrxMode;
    if (!pid || !ip || !port) return 0;
    pidVal = (DWORD)strtoul(pid, NULL, 10);
    portVal = atoi(port);
    if (pidVal == 0 || portVal <= 0 || portVal > 65535) return 0;
    if (pidVal == GetCurrentProcessId()) {
        LogF("SetProxy: refuse self pid");
        return 0;
    }

    MakeFactoryKey(pid, ip, expect);
    if (!key || _stricmp(key, expect) != 0) {
        LogF("SetProxy: key mismatch pid=%s", pid);
        return 0;
    }

    /* 鐧昏 PID(椹卞姩鍥炲啓璁¤垂璁板綍 ID) */
    if (!CtrlCmd(HPX_CTRL_ADD_PID, pidVal, &out, sizeof(out))) {
        LogF("SetProxy: add pid fail");
        return 0;
    }
    recId = out;
    KillTcpConnsOfPid(pidVal);   /* 绑定动作:收编该进程池化/保活连接(建立于绑定前不走 connect) */

    EnterCriticalSection(&g_cs);
    {
        ENG_PROC* p = FindProc(pidVal);
        if (!p) {
            int i;
            for (i = 0; i < MAX_PROCS && g_procs[i].active; i++) {}
            if (i < MAX_PROCS) p = &g_procs[i];
        }
        if (p) {
            memset(p, 0, sizeof(*p));
            p->pid = pidVal;
            p->recId = recId;
            p->active = 1;
            p->isAuto = 0;
            p->userStopped = 0;
            if (!LookupImageByPid(pidVal, p->image, sizeof(p->image)))
                strncpy_s(p->image, sizeof(p->image), pid, _TRUNCATE);
        }
        {
            S5_NODE node;
            memset(&node, 0, sizeof(node));
            strncpy_s(node.ip, sizeof(node.ip), ip, _TRUNCATE);
            node.port = portVal;
            if (user) strncpy_s(node.user, sizeof(node.user), user, _TRUNCATE);
            if (pass) strncpy_s(node.pass, sizeof(node.pass), pass, _TRUNCATE);
            g_node = node;
            LocSetNodeIp(node.ip);
        }
    }
    LeaveCriticalSection(&g_cs);

    /* 娴侀噺闄愰(榛樿 100MB) */
    {
        HPX_FLOW_LIMIT lim;
        lim.limitUp = lim.limitDown = HPX_DEFAULT_FLOW_LIMIT;
        DevControl(IOCTL_HPX_FLOW_LIMIT, &lim, sizeof(lim), &out, sizeof(out), &br);
    }
    LogF("SetProxy: pid=%lu rec=%lu node=%s:%d", pidVal, recId, ip, portVal);
    return 1;
}

/* StopProxy:澶辨晥璇?PID 鐨勮褰?璁¤垂鍘嗗彶淇濈暀) */
BOOL WINAPI StopProxy(DWORD pid)
{
    ENG_PROC* p;
    EngineLazyInit();
    EnterCriticalSection(&g_cs);
    p = FindProc(pid);
    if (p) { p->active = 0; p->userStopped = 1; }
    LeaveCriticalSection(&g_cs);
    if (!p) return 0;
    CtrlCmd(HPX_CTRL_REMOVE_PID, pid, NULL, 0);
    LogF("StopProxy: pid=%lu", pid);
    return 1;
}

/* GetProcessFlow:Switch=0 绱 / 1 浼氳瘽澧為噺 */
BOOL WINAPI GetProcessFlow(BOOLEAN Switch, DWORD pid, unsigned long long* up, unsigned long long* down)
{
    ENG_PROC* p;
    HPX_FLOW_STAT st;
    DWORD br = 0;
    ULONG key;
    EngineLazyInit();

    EnterCriticalSection(&g_cs);
    p = FindProc(pid);
    key = p ? p->recId : 0;
    LeaveCriticalSection(&g_cs);
    if (!p) {
        key = pid;                       /* 鍏煎:鎸?PID 鐩存煡椹卞姩 */
    }
    if (!DevControl(IOCTL_HPX_QUERY_FLOW, &key, sizeof(key), &st, sizeof(st), &br) ||
        br < sizeof(st))
        return 0;
    if (up) *up = Switch ? (st.up - (p ? p->baseUp : 0)) : st.up;
    if (down) *down = Switch ? (st.down - (p ? p->baseDown : 0)) : st.down;
    return 1;
}

/* AddFilterExeName:鏄犲儚鍚嶇櫧鍚嶅崟(杩涚▼鍑虹幇鍗宠嚜鍔ㄧ櫥璁颁唬鐞? */
BOOL WINAPI AddFilterExeName(char* ProxyExe)
{
    int i;
    char norm[MAX_PATH];
    EngineLazyInit();
    if (!ProxyExe || !ProxyExe[0]) return 0;
    strncpy_s(norm, sizeof(norm), ProxyExe, _TRUNCATE);
    if (!strchr(norm, '.')) strncat_s(norm, sizeof(norm), ".exe", _TRUNCATE);
    EnterCriticalSection(&g_cs);
    for (i = 0; i < g_exeCount; i++)
        if (_stricmp(g_exeList[i], norm) == 0) { LeaveCriticalSection(&g_cs); return 1; }
    if (g_exeCount < MAX_EXES) {
        strncpy_s(g_exeList[g_exeCount], MAX_PATH, norm, _TRUNCATE);
        g_exeCount++;
    }
    LeaveCriticalSection(&g_cs);
    LogF("AddFilterExeName: %s", norm);
    {
        struct { ULONG cmd; ULONG pad; WCHAR name[64]; } ir;
        int k;
        memset(&ir, 0, sizeof(ir));
        ir.cmd = HPX_CTRL_ADD_IMG;
        for (k = 0; k < 63 && norm[k]; k++) ir.name[k] = (WCHAR)(unsigned char)norm[k];
        DevControl(IOCTL_HPX_CONTROL, &ir, sizeof(ir), NULL, 0, NULL);
    }
    KillTcpConnsOfImage(norm);      /* 绑定动作:收编现存同名进程的池化/保活连接 */
    AutoScanOnce();                 /* 鐜板瓨鍚屽悕杩涚▼绔嬪嵆鐧昏 */
    return 1;
}

/* FilterProcessNet:mode 浣?2 浣?0/2=浠呯洰鏍?pid,1/3=鍏ㄥ眬;
 * a 浣?8 浣嶅姩浣?0=鍔犺繃婊ら」 1=鍒犺繃婊ら」 2=娓呯┖;b = {type(1=IP 2=绔彛 3=鏄犲儚鍚?, value} */
BOOL WINAPI FilterProcessNet(int mode, DWORD pid, void* a, void* b)
{
    unsigned long long action = a ? *(unsigned long long*)a : 0;
    unsigned long long* item = (unsigned long long*)b;
    int type;
    unsigned long long value;
    (void)mode; (void)pid;
    if (!item) return 0;
    type = (int)(item[0] & 0xFFFFFFFF);
    value = item[1];
    switch (action & 0xFF) {
    case 0:
        if (type == 1 && g_filtIpCount < MAX_FILT) {
            g_filtIps[g_filtIpCount++] = (unsigned long)value;
            CtrlCmd(HPX_CTRL_ADD_IP, (ULONG)value, NULL, 0);
        } else if (type == 2 && g_filtPortCount < MAX_FILT) {
            g_filtPorts[g_filtPortCount++] = (unsigned short)value;
            CtrlCmd(HPX_CTRL_ADD_PORT, (ULONG)value, NULL, 0);
        } else if (type == 3) {
            AddFilterExeName((char*)&value);
        }
        return 1;
    case 1:
        if (type == 1) {
            int i;
            for (i = 0; i < g_filtIpCount; i++)
                if (g_filtIps[i] == (unsigned long)value) { g_filtIps[i] = g_filtIps[--g_filtIpCount]; break; }
            CtrlCmd(HPX_CTRL_DEL_IP, (ULONG)value, NULL, 0);
        } else if (type == 2) {
            int i;
            for (i = 0; i < g_filtPortCount; i++)
                if (g_filtPorts[i] == (unsigned short)value) { g_filtPorts[i] = g_filtPorts[--g_filtPortCount]; break; }
            CtrlCmd(HPX_CTRL_DEL_PORT, (ULONG)value, NULL, 0);
        }
        return 1;
    case 2: {
        int i;
        for (i = 0; i < g_filtIpCount; i++) CtrlCmd(HPX_CTRL_DEL_IP, g_filtIps[i], NULL, 0);
        for (i = 0; i < g_filtPortCount; i++) CtrlCmd(HPX_CTRL_DEL_PORT, g_filtPorts[i], NULL, 0);
        g_filtIpCount = g_filtPortCount = 0;
        return 1;
    }
    default:
        return 0;
    }
}

/* FixNet:鍘熷巶姝ゆ帴鍙ｄ細绡℃敼绯荤粺璁剧疆(鍏?UAC/闃茬伀澧?鏉€杩涚▼);鏈疄鐜颁笉澶嶅埢鐮村潖闈?
 * 浠呰瀹¤鏃ュ織骞惰繑鍥炴垚鍔?鏈夋剰宸紓,瑙?docs\DESIGN.md)銆?*/
BOOL WINAPI FixNet(void)
{
    LogF("FixNet: no-op (system tampering intentionally not replicated)");
    return 1;
}

/* EmptyData:鍋滀腑缁?鈫?娓呰褰?鈫?鍏宠澶?椹卞姩鏈嶅姟瑁呭嵏鐢?GUI 鏄惧紡鎺у埗,鏈夋剰宸紓) */
BOOL WINAPI EmptyData(void)
{
    if (!g_init) return 0;
    CtrlCmd(HPX_CTRL_ENABLE, 0, NULL, 0);
    StopRelay();
    CtrlCmd(HPX_CTRL_RESET, 0, NULL, 0);
    EnterCriticalSection(&g_cs);
    memset(g_procs, 0, sizeof(g_procs));
    LeaveCriticalSection(&g_cs);
    if (g_dev != INVALID_HANDLE_VALUE) {
        CloseHandle(g_dev);
        g_dev = INVALID_HANDLE_VALUE;
    }
    g_init = 0;
    g_running = 0;
    LogF("EmptyData: done");
    /*WSACleanup 宸茬Щ闄?EmptyData/澶辫触璺緞涔嬪悗 CheckSocks5 绛夋帴鍙ｄ粛闇€ Winsock*/
    return 1;
}

/* ============================ 鎵╁睍(GUI/鎺㈤拡) ============================ */
BOOL WINAPI HpxSetUdpBackMode(int mode)
{
    g_udpBackMode = mode;
    LogF("udp back mode = %d", mode);
    return 1;
}

/* 棰勭儹 UDP 鐩爣(mode 3):鎻愬墠鏈湴鍖栫洰鏍?IP 骞剁粦瀹氱洰鏍囩鐐瑰鎺ュ瓧,
 * 娑堥櫎"搴旂敤棣栧寘鏃╀簬娴佸彂鐜?鐨勭珵鎬?搴旂敤鍙厛澹版槑鐩爣鍐嶅彂娴侀噺) */
BOOL WINAPI HpxUdpPreTargetA(const char* ip, int port)
{
    struct sockaddr_in T;
    EngineLazyInit();
    LogF("pre: enter mode=%d ip=%s port=%d loop=%d", g_udpBackMode, ip ? ip : "?", port, g_LoopLuidOk);
    if (g_udpBackMode != 3) return 0;
    if (!g_LoopLuidOk && LocInit() != 0) { LogF("pre: loc init fail"); return 0; }
    memset(&T, 0, sizeof(T));
    T.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &T.sin_addr) != 1) { LogF("pre: bad ip"); return 0; }
    T.sin_port = htons((unsigned short)port);
    if (LocBlockedIp(T.sin_addr.s_addr)) {
        /* 局域网/基础设施目标:驱动侧直连不代理,无需本地化 —— 目标即就绪 */
        LogF("pre: direct target %s:%d (LAN/infra), skip localize", ip, port);
        return 1;
    }
    if (LocEnsureTarget(&T) == NULL) { LogF("pre: ensure fail"); return 0; }
    LogF("pre: ok %s:%d", ip, port);
    return 1;
}

/* 全局模式:代理所有进程(驱动侧 classify 全放行接管,排除中继;私网 LAN 例外直连) */
BOOL WINAPI HpxSetGlobal(int on)
{
    EngineLazyInit();
    LogF("global mode = %d", on ? 1 : 0);
    if (on) KillAllStaleTcpConns();      /* 绑定即接管:清存量连接,防池化直连残留 */
    return CtrlCmd(HPX_CTRL_SET_GLOBAL, (ULONG)(on ? 1 : 0), NULL, 0);
}

BOOL WINAPI HpxDiagW(wchar_t* buf, int cch)
{
    ULONG cls[19], udp[9], audit[8], site[8];
    DWORD br = 0;
    if (g_dev == INVALID_HANDLE_VALUE) OpenDevice();   /* 允许未 InitData 的独立诊断调用 */
    memset(cls, 0, sizeof(cls));
    memset(udp, 0, sizeof(udp));
    memset(audit, 0, sizeof(audit));
    memset(site, 0, sizeof(site));
    CtrlCmd(HPX_CTRL_CLS_DIAG, 0, cls, sizeof(cls));
    CtrlCmd(HPX_CTRL_UDP_DIAG, 0, udp, sizeof(udp));
    CtrlCmd(HPX_CTRL_AUDIT, 0, audit, sizeof(audit));
    CtrlCmd(HPX_CTRL_DIAG, 0, site, sizeof(site));
    _snwprintf_s(buf, cch, _TRUNCATE,
        L"wfpSt=0x%08X bound=%lu step=%lu | cls=%lu pidHit=%lu rewrite=%lu claim=%lu v6blk=%lu quicblk=%lu imgRules=%lu imgHit=%lu | dgHit=%lu dgRw=%lu injOk=%lu injFail=%lu injSt=0x%08X injTag=%lu backRw=%lu exempt=%lu dgPermit=%lu | totalKB=%lu/%lu | ioctl=%lu denied=%lu relayPid=%lu en=%lu",
        site[5], site[6], site[7],
        cls[1], cls[2], cls[3], cls[6], cls[12], cls[18], cls[13], cls[14],
        udp[1], udp[2], audit[7], udp[3], udp[8], cls[17], udp[5], udp[6], udp[7],
        cls[15], cls[16],
        audit[1], audit[2], audit[5], audit[6]);
    (void)br;
    return 1;
}

BOOL WINAPI HpxGetLogA(int idx, char* buf, int cch)
{
    LONG cur = InterlockedCompareExchange(&g_logIdx, 0, 0);
    if (idx < 0 || (LONG)idx >= cur) return 0;
    strncpy_s(buf, cch, g_log[((LONG)idx) % LOG_RING], _TRUNCATE);
    return 1;
}

BOOL WINAPI HpxQueryPidFlowA(DWORD pid, unsigned long long* up, unsigned long long* down)
{
    return GetProcessFlow(0, pid, up, down);
}

BOOL WINAPI HpxMakeKeyA(const char* pid, const char* ip, char* out33)
{
    if (!pid || !ip || !out33) return 0;
    MakeFactoryKey(pid, ip, out33);
    return 1;
}
