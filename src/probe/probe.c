/*
 * probe.c 鈥?HookProxy 绔埌绔帰閽?鑷姩鍖栧垽鎹?渚?VM 鍐呴獙璇?
 *
 * 妯″紡:
 *   e2e  [--node ip:port] [--user u] [--pass p] [--tcp self|ip:port] [--udp ip:port] [--back 0|1|2]
 *        瀹夸富娴佺▼(杩愯寮曟搸,鍗充腑缁ц繘绋?:InitData 鈫?CheckSocks5 鈫? *        娲剧敓娴侀噺瀛愯繘绋?gen)鈫?SetProxy(鐧昏瀛愯繘绋?PID)鈫?鏀跺瓙杩涚▼鍒ゆ嵁 鈫? *        璁℃暟澧為噺 + GetProcessFlow 鈫?StopProxy 鈫?EmptyData銆? *        姣忔杈撳嚭 MARKER-* 琛?缁撳熬 RESULT: PASS|FAIL銆? *   gen  <outFile> [--tcp self|ip:port] [--udp ip:port]
 *        娴侀噺瀛愯繘绋?琚唬鐞嗚繘绋嬭嚜韬仛 TCP/UDP 鎺㈤拡 + 鍥炵幆璐熷鐓?缁撴灉鍐?outFile銆? *   wfp           椹卞姩璇婃柇
 *
 * 缁撴瀯绾︽潫:涓户(寮曟搸)杩涚▼鑷韩姘镐笉琚唬鐞?椹卞姩淇′换闂告帓闄ゆ彙鎵嬭繘绋?,
 * 鏁呰浠ｇ悊娴侀噺蹇呴』鏉ヨ嚜**鍙︿竴涓繘绋?*鈥斺€攅2e 鑷姩娲剧敓 gen 瀛愯繘绋嬫弧瓒炽€? *
 * 缃戠粶杈圭晫(纭害鏉?:瀹夸富/瀛愯繘绋嬬洿杩炰粎鍒颁笂娓?SOCKS5 鑺傜偣(榛樿 10.10.10.254:1081
 * 鍙婂叾 UDP ASSOCIATE 浼撮殢绔偣);鎺㈤拡鐩爣娴侀噺鍏ㄩ儴缁忚妭鐐逛腑缁?
 *   TCP 鐩爣 = 鑷韩 LAN IP 鍥炴樉(鑺傜偣鍥炶繛;澶辫触浜︿笉瑙︾绗笁鏂?;
 *   UDP 鐩爣 = 223.5.5.5:53(缁忛摼;鑺傜偣鎷掔粷 LAN 鐩爣)銆? */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>

#include "hpx_proto.h"
#include "engine.h"

typedef BOOL (WINAPI *PFN_InitData)(int, int, BOOLEAN);
typedef BOOL (WINAPI *PFN_CheckSocks5)(int, char*, int, char*, char*);
typedef BOOL (WINAPI *PFN_SetProxy)(int, const char*, const char*, const char*, const char*, const char*, const char*);
typedef BOOL (WINAPI *PFN_StopProxy)(DWORD);
typedef BOOL (WINAPI *PFN_GetProcessFlow)(BOOLEAN, DWORD, unsigned long long*, unsigned long long*);
typedef BOOL (WINAPI *PFN_EmptyData)(void);
typedef BOOL (WINAPI *PFN_Diag)(wchar_t*, int);
typedef BOOL (WINAPI *PFN_BackMode)(int);
typedef BOOL (WINAPI *PFN_MakeKey)(const char*, const char*, char*);

static HMODULE g_dll;
static PFN_InitData pInitData;
static PFN_CheckSocks5 pCheckSocks5;
static PFN_SetProxy pSetProxy;
static PFN_StopProxy pStopProxy;
static PFN_GetProcessFlow pGetProcessFlow;
static PFN_EmptyData pEmptyData;
static PFN_Diag pDiag;
static PFN_BackMode pBackMode;
static PFN_MakeKey pMakeKey;

static int g_pass = 1;
static FILE* g_out = NULL;

typedef struct { unsigned long long up, down; } FLOW;

/* 活体日志:每条落盘+强制刷盘(写穿),VM 冻结后仍可取证 */
static void LiveLog(const char* fmt, ...)
{
    va_list ap;
    FILE* f = fopen("C:\\hpx\\hold_live.txt", "a");
    if (!f) return;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fflush(f);
    _commit(_fileno(f));
    fclose(f);
}
static void Emit(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_out ? g_out : stdout, fmt, ap);
    va_end(ap);
    fputc('\n', g_out ? g_out : stdout);
    fflush(g_out ? g_out : stdout);
}

static void Verdict(const char* name, int ok, const char* detail)
{
    Emit("MARKER-%s %s %s", name, ok ? "OK" : "FAIL", detail ? detail : "");
    if (!ok) g_pass = 0;
}

static int LoadEngine(void)
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    {
        wchar_t* slash = wcsrchr(path, L'\\');
        if (slash) *(slash + 1) = 0;
        wcsncat_s(path, MAX_PATH, L"HookProxy.dll", _TRUNCATE);
    }
    g_dll = LoadLibraryW(path);
    if (!g_dll) g_dll = LoadLibraryW(L"HookProxy.dll");
    if (!g_dll) { Emit("FATAL: HookProxy.dll not found"); return -1; }
    #define GET(name, var) var = (void*)GetProcAddress(g_dll, name); \
        if (!var) { Emit("FATAL: missing export %s", name); return -1; }
    GET("InitData", pInitData);
    GET("CheckSocks5", pCheckSocks5);
    GET("SetProxy", pSetProxy);
    GET("StopProxy", pStopProxy);
    GET("GetProcessFlow", pGetProcessFlow);
    GET("EmptyData", pEmptyData);
    GET("HpxDiagW", pDiag);
    GET("HpxSetUdpBackMode", pBackMode);
    GET("HpxMakeKeyA", pMakeKey);
    #undef GET
    return 0;
}

static void PrintDiag(const char* tag)
{
    wchar_t buf[512];
    if (pDiag && pDiag(buf, 512)) Emit("DIAG-%s %ls", tag, buf);
}

/* ---------------- DNS 鏌ヨ鏋勯€?鍒よ ---------------- */
static int BuildDnsQuery(unsigned char* out, const char* name)
{
    int i = 12;
    const char* p = name;
    out[0] = 0x34; out[1] = 0x12;
    out[2] = 0x01; out[3] = 0x00;
    out[4] = 0x00; out[5] = 0x01;
    out[6] = out[7] = out[8] = out[9] = out[10] = out[11] = 0;
    while (*p) {
        const char* dot = strchr(p, '.');
        int ln = dot ? (int)(dot - p) : (int)strlen(p);
        out[i++] = (unsigned char)ln;
        memcpy(out + i, p, ln);
        i += ln;
        p += ln + (dot ? 1 : 0);
    }
    out[i++] = 0;
    out[i++] = 0; out[i++] = 1;
    out[i++] = 0; out[i++] = 1;
    return i;
}

static int ParseDnsAnswer(const unsigned char* d, int n, int* ancount)
{
    if (n < 12) return -1;
    if (d[0] != 0x34 || d[1] != 0x12) return -1;
    *ancount = (d[6] << 8) | d[7];
    return d[3] & 0x0F;
}

/* ---------------- TCP 鎺㈤拡(HTTP,缁忛摼) ---------------- */
static int TcpProbe(const char* ip, int port, char* detail, int dlen)
{
    struct sockaddr_in sa;
    SOCKET s;
    char buf[4096];
    int n, total = 0;
    const char* req = "GET / HTTP/1.0\r\nHost: probe\r\n\r\n";

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { _snprintf_s(detail, dlen, _TRUNCATE, "socket-err%d", WSAGetLastError()); return 0; }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);
    sa.sin_port = htons((unsigned short)port);
    {
        int timeoutMs = 15000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
    }
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        _snprintf_s(detail, dlen, _TRUNCATE, "connect-err%d", WSAGetLastError());
        closesocket(s);
        return 0;
    }
    send(s, req, (int)strlen(req), 0);
    n = recv(s, buf, sizeof(buf) - 1, 0);
    if (n > 0) total = n;
    closesocket(s);
    if (total > 0) {
        int i;
        buf[total < 40 ? total : 40] = 0;
        for (i = 0; buf[i]; i++) if ((unsigned char)buf[i] < 32) buf[i] = '.';
        _snprintf_s(detail, dlen, _TRUNCATE, "resp=\"%s\" len=%d", buf, total);
        return 1;
    }
    _snprintf_s(detail, dlen, _TRUNCATE, "no-response");
    return 0;
}

/* ---------------- UDP 鎺㈤拡(缁忛摼;connected / sendto 鍙岃矾) ---------------- */
static int UdpProbe(const char* ip, int port, int connected, char* detail, int dlen)
{
    struct sockaddr_in sa;
    SOCKET s;
    unsigned char q[256], r[2048];
    int qn, n, rcode, ancount;
    struct sockaddr_in from;
    int flen = sizeof(from);

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { _snprintf_s(detail, dlen, _TRUNCATE, "socket-err%d", WSAGetLastError()); return 0; }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);
    sa.sin_port = htons((unsigned short)port);
    {
        int timeoutMs = 8000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
    }
    qn = BuildDnsQuery(q, "www.baidu.com");
    if (connected) {
        if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
            _snprintf_s(detail, dlen, _TRUNCATE, "connect-err%d", WSAGetLastError());
            closesocket(s);
            return 0;
        }
        if (send(s, (const char*)q, qn, 0) != qn) {
            _snprintf_s(detail, dlen, _TRUNCATE, "send-err%d", WSAGetLastError());
            closesocket(s);
            return 0;
        }
        n = recv(s, (char*)r, sizeof(r), 0);
    } else {
        if (sendto(s, (const char*)q, qn, 0, (struct sockaddr*)&sa, sizeof(sa)) != qn) {
            _snprintf_s(detail, dlen, _TRUNCATE, "sendto-err%d", WSAGetLastError());
            closesocket(s);
            return 0;
        }
        n = recvfrom(s, (char*)r, sizeof(r), 0, (struct sockaddr*)&from, &flen);
    }
    closesocket(s);
    if (n <= 0) { _snprintf_s(detail, dlen, _TRUNCATE, "timeout"); return 0; }
    rcode = ParseDnsAnswer(r, n, &ancount);
    if (!connected) {
        char src[64];
        inet_ntop(AF_INET, &from.sin_addr, src, sizeof(src));
        _snprintf_s(detail, dlen, _TRUNCATE, "from=%s:%u n=%d rcode=%d an=%d",
                    src, ntohs(from.sin_port), n, rcode, ancount);
    } else {
        _snprintf_s(detail, dlen, _TRUNCATE, "n=%d rcode=%d an=%d", n, rcode, ancount);
    }
    return (rcode == 0 && ancount >= 1);
}

/* ---------------- 鍥炴樉鏈嶅姟(绾跨▼) ---------------- */
typedef struct { int port; int bindAny; } ECHO_ARG;
static DWORD WINAPI EchoThread(LPVOID arg)
{
    ECHO_ARG* ea = (ECHO_ARG*)arg;
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in sa;
    BOOL reuse = TRUE;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ea->bindAny ? INADDR_ANY : INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)ea->port);
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
    if (bind(ls, (struct sockaddr*)&sa, sizeof(sa)) != 0 || listen(ls, 4) != 0) {
        Emit("ECHO listen port=%d FAIL err=%d", ea->port, WSAGetLastError());
        closesocket(ls);
        return 1;
    }
    Emit("ECHO listen port=%d bindAny=%d ok", ea->port, ea->bindAny);
    for (;;) {
        SOCKET c = accept(ls, NULL, NULL);
        char b[256];
        int n;
        struct sockaddr_in peer;
        int plen = sizeof(peer);
        if (c == INVALID_SOCKET) break;
        if (getpeername(c, (struct sockaddr*)&peer, &plen) == 0)
            Emit("ECHO accept from=%08x:%u", peer.sin_addr.s_addr, ntohs(peer.sin_port));
        n = recv(c, b, sizeof(b), 0);
        Emit("ECHO recv n=%d", n);
        if (n > 0) { int sn = send(c, b, n, 0); Emit("ECHO send n=%d", sn); }
        closesocket(c);
        Emit("ECHO closed");
    }
    return 1;
}

static int GetSelfLanIp(char* out, int cap)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in peer, local;
    int llen = sizeof(local);
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(1081);
    inet_pton(AF_INET, "10.10.10.254", &peer.sin_addr);
    if (connect(s, (struct sockaddr*)&peer, sizeof(peer)) != 0) { closesocket(s); return -1; }
    if (getsockname(s, (struct sockaddr*)&local, &llen) != 0) { closesocket(s); return -1; }
    closesocket(s);
    inet_ntop(AF_INET, &local.sin_addr, out, cap);
    return 0;
}

/* 缁忛摼 TCP 鑷洖鏄?鐩爣 = 鑷韩 LAN IP;鑺傜偣鍥炶繛;澶辫触涓嶈Е纰扮涓夋柟) */
static int SelfTcpProbe(int echoPort, char* detail, int dlen)
{
    char selfIp[64];
    struct sockaddr_in sa;
    SOCKET s;
    char buf[64];
    int n;
    HANDLE th;
    ECHO_ARG ea = { echoPort, 1 };

    if (GetSelfLanIp(selfIp, sizeof(selfIp)) != 0) {
        _snprintf_s(detail, dlen, _TRUNCATE, "selfip-fail");
        return 0;
    }
    th = CreateThread(NULL, 0, EchoThread, &ea, 0, NULL);
    Sleep(400);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, selfIp, &sa.sin_addr);
    sa.sin_port = htons((unsigned short)echoPort);
    {
        int timeoutMs = 15000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
    }
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        _snprintf_s(detail, dlen, _TRUNCATE, "connect-err%d self=%s", WSAGetLastError(), selfIp);
        closesocket(s);
        if (th) { TerminateThread(th, 0); CloseHandle(th); }
        return 0;
    }
    send(s, "SELF", 4, 0);
    n = recv(s, buf, sizeof(buf), 0);
    closesocket(s);
    if (th) { TerminateThread(th, 0); CloseHandle(th); }
    if (n == 4 && memcmp(buf, "SELF", 4) == 0) {
        _snprintf_s(detail, dlen, _TRUNCATE, "echo-ok self=%s:%d", selfIp, echoPort);
        return 1;
    }
    _snprintf_s(detail, dlen, _TRUNCATE, "echo-bad n=%d self=%s", n, selfIp);
    return 0;
}

/* 鍥炵幆璐熷鐓?鐜洖 echo 涓嶅彈浠ｇ悊褰卞搷 */
static int NegCtrl(void)
{
    const int port = 39999;
    ECHO_ARG ea = { port, 0 };
    HANDLE th = CreateThread(NULL, 0, EchoThread, &ea, 0, NULL);
    SOCKET s;
    struct sockaddr_in sa;
    char b[64];
    int n, ok;
    Sleep(300);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)port);
    ok = (connect(s, (struct sockaddr*)&sa, sizeof(sa)) == 0);
    if (ok) {
        send(s, "NEGC", 4, 0);
        n = recv(s, b, sizeof(b), 0);
        ok = (n == 4 && memcmp(b, "NEGC", 4) == 0);
    }
    closesocket(s);
    if (th) { TerminateThread(th, 0); CloseHandle(th); }
    return ok;
}

/* ---------------- 瀛愯繘绋?娴侀噺鍙戠敓 ---------------- */
static int CmdGen(const char* outFile, const char* tcpTgt, int tcpPort,
                  const char* udpTgt, int udpPort)
{
    char detail[256];
    int ok;
    g_out = fopen(outFile, "w");
    if (!g_out) g_out = stdout;

    /* 1. 鍥炵幆璐熷鐓?鏈繘绋嬪凡琚櫥璁?鐜洖涓嶅緱琚唬鐞? */
    ok = NegCtrl();
    Verdict("NEGCTRL", ok, ok ? "loopback-echo-ok" : "loopback-echo-fail");

    /* 2. TCP 缁忛摼 */
    if (strcmp(tcpTgt, "self") == 0)
        ok = SelfTcpProbe(tcpPort ? tcpPort : 39998, detail, sizeof(detail));
    else
        ok = TcpProbe(tcpTgt, tcpPort, detail, sizeof(detail));
    Verdict("TCP", ok, detail);

    /* 3+4. UDP 鍙岃涔夌粡閾?鍚屼竴濂楁帴瀛?鍚屼竴娴?閬垮厤鑺傜偣骞跺彂鍏宠仈鐨勫凡鐭ユ姈鍔?:
     *   鈶?connected 璇箟:connect(T)+send/recv 鈥斺€?鍙敹瀵圭 = 鍥炵▼浼€犳簮鍒ゆ嵁;
     *   鈶?sendto 璇箟:鍚屽鎺ュ瓧 sendto(T)+recv */
    {
        struct sockaddr_in sa;
        SOCKET s;
        unsigned char q[256], r[2048];
        int qn, n, rcode, ancount;
        char d1[160], d2[160];
        int ok1, ok2;
        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, udpTgt, &sa.sin_addr);
        sa.sin_port = htons((unsigned short)udpPort);
        {
            int timeoutMs = 8000;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
        }
        qn = BuildDnsQuery(q, "www.baidu.com");
        ok1 = 0; ok2 = 0;
        _snprintf_s(d1, sizeof(d1), _TRUNCATE, "n/a");
        _snprintf_s(d2, sizeof(d2), _TRUNCATE, "n/a");
        if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) == 0 &&
            send(s, (const char*)q, qn, 0) == qn) {
            n = recv(s, (char*)r, sizeof(r), 0);
            if (n > 0) {
                rcode = ParseDnsAnswer(r, n, &ancount);
                ok1 = (rcode == 0 && ancount >= 1);
                _snprintf_s(d1, sizeof(d1), _TRUNCATE, "connected n=%d rcode=%d an=%d", n, rcode, ancount);
            } else {
                _snprintf_s(d1, sizeof(d1), _TRUNCATE, "connected timeout");
            }
        } else {
            _snprintf_s(d1, sizeof(d1), _TRUNCATE, "connected err=%d", WSAGetLastError());
        }
        if (sendto(s, (const char*)q, qn, 0, (struct sockaddr*)&sa, sizeof(sa)) == qn) {
            struct sockaddr_in from;
            int flen = sizeof(from);
            n = recvfrom(s, (char*)r, sizeof(r), 0, (struct sockaddr*)&from, &flen);
            if (n > 0) {
                char src[64];
                inet_ntop(AF_INET, &from.sin_addr, src, sizeof(src));
                rcode = ParseDnsAnswer(r, n, &ancount);
                ok2 = (rcode == 0 && ancount >= 1 &&
                       from.sin_addr.s_addr == sa.sin_addr.s_addr && from.sin_port == sa.sin_port);
                _snprintf_s(d2, sizeof(d2), _TRUNCATE, "sendto from=%s:%u n=%d rcode=%d an=%d",
                            src, ntohs(from.sin_port), n, rcode, ancount);
            } else {
                _snprintf_s(d2, sizeof(d2), _TRUNCATE, "sendto timeout");
            }
        } else {
            _snprintf_s(d2, sizeof(d2), _TRUNCATE, "sendto err=%d", WSAGetLastError());
        }
        closesocket(s);
        Verdict("UDP-CONN", ok1, d1);
        Verdict("UDP-SENDTO", ok2, d2);
    }

    Emit("RESULT: %s", g_pass ? "PASS" : "FAIL");
    if (g_out && g_out != stdout) fclose(g_out);
    return g_pass ? 0 : 1;
}

/* ---------------- 瀹夸富娴佺▼ ---------------- */
static int CmdE2E(const char* node, int nport, const char* user, const char* pass,
                  const char* tcpTgt, int tcpPort, const char* udpTgt, int udpPort,
                  int backMode)
{
    char pidStr[32], detail[256], key[40], portStr[16], childCmd[MAX_PATH * 2];
    DWORD childPid = 0;
    FLOW flow;
    int ok;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    wchar_t selfPath[MAX_PATH];

    if (LoadEngine() != 0) return 2;
    if (backMode >= 0) pBackMode(backMode);

    _snprintf_s(portStr, sizeof(portStr), _TRUNCATE, "%d", nport);
    Emit("MARKER-START node=%s:%d tcp=%s:%d udp=%s:%d back=%d",
         node, nport, tcpTgt, tcpPort, udpTgt, udpPort, backMode);

    ok = pInitData(0, 0, 0);
    Verdict("INIT", ok, ok ? "" : "InitData failed");
    if (!ok) { Emit("RESULT: FAIL"); return 1; }

    ok = pCheckSocks5(2, (char*)node, nport, (char*)user, (char*)pass);
    Verdict("CHECK", ok, ok ? "" : "SOCKS5 handshake failed");
    if (!ok) { pEmptyData(); Emit("RESULT: FAIL"); return 1; }

    /* 娲剧敓娴侀噺瀛愯繘绋?绛夊緟鐧昏鍚庤嚜鍔ㄥ紑濮?瀛愯繘绋嬪厛鐫?2s) */
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    {
        char exeA[MAX_PATH * 2], outFile[MAX_PATH * 2];
        WideCharToMultiByte(CP_UTF8, 0, selfPath, -1, exeA, sizeof(exeA), NULL, NULL);
        _snprintf_s(outFile, sizeof(outFile), _TRUNCATE, "%s.genout.txt", exeA);
        _snprintf_s(childCmd, sizeof(childCmd), _TRUNCATE,
                    "\"%s\" gen \"%s\" --tcp %s --udp %s:%d", exeA, outFile, tcpTgt, udpTgt, udpPort);
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));
        if (!CreateProcessA(NULL, childCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            Verdict("SPAWN", 0, "CreateProcess failed");
            pEmptyData();
            Emit("RESULT: FAIL");
            return 1;
        }
        childPid = pi.dwProcessId;
        CloseHandle(pi.hThread);
        Emit("MARKER-SPAWN child=%lu", childPid);
    }

    /* 鐧昏瀛愯繘绋?鍘熷巶 key 鍏紡;pid=瀛愯繘绋? */
    _snprintf_s(pidStr, sizeof(pidStr), _TRUNCATE, "%lu", childPid);
    pMakeKey(pidStr, node, key);
    ok = pSetProxy(0, pidStr, node, portStr, user, pass, key);
    Verdict("SET", ok, ok ? key : "SetProxy failed");
    if (!ok) {
        TerminateProcess(pi.hProcess, 3);
        CloseHandle(pi.hProcess);
        pEmptyData();
        Emit("RESULT: FAIL");
        return 1;
    }

    /* 棰勭儹 UDP 鐩爣(鏈湴鍖?+ 缁戝畾鐩爣绔偣;娑堝簲鐢ㄩ鍖呯珵鎬? */
    {
        typedef BOOL (WINAPI *PFN_Pre)(const char*, int);
        PFN_Pre pPre = (PFN_Pre)GetProcAddress(g_dll, "HpxUdpPreTargetA");
        int preOk = pPre ? pPre(udpTgt, udpPort) : 0;
        Verdict("PRETARGET", preOk, udpTgt);
    }

    PrintDiag("PRE");

    /* 绛夊瓙杩涚▼璺戝畬(鈮?0s) */
    WaitForSingleObject(pi.hProcess, 90000);
    CloseHandle(pi.hProcess);

    /* 鏀跺瓙杩涚▼鍒ゆ嵁 */
    {
        char outFile[MAX_PATH * 2], line[512];
        FILE* f;
        WideCharToMultiByte(CP_UTF8, 0, selfPath, -1, outFile, sizeof(outFile), NULL, NULL);
        _snprintf_s(outFile, sizeof(outFile), _TRUNCATE, "%s.genout.txt", outFile);
        f = fopen(outFile, "r");
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                line[strcspn(line, "\r\n")] = 0;
                if (strncmp(line, "MARKER-", 7) == 0) {
                    Emit("%s", line);
                    if (strstr(line, "FAIL")) g_pass = 0;
                }
            }
            fclose(f);
        } else {
            Verdict("GENOUT", 0, "child output missing");
        }
    }

    PrintDiag("POST");

    /* 璁¤垂鍒ゆ嵁(缁忎唬鐞嗙殑纭瘉鏄?:鎬婚噺蹇呴』瑕嗙洊 TCP + 鍙?UDP 鎺㈤拡;
     * 鐩磋繛鍋囬槼鎬у彧鑳界粰鍑?TCP 閲?~157B),UDP 涓よ疆 ~186B 蹇呴』缁忚璐瑰彲瑙?*/
    flow.up = flow.down = 0;
    if (pGetProcessFlow(0, childPid, &flow.up, &flow.down)) {
        char fbuf[80];
        _snprintf_s(fbuf, sizeof(fbuf), _TRUNCATE, "up=%llu down=%llu", flow.up, flow.down);
        Verdict("FLOW", (flow.up >= 70 && flow.down >= 250), fbuf);
    } else {
        Verdict("FLOW", 0, "GetProcessFlow failed");
    }

    /* 鏀跺熬 */
    ok = pStopProxy(childPid);
    Verdict("STOP", ok, "");
    ok = pEmptyData();
    Verdict("TEARDOWN", ok, "");

    (void)detail;
    Emit("RESULT: %s", g_pass ? "PASS" : "FAIL");
    return g_pass ? 0 : 1;
}

/* ---------- 鑷姩鐧昏(鏄犲儚鍚?楠岃瘉:瀹夸富缂栨帓 ---------- */
typedef BOOL (WINAPI *PFN_EnumProc)(int, DWORD*, char*, int, int*, int*, int*);
typedef BOOL (WINAPI *PFN_AddImg)(char*);

static int EnumHasAuto(DWORD pid, int requireActive)
{
    PFN_EnumProc pEnum = (PFN_EnumProc)GetProcAddress(g_dll, "HpxEnumProcA");
    int i;
    if (!pEnum) return 0;
    for (i = 0; i < 128; i++) {
        DWORD p = 0;
        char image[MAX_PATH];
        int act = 0, aut = 0, ust = 0;
        image[0] = 0;
        if (!pEnum(i, &p, image, sizeof(image), &act, &aut, &ust)) break;
        if (p == pid && aut && (!requireActive || act)) return 1;
    }
    return 0;
}

static DWORD SpawnTgt(const char* selfA, const char* outFile, const char* tcpTgt, int secs)
{
    char cmd[MAX_PATH * 3];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, "\"%s\" idle %d \"%s\" --tcp %s", selfA, secs, outFile, tcpTgt);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return 0;
    CloseHandle(pi.hThread);
    return pi.dwProcessId;
}

static int CmdAuto(const char* node, int nport, const char* tcpTgt, int tcpPort)
{
    char selfA[MAX_PATH * 2], tgtA[MAX_PATH * 2], tcpSpec[64];
    DWORD pA, pB, pC;
    PFN_AddImg pAddImg;
    typedef BOOL (WINAPI *PFN_Empty)(void);
    PFN_Empty pEmpty;

    GetModuleFileNameA(NULL, selfA, sizeof(selfA));
    _snprintf_s(tgtA, sizeof(tgtA), _TRUNCATE, "%s", selfA);
    {
        char* slash = strrchr(tgtA, '\\');
        if (slash) strcpy_s(slash + 1, 32, "HpxTgt.exe");
    }
    CopyFileA(selfA, tgtA, FALSE);
    _snprintf_s(tcpSpec, sizeof(tcpSpec), _TRUNCATE, "%s:%d", tcpTgt, tcpPort);

    if (LoadEngine() != 0) return 2;
    pEmpty = (PFN_Empty)GetProcAddress(g_dll, "EmptyData");
    pAddImg = (PFN_AddImg)GetProcAddress(g_dll, "AddFilterExeName");
    Emit("MARKER-START auto node=%s:%d tcp=%s", node, nport, tcpSpec);

    if (!pInitData(0, 0, 0)) { Verdict("INIT", 0, "InitData failed"); Emit("RESULT: FAIL"); return 1; }
    Verdict("INIT", 1, "");
    if (!pCheckSocks5(2, (char*)node, nport, (char*)"", (char*)"")) {
        Verdict("CHECK", 0, "node down"); if (pEmpty) pEmpty(); Emit("RESULT: FAIL"); return 1;
    }
    Verdict("CHECK", 1, "");

    /* 1) 鐧藉悕鍗曡鍒?鈫?鐜板瓨/鍚庣画杩涚▼鑷姩鐧昏(闈惰繘绋嬫槸琚祴瀵硅薄,瀹夸富涓嶈嚜鐧昏) */
    if (!pAddImg || !pAddImg((char*)"HpxTgt.exe")) {
        Verdict("ADDRULE", 0, "AddFilterExeName failed"); if (pEmpty) pEmpty(); Emit("RESULT: FAIL"); return 1;
    }
    Verdict("ADDRULE", 1, "HpxTgt.exe");

    pA = SpawnTgt(tgtA, "C:\\hpx\\ta.txt", tcpSpec, 5);    /* A 鑷劧閫€鍑?娴嬭嚜鍔ㄦ敞閿€) */
    pB = SpawnTgt(tgtA, "C:\\hpx\\tb.txt", tcpSpec, 15);   /* B 瀛樻椿(娴嬭璐? */
    Emit("MARKER-SPAWN a=%lu b=%lu", pA, pB);
    Sleep(2500);
    Verdict("AUTO-REG", (EnumHasAuto(pA, 1) && EnumHasAuto(pB, 1)), "two instances auto-registered");

    /* 2) 瑙勫垯涔嬪悗鏂拌捣鐨勮繘绋嬩篃鑷姩鐧昏 */
    pC = SpawnTgt(tgtA, "C:\\hpx\\tc.txt", tcpSpec, 12);
    Emit("MARKER-SPAWN-LATE c=%lu", pC);
    Sleep(2500);
    Verdict("AUTO-LATE", EnumHasAuto(pC, 1), "late-spawned auto-registered");

    /* 3) 杩涚▼鑷劧閫€鍑?鈫?鑷姩娉ㄩ攢(A 鍦?t鈮?s 閫€鍑? */
    Sleep(2500);
    Verdict("AUTO-UNREG", !EnumHasAuto(pA, 1), "exited instance unregistered");

    /* 4) 鑷姩鐧昏杩涚▼鐨勬祦閲忕‘瀹炵粡浠ｇ悊(璁¤垂纭瘉鏄? */
    {
        typedef BOOL (WINAPI *PFN_QFlow)(DWORD, unsigned long long*, unsigned long long*);
        PFN_QFlow pQ = (PFN_QFlow)GetProcAddress(g_dll, "HpxQueryPidFlowA");
        unsigned long long up = 0, down = 0;
        int ok = 0;
        if (pQ && pQ(pB, &up, &down) && up > 0) ok = 1;
        {
            char fbuf[80];
            _snprintf_s(fbuf, sizeof(fbuf), _TRUNCATE, "pid=%lu up=%llu down=%llu", pB, up, down);
            Verdict("AUTO-PROXY", ok, fbuf);
        }
    }

    if (pStopProxy) pStopProxy(pB);
    if (pStopProxy) pStopProxy(pC);
    if (pEmpty) pEmpty();
    Verdict("TEARDOWN", 1, "");
    Emit("RESULT: %s", g_pass ? "PASS" : "FAIL");
    return g_pass ? 0 : 1;
}

static void PrintUsage(void)
{
    printf("HpxProbe e2e [--node ip:port] [--user u] [--pass p] [--tcp self|ip:port] [--udp ip:port] [--back 0|1|2|3]\n");
    printf("HpxProbe auto [--node ip:port] [--tcp ip:port]   (鏄犲儚鍚嶈嚜鍔ㄧ櫥璁伴瞾妫掓€ч獙璇?\n");
    printf("HpxProbe gen <outFile> [--tcp self|ip:port] [--udp ip:port]\n");
    printf("HpxProbe drv install|uninstall\n");
    printf("HpxProbe wfp\n");
}

int main(int argc, char** argv)
{
    WSADATA wsa;
    int rc = 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("HPXPROBE-BUILD %s %s argc=%d a1=%s\n", __DATE__, __TIME__, argc, argc > 1 ? argv[1] : "-");
    /* s5 = GUI"娴嬭瘯杩炴帴"蹇犲疄澶嶇幇:鎺㈤拡鑷韩涔熶笉鍋?WSAStartup,
     * 鍏ㄩ儴渚濊禆寮曟搸鑷垵濮嬪寲(GUI 杩涚▼浠庝笉璋?WSAStartup) */
    if (!(argc >= 2 && strcmp(argv[1], "s5") == 0))
        WSAStartup(MAKEWORD(2, 2), &wsa);

    if (argc < 2) { PrintUsage(); return 2; }

    if (strcmp(argv[1], "e2e") == 0) {
        const char* node = "10.10.10.254";
        int nport = 1081;
        const char* user = "", *pass = "";
        const char* tcpTgt = "223.5.5.5"; int tcpPort = 80;
        const char* udpTgt = "223.5.5.5"; int udpPort = 53;
        int back = 3;
        int i;
        for (i = 2; i + 1 < argc; i += 2) {
            if (strcmp(argv[i], "--node") == 0) {
                char* c = strchr(argv[i + 1], ':');
                if (c) { *c = 0; nport = atoi(c + 1); }
                node = argv[i + 1];
            } else if (strcmp(argv[i], "--user") == 0) user = argv[i + 1];
            else if (strcmp(argv[i], "--pass") == 0) pass = argv[i + 1];
            else if (strcmp(argv[i], "--tcp") == 0) {
                if (strcmp(argv[i + 1], "self") == 0) {
                    tcpTgt = "self";
                } else {
                    char* c = strchr(argv[i + 1], ':');
                    if (c) { *c = 0; tcpPort = atoi(c + 1); }
                    tcpTgt = argv[i + 1];
                }
            } else if (strcmp(argv[i], "--udp") == 0) {
                char* c = strchr(argv[i + 1], ':');
                if (c) { *c = 0; udpPort = atoi(c + 1); }
                udpTgt = argv[i + 1];
            } else if (strcmp(argv[i], "--back") == 0) back = atoi(argv[i + 1]);
        }
        rc = CmdE2E(node, nport, user, pass, tcpTgt, tcpPort, udpTgt, udpPort, back);
    } else if (strcmp(argv[1], "auto") == 0) {
        const char* node = "10.10.10.254";
        int nport = 1081;
        const char* tcpTgt = "223.5.5.5"; int tcpPort = 80;
        int i;
        for (i = 2; i + 1 < argc; i += 2) {
            if (strcmp(argv[i], "--node") == 0) {
                char* c = strchr(argv[i + 1], ':');
                if (c) { *c = 0; nport = atoi(c + 1); }
                node = argv[i + 1];
            } else if (strcmp(argv[i], "--tcp") == 0) {
                if (strcmp(argv[i + 1], "self") == 0) tcpTgt = "self";
                else {
                    char* c = strchr(argv[i + 1], ':');
                    if (c) { *c = 0; tcpPort = atoi(c + 1); }
                    tcpTgt = argv[i + 1];
                }
            }
        }
        rc = CmdAuto(node, nport, tcpTgt, tcpPort);
    } else if (strcmp(argv[1], "idle") == 0 && argc >= 4) {
        /* 琚嚜鍔ㄧ櫥璁扮殑闈惰繘绋?鍏堢潯 3s(绛夎嚜鍔ㄧ櫥璁?,鍐嶅彂涓€娆＄粡閾?TCP 鎺㈤拡 */
        int secs = atoi(argv[2]);
        const char* tcpTgt = "223.5.5.5"; int tcpPort = 80;
        char detail[256];
        int i, ok;
        for (i = 4; i + 1 < argc; i += 2) {
            if (strcmp(argv[i], "--tcp") == 0) {
                char* c = strchr(argv[i + 1], ':');
                if (c) { *c = 0; tcpPort = atoi(c + 1); }
                tcpTgt = argv[i + 1];
            }
        }
        g_out = fopen(argv[3], "w");
        if (!g_out) g_out = stdout;
        Sleep(3000);
        ok = TcpProbe(tcpTgt, tcpPort, detail, sizeof(detail));
        Verdict("IDLE-TCP", ok, detail);
        if (g_out && g_out != stdout) { fclose(g_out); g_out = NULL; }
        if (secs > 3) Sleep((secs - 3) * 1000);
        rc = ok ? 0 : 1;
    } else if (strcmp(argv[1], "gen") == 0 && argc >= 3) {
        const char* tcpTgt = "223.5.5.5"; int tcpPort = 80;
        const char* udpTgt = "223.5.5.5"; int udpPort = 53;
        int i;
        for (i = 3; i + 1 < argc; i += 2) {
            if (strcmp(argv[i], "--tcp") == 0) {
                if (strcmp(argv[i + 1], "self") == 0) tcpTgt = "self";
                else {
                    char* c = strchr(argv[i + 1], ':');
                    if (c) { *c = 0; tcpPort = atoi(c + 1); }
                    tcpTgt = argv[i + 1];
                }
            } else if (strcmp(argv[i], "--udp") == 0) {
                char* c = strchr(argv[i + 1], ':');
                if (c) { *c = 0; udpPort = atoi(c + 1); }
                udpTgt = argv[i + 1];
            }
        }
        Sleep(2500);   /* 绛夊涓荤櫥璁版湰杩涚▼鍚庡啀寮€娴侀噺 */
        rc = CmdGen(argv[2], tcpTgt, tcpPort, udpTgt, udpPort);
    } else if (strcmp(argv[1], "s5") == 0) {
        /* 澶嶇幇/鍥炲綊:浠?CheckSocks5(涓?InitData)鈥斺€擥UI"娴嬭瘯杩炴帴"鐨勭嫭绔嬭矾寰?*/
        const char* node = "10.10.10.254";
        int nport = 1081;
        int i;
        for (i = 2; i + 1 < argc; i += 2) {
            if (strcmp(argv[i], "--node") == 0) {
                char* c = strchr(argv[i + 1], ':');
                if (c) { *c = 0; nport = atoi(c + 1); }
                node = argv[i + 1];
            }
        }
        if (LoadEngine() != 0) return 2;
        {
            typedef BOOL (WINAPI *PFN_Check)(int, char*, int, char*, char*);
            PFN_Check pChk = (PFN_Check)GetProcAddress(g_dll, "CheckSocks5");
            int ok = pChk && pChk(2, (char*)node, nport, (char*)"", (char*)"");
            Verdict("S5-ONLY", ok, ok ? "connect-ok" : "connect-fail");
        }
        rc = g_pass ? 0 : 1;
    } else if (strcmp(argv[1], "drv") == 0 && argc >= 3) {
        /* 椹卞姩瑁呭嵏(GUI 鎸夐挳鐨勫悗绔嚱鏁?鑷姩鍖栬鐩? */
        typedef BOOL (WINAPI *PFN_Inst)(const wchar_t*);
        typedef BOOL (WINAPI *PFN_Uninst)(void);
        typedef BOOL (WINAPI *PFN_St)(wchar_t*, int);
        PFN_Inst pInst;
        PFN_Uninst pUn;
        PFN_St pSt;
        wchar_t st[256];
        if (LoadEngine() != 0) return 2;
        pInst = (PFN_Inst)GetProcAddress(g_dll, "HpxInstallDriverW");
        pUn = (PFN_Uninst)GetProcAddress(g_dll, "HpxUninstallDriverW");
        pSt = (PFN_St)GetProcAddress(g_dll, "HpxDriverStatusW");
        if (strcmp(argv[2], "install") == 0) {
            Verdict("DRV-INSTALL", pInst && pInst(NULL), "");
        } else if (strcmp(argv[2], "uninstall") == 0) {
            Verdict("DRV-UNINSTALL", pUn && pUn(), "");
        }
        if (pSt && pSt(st, 256)) Emit("DRIVER %ls", st);
        rc = 0;
    } else if (strcmp(argv[1], "wfp") == 0 || strcmp(argv[1], "hold") == 0) {
        if (LoadEngine() == 0) {
            typedef BOOL (WINAPI *PFN_Status)(wchar_t*, int);
            PFN_Status pSt = (PFN_Status)GetProcAddress(g_dll, "HpxDriverStatusW");
            wchar_t st[256];
            int secs = (argc >= 3) ? atoi(argv[2]) : 12;
            int i;
            if (pSt && pSt(st, 256)) Emit("DRIVER %ls", st);
            if (pInitData(0, 0, 0)) {
                int j;
                Emit("MARKER-ENGINE-UP t=0");
                LiveLog("ENGINE-UP t=0");
                for (j = 2; j < argc; j++) {
                    if (strcmp(argv[j], "--global") == 0) {
                        typedef BOOL (WINAPI *PFN_SG)(int);
                        PFN_SG pSG = (PFN_SG)GetProcAddress(g_dll, "HpxSetGlobal");
                        if (!pSG) Emit("MARKER-GLOBAL FAIL noload=%lu", GetLastError());
                        else if (!pSG(1)) Emit("MARKER-GLOBAL FAIL call=%lu", GetLastError());
                        else Emit("MARKER-GLOBAL ok");
                    }
                    if (strcmp(argv[j], "--node") == 0 && j + 1 < argc) {
                        char* colon = strrchr(argv[j + 1], ':');
                        if (colon) {
                            int np = atoi(colon + 1);
                            *colon = 0;
                            if (pCheckSocks5 && pCheckSocks5(2, argv[j + 1], np, (char*)"", (char*)""))
                                Emit("MARKER-NODE ok %s:%d", argv[j + 1], np);
                            else
                                Emit("MARKER-NODE FAIL");
                            *colon = ':';
                        }
                    }
                    if (strcmp(argv[j], "--img") == 0 && j + 1 < argc) {
                        typedef BOOL (WINAPI *PFN_AddImg)(char*);
                        PFN_AddImg pImg = (PFN_AddImg)GetProcAddress(g_dll, "AddFilterExeName");
                        if (pImg && pImg(argv[j + 1]))
                            Emit("MARKER-IMG-REG ok %s", argv[j + 1]);
                        else
                            Emit("MARKER-IMG-REG FAIL %s", argv[j + 1]);
                    }
                }
                for (i = 1; i <= secs; i++) {
                    Sleep(1000);
                    if (i % 10 == 0 || i == secs) {
                        Emit("MARKER-ALIVE t=%d", i);
                        LiveLog("ALIVE t=%d", i);
                    }
                }
                PrintDiag("HOLD");
                pEmptyData();
                Emit("MARKER-ENGINE-DOWN");
                LiveLog("ENGINE-DOWN");
            } else {
                Emit("FATAL: InitData failed");
                LiveLog("INIT-FAIL");
            }
            rc = 0;
        }
    } else {
        PrintUsage();
    }
    WSACleanup();
    return rc;
}
