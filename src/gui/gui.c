/*
 * gui.c — HookProxy 手动测试台(Win32 GUI,x64)
 *
 * 面向手动测试的控制面板:
 *   [驱动] 安装 / 卸载 / 状态
 *   [上游 SOCKS5] 节点地址与认证、连通性测试
 *   [引擎] 启动代理(InitData)/ 停止(EmptyData)/ UDP 回程模式
 *   [按进程代理] PID/进程名搜索(实时过滤)、按 PID / 按进程名双模式代理、
 *                流量表(PID/映像/上行/下行/来源状态)
 *   [状态/流量] 驱动计数、总流量、引擎日志
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <tlhelp32.h>

#include "engine.h"

#pragma comment(lib, "comctl32.lib")

/* ---------- 控件 ID ---------- */
enum {
    IDC_BTN_INSTALL = 100, IDC_BTN_UNINSTALL, IDC_BTN_DRVSTATUS, IDC_ST_DRV,
    IDC_ED_NODE, IDC_ED_PORT, IDC_ED_USER, IDC_ED_PASS, IDC_BTN_CHECKS5,
    IDC_BTN_START, IDC_BTN_STOP, IDC_ST_ENGINE, IDC_CB_BACK, IDC_CHK_GLOBAL,
    IDC_ED_PID, IDC_BTN_ADD, IDC_BTN_REMOVE, IDC_CB_PROCS, IDC_LV_FLOWS,
    IDC_BTN_ADDIMAGE, IDC_BTN_REFRESHPROCS,
    IDC_ST_DIAG, IDC_ST_TOTAL, IDC_BTN_CLRLOG, IDC_LB_LOG,
    IDC_TIMER = 1
};

/* ---------- 引擎函数指针 ---------- */
static HMODULE g_dll;
typedef BOOL (WINAPI *PFN_InitData)(int, int, BOOLEAN);
typedef BOOL (WINAPI *PFN_EmptyData)(void);
typedef BOOL (WINAPI *PFN_CheckSocks5)(int, char*, int, char*, char*);
typedef BOOL (WINAPI *PFN_SetGlobal)(int);
typedef BOOL (WINAPI *PFN_SetProxy)(int, const char*, const char*, const char*, const char*, const char*, const char*);
typedef BOOL (WINAPI *PFN_StopProxy)(DWORD);
typedef BOOL (WINAPI *PFN_GetProcessFlow)(BOOLEAN, DWORD, unsigned long long*, unsigned long long*);
typedef BOOL (WINAPI *PFN_Install)(const wchar_t*);
typedef BOOL (WINAPI *PFN_Uninstall)(void);
typedef BOOL (WINAPI *PFN_DrvStatus)(wchar_t*, int);
typedef BOOL (WINAPI *PFN_BackMode)(int);
typedef BOOL (WINAPI *PFN_Diag)(wchar_t*, int);
typedef BOOL (WINAPI *PFN_Log)(int, char*, int);
typedef BOOL (WINAPI *PFN_MakeKey)(const char*, const char*, char*);
typedef BOOL (WINAPI *PFN_EnumProc)(int, DWORD*, char*, int, int*, int*, int*);
typedef BOOL (WINAPI *PFN_AddFilterExeName)(char*);

static PFN_InitData     pInitData;
static PFN_EmptyData    pEmptyData;
static PFN_CheckSocks5  pCheckSocks5;
static PFN_SetGlobal    pSetGlobal;
static HWND             g_hChkGlobal;
static PFN_SetProxy     pSetProxy;
static PFN_StopProxy    pStopProxy;
static PFN_GetProcessFlow pGetProcessFlow;
static PFN_Install      pInstall;
static PFN_Uninstall    pUninstall;
static PFN_DrvStatus    pDrvStatus;
static PFN_BackMode     pBackMode;
static PFN_Diag         pDiag;
static PFN_Log          pLog;
static PFN_MakeKey      pMakeKey;
static PFN_EnumProc     pEnumProc;
static PFN_AddFilterExeName pAddFilterExeName;

static int g_logIdx = 0;
static HWND g_hLog, g_hFlows, g_hStDrv, g_hStEngine, g_hStDiag, g_hStTotal;
static HWND g_hEdNode, g_hEdPort, g_hEdUser, g_hEdPass, g_hEdPid, g_hCbProcs, g_hCbBack;

static void SetText(HWND h, const wchar_t* s) { SetWindowTextW(h, s); }

static void GetEd(HWND h, char* out, int cap)
{
    wchar_t w[256];
    GetWindowTextW(h, w, 256);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cap, NULL, NULL);
}

static void GetEdW(HWND h, wchar_t* out, int cap)
{
    GetWindowTextW(h, out, cap);
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
    if (!g_dll) return -1;
    #define GET(name, var) var = (void*)GetProcAddress(g_dll, name)
    GET("InitData", pInitData);
    GET("EmptyData", pEmptyData);
    GET("CheckSocks5", pCheckSocks5);
    GET("SetProxy", pSetProxy);
    GET("StopProxy", pStopProxy);
    GET("GetProcessFlow", pGetProcessFlow);
    GET("HpxInstallDriverW", pInstall);
    GET("HpxUninstallDriverW", pUninstall);
    GET("HpxDriverStatusW", pDrvStatus);
    GET("HpxSetUdpBackMode", pBackMode);
    GET("HpxSetGlobal", pSetGlobal);
    GET("HpxDiagW", pDiag);
    GET("HpxGetLogA", pLog);
    GET("HpxMakeKeyA", pMakeKey);
    GET("HpxEnumProcA", pEnumProc);
    GET("AddFilterExeName", pAddFilterExeName);
    #undef GET
    return (pInitData && pEmptyData && pSetProxy && pInstall) ? 0 : -1;
}

/* ---------- 进程枚举/搜索:PID 与进程名模糊过滤,按映像名→PID 排序 ---------- */
typedef struct { wchar_t line[320]; wchar_t sortKey[360]; } PROCROW;
static int __cdecl ProcRowCmp(const void* a, const void* b)
{
    const PROCROW* x = (const PROCROW*)a;
    const PROCROW* y = (const PROCROW*)b;
    return _wcsicmp(x->sortKey, y->sortKey);
}

static void FillProcesses(const wchar_t* filter)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    PROCROW* rows;
    int n = 0, i;
    wchar_t fbuf[128];

    SendMessageW(g_hCbProcs, CB_RESETCONTENT, 0, 0);
    fbuf[0] = 0;
    if (filter && filter[0]) {
        wcsncpy_s(fbuf, 128, filter, _TRUNCATE);
        _wcslwr_s(fbuf, 128);
    }
    rows = (PROCROW*)malloc(sizeof(PROCROW) * 2048);
    if (!rows) return;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { free(rows); return; }
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            wchar_t img[260], low[300], pidstr[24];
            int match = 1;
            _snwprintf_s(pidstr, 24, _TRUNCATE, L"%lu", pe.th32ProcessID);
            wcsncpy_s(img, 260, pe.szExeFile, _TRUNCATE);
            if (fbuf[0]) {
                wcscpy_s(low, 300, img);
                _wcslwr_s(low, 300);
                match = (wcsstr(low, fbuf) != NULL) || (wcsstr(pidstr, fbuf) != NULL);
            }
            if (!match) continue;
            if (n < 2048) {
                _snwprintf_s(rows[n].line, 320, _TRUNCATE, L"%s  %s", pidstr, img);
                _snwprintf_s(rows[n].sortKey, 360, _TRUNCATE, L"%s|%010lu", img, pe.th32ProcessID);
                n++;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    qsort(rows, n, sizeof(PROCROW), ProcRowCmp);
    for (i = 0; i < n; i++)
        SendMessageW(g_hCbProcs, CB_ADDSTRING, 0, (LPARAM)rows[i].line);
    if (n >= 2048)
        SendMessageW(g_hCbProcs, CB_ADDSTRING, 0, (LPARAM)L"(结果过多,请细化搜索)");
    free(rows);
}

/* ---------- 流量表:快照→排序→就地更新(零闪烁、读数一致) ---------- */
typedef struct {
    DWORD pid;
    char  image[MAX_PATH];
    unsigned long long up, down;
    int   act, aut, ust;
} FLOWROW;

static FLOWROW g_rows[128];
static int     g_sortCol = 2;        /* 默认按上行 */
static int     g_sortDir = -1;       /* 1=升序 -1=降序 */

static int FlowRowCmp(const void* a, const void* b)
{
    const FLOWROW* ra = (const FLOWROW*)a;
    const FLOWROW* rb = (const FLOWROW*)b;
    int r;
    switch (g_sortCol) {
    case 0:  r = (ra->pid > rb->pid) - (ra->pid < rb->pid); break;
    case 1:  r = _stricmp(ra->image, rb->image); break;
    case 3:  r = (ra->down > rb->down) - (ra->down < rb->down); break;
    case 4:  r = (ra->act != rb->act) ? (ra->act ? -1 : 1) : (ra->aut - rb->aut); break;
    default: r = (ra->up > rb->up) - (ra->up < rb->up); break;
    }
    return g_sortDir * r;
}

static void SetCellIfChanged(int row, int col, const wchar_t* text)
{
    wchar_t cur[256];
    LVITEMW it;
    memset(&it, 0, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = row;
    it.iSubItem = col;
    it.pszText = cur;
    it.cchTextMax = 256;
    if (ListView_GetItem(g_hFlows, &it) && cur[0] && wcscmp(cur, text) == 0) return;
    ListView_SetItemText(g_hFlows, row, col, (LPWSTR)text);
}

/* 表头排序箭头(升/降序可见化) */
static void UpdateSortIndicator(void)
{
    HWND hdr = ListView_GetHeader(g_hFlows);
    int i, n = Header_GetItemCount(hdr);
    for (i = 0; i < n; i++) {
        HDITEMW h;
        memset(&h, 0, sizeof(h));
        h.mask = HDI_FORMAT;
        Header_GetItem(hdr, i, &h);
        h.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (i == g_sortCol) h.fmt |= (g_sortDir > 0) ? HDF_SORTUP : HDF_SORTDOWN;
        Header_SetItem(hdr, i, &h);
    }
}

static void RefreshFlows(void)
{
    int idx, n = 0, i, cnt, selRow;
    unsigned long long totalUp = 0, totalDown = 0;
    wchar_t line[256], wtmp[MAX_PATH + 8];
    DWORD selPid = 0;
    LVITEMW it;

    if (!pEnumProc) return;

    /* 1) 单时刻快照:枚举 + 逐行读数,一次取齐(同刻读数才准确、可比较) */
    for (idx = 0; idx < 128 && n < 128; idx++) {
        FLOWROW* r = &g_rows[n];
        r->image[0] = 0;
        if (!pEnumProc(idx, &r->pid, r->image, sizeof(r->image), &r->act, &r->aut, &r->ust)) break;
        if (r->pid == 0) continue;
        r->up = r->down = 0;
        if (pGetProcessFlow && r->act) pGetProcessFlow(0, r->pid, &r->up, &r->down);
        totalUp += r->up;
        totalDown += r->down;
        n++;
    }

    /* 2) 按当前排序键排序(点列头切换) */
    if (n > 1) qsort(g_rows, (size_t)n, sizeof(FLOWROW), FlowRowCmp);

    /* 3) 就地更新:行增删只动尾部,单元格仅在文本变化时写;批内禁绘,杜绝闪烁 */
    cnt = ListView_GetItemCount(g_hFlows);
    selRow = ListView_GetNextItem(g_hFlows, -1, LVNI_SELECTED);
    if (selRow >= 0 && selRow < cnt) {
        memset(&it, 0, sizeof(it));
        it.mask = LVIF_PARAM;
        it.iItem = selRow;
        if (ListView_GetItem(g_hFlows, &it)) selPid = (DWORD)it.lParam;
    }
    SendMessageW(g_hFlows, WM_SETREDRAW, FALSE, 0);
    while (cnt > n) { ListView_DeleteItem(g_hFlows, --cnt); }
    while (cnt < n) {
        memset(&it, 0, sizeof(it));
        it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = cnt;
        it.pszText = (LPWSTR)L"";
        ListView_InsertItem(g_hFlows, &it);
        cnt++;
    }
    for (i = 0; i < n; i++) {
        FLOWROW* r = &g_rows[i];
        memset(&it, 0, sizeof(it));
        it.mask = LVIF_PARAM;
        it.iItem = i;
        it.lParam = (LPARAM)r->pid;
        ListView_SetItem(g_hFlows, &it);
        _snwprintf_s(wtmp, MAX_PATH + 8, _TRUNCATE, L"%lu", r->pid);
        SetCellIfChanged(i, 0, wtmp);
        MultiByteToWideChar(CP_UTF8, 0, r->image, -1, wtmp, MAX_PATH + 8);
        SetCellIfChanged(i, 1, wtmp);
        _snwprintf_s(wtmp, MAX_PATH + 8, _TRUNCATE, L"%llu", r->up);
        SetCellIfChanged(i, 2, wtmp);
        _snwprintf_s(wtmp, MAX_PATH + 8, _TRUNCATE, L"%llu", r->down);
        SetCellIfChanged(i, 3, wtmp);
        _snwprintf_s(wtmp, MAX_PATH + 8, _TRUNCATE, L"%s",
                     !r->act ? (r->ust ? L"已停(用户)" : L"已停")
                             : (r->aut ? L"自动·活跃" : L"手动·活跃"));
        SetCellIfChanged(i, 4, wtmp);
    }
    SendMessageW(g_hFlows, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hFlows, NULL, TRUE);

    /* 选中态按 PID 延续(排序/增删不丢选中) */
    if (selPid) {
        for (i = 0; i < n; i++) {
            memset(&it, 0, sizeof(it));
            it.mask = LVIF_PARAM;
            it.iItem = i;
            if (ListView_GetItem(g_hFlows, &it) && (DWORD)it.lParam == selPid) {
                ListView_SetItemState(g_hFlows, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                break;
            }
        }
    }

    _snwprintf_s(line, 256, _TRUNCATE, L"总流量:上行 %llu B / 下行 %llu B", totalUp, totalDown);
    SetText(g_hStTotal, line);
}

static void RefreshDiag(void)
{
    if (pDiag) {
        wchar_t buf[512];
        if (pDiag(buf, 512)) SetText(g_hStDiag, buf);
    }
}

static void PullLog(void)
{
    char line[256];
    int added = 0;
    if (!pLog) return;
    while (pLog(g_logIdx, line, sizeof(line))) {
        wchar_t w[300];
        MultiByteToWideChar(CP_UTF8, 0, line, -1, w, 300);
        SendMessageW(g_hLog, LB_ADDSTRING, 0, (LPARAM)w);
        while ((int)SendMessageW(g_hLog, LB_GETCOUNT, 0, 0) > 500)
            SendMessageW(g_hLog, LB_DELETESTRING, 0, 0);
        g_logIdx++;
        added = 1;
    }
    if (added) {
        /* 日志跟随最新:视图滚到最底,最新一行始终可见(向上滚动) */
        int n = (int)SendMessageW(g_hLog, LB_GETCOUNT, 0, 0);
        if (n > 0) SendMessageW(g_hLog, LB_SETTOPINDEX, (WPARAM)(n - 1), 0);
    }
}

/* ---------- 目标解析:搜索框优先(纯数字 = PID,否则 = 进程名);下拉选中行兜底 ---------- */
static int ResolveSelectedPid(DWORD* pidOut)
{
    char txt[260];
    GetEd(g_hEdPid, txt, sizeof(txt));
    if (txt[0]) {
        char* end = NULL;
        unsigned long v = strtoul(txt, &end, 10);
        if (end && *end == 0 && v > 0) { *pidOut = (DWORD)v; return 1; }
    }
    {
        wchar_t line[320];
        int sel = (int)SendMessageW(g_hCbProcs, CB_GETCURSEL, 0, 0);
        if (sel < 0) return 0;
        SendMessageW(g_hCbProcs, CB_GETLBTEXT, sel, (LPARAM)line);
        *pidOut = (DWORD)wcstoul(line, NULL, 10);
        return *pidOut > 0;
    }
}

static int ResolveSelectedImage(char* image, int cap)
{
    wchar_t txt[260];
    int digits = 1, i;
    GetEdW(g_hEdPid, txt, 260);
    for (i = 0; txt[i]; i++)
        if (!iswdigit(txt[i])) { digits = 0; break; }
    if (txt[0] && !digits) {
        WideCharToMultiByte(CP_UTF8, 0, txt, -1, image, cap, NULL, NULL);
        return 1;
    }
    {
        wchar_t line[320], * sp;
        int sel = (int)SendMessageW(g_hCbProcs, CB_GETCURSEL, 0, 0);
        if (sel < 0) return 0;
        SendMessageW(g_hCbProcs, CB_GETLBTEXT, sel, (LPARAM)line);
        sp = wcschr(line, L' ');          /* 行格式 "pid  image" */
        while (sp && *sp == L' ') sp++;
        if (!sp || !*sp) return 0;
        WideCharToMultiByte(CP_UTF8, 0, sp, -1, image, cap, NULL, NULL);
        return 1;
    }
}

/* ---------- 动作 ---------- */
static void DoInstall(void)
{
    wchar_t st[256];
    if (!pInstall) return;
    SetText(g_hStDrv, L"状态: 安装中…");
    if (pInstall(NULL)) SetText(g_hStDrv, L"状态: 驱动已安装并运行");
    else SetText(g_hStDrv, L"状态: 安装失败(查看日志)");
    if (pDrvStatus && pDrvStatus(st, 256)) {
        wchar_t line[320];
        _snwprintf_s(line, 320, _TRUNCATE, L"状态: %s", st);
        SetText(g_hStDrv, line);
    }
    PullLog();
}

static void DoUninstall(void)
{
    if (!pUninstall) return;
    if (pUninstall()) SetText(g_hStDrv, L"状态: 驱动已停止并删除");
    else SetText(g_hStDrv, L"状态: 卸载失败(查看日志)");
    PullLog();
}

static void DoDrvStatus(void)
{
    wchar_t st[256];
    if (pDrvStatus && pDrvStatus(st, 256)) {
        wchar_t line[320];
        _snwprintf_s(line, 320, _TRUNCATE, L"状态: %s", st);
        SetText(g_hStDrv, line);
    } else {
        SetText(g_hStDrv, L"状态: 驱动不可用");
    }
}

static void DoCheckS5(void)
{
    char ip[64], user[64], pass[64];
    wchar_t wport[32];
    int port;
    GetEd(g_hEdNode, ip, sizeof(ip));
    GetEd(g_hEdUser, user, sizeof(user));
    GetEd(g_hEdPass, pass, sizeof(pass));
    GetEdW(g_hEdPort, wport, 32);
    port = _wtoi(wport);
    if (pCheckSocks5 && pCheckSocks5(2, ip, port, user, pass)) {
        wchar_t line[320];
        _snwprintf_s(line, 320, _TRUNCATE, L"引擎: SOCKS5 节点 %hs:%d 可用", ip, port);
        SetText(g_hStEngine, line);
    } else {
        SetText(g_hStEngine, L"引擎: SOCKS5 节点不可用(查看日志)");
    }
    PullLog();
}

static void DoStart(void)
{
    if (!pInitData) return;
    if (pBackMode) {
        int mode = (int)SendMessageW(g_hCbBack, CB_GETCURSEL, 0, 0);
        /* 下拉顺序:0=本地化(3) 1=驱动注入(1) 2=bind(2) 3=注入优先(0) */
        static const int map[4] = { 3, 1, 2, 0 };
        pBackMode((mode >= 0 && mode < 4) ? map[mode] : 3);
    }
    if (pSetGlobal)
        pSetGlobal(SendMessageW(g_hChkGlobal, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0);
    if (pInitData(0, 0, 0)) SetText(g_hStEngine, L"引擎: 运行中(中继已就绪)");
    else SetText(g_hStEngine, L"引擎: 启动失败(查看日志)");
    PullLog();
}

static void DoStop(void)
{
    if (!pEmptyData) return;
    if (pEmptyData()) SetText(g_hStEngine, L"引擎: 已停止");
    else SetText(g_hStEngine, L"引擎: 未在运行");
    PullLog();
}

static void DoAddPid(void)
{
    char pidStr[32], node[64], user[64], pass[64], key[40], portStr[32];
    wchar_t wport[32];
    DWORD pid = 0;
    if (!ResolveSelectedPid(&pid)) { SetText(g_hStEngine, L"引擎: 请输入有效 PID 或在下拉中选进程"); return; }
    _snprintf_s(pidStr, sizeof(pidStr), _TRUNCATE, "%lu", pid);
    GetEd(g_hEdNode, node, sizeof(node));
    GetEd(g_hEdUser, user, sizeof(user));
    GetEd(g_hEdPass, pass, sizeof(pass));
    GetEdW(g_hEdPort, wport, 32);
    WideCharToMultiByte(CP_UTF8, 0, wport, -1, portStr, sizeof(portStr), NULL, NULL);
    if (pMakeKey) pMakeKey(pidStr, node, key);
    else key[0] = 0;
    if (pSetProxy && pSetProxy(0, pidStr, node, portStr, user, pass, key)) {
        wchar_t line[320];
        _snwprintf_s(line, 320, _TRUNCATE, L"引擎: PID %lu 已登记代理", pid);
        SetText(g_hStEngine, line);
        RefreshFlows();
    } else {
        SetText(g_hStEngine, L"引擎: 登记失败(需先启动引擎;查看日志)");
    }
    PullLog();
}

static void DoRemovePid(void)
{
    DWORD pid = 0;
    if (!ResolveSelectedPid(&pid)) return;
    if (pStopProxy && pStopProxy(pid)) {
        wchar_t line[320];
        _snwprintf_s(line, 320, _TRUNCATE, L"引擎: PID %lu 已停止代理", pid);
        SetText(g_hStEngine, line);
        RefreshFlows();
    }
    PullLog();
}

/* 按进程名代理:一条规则覆盖该映像的现存进程与未来新进程(如多个 chrome.exe) */
static void DoAddImage(void)
{
    char image[MAX_PATH];
    if (!ResolveSelectedImage(image, sizeof(image))) {
        SetText(g_hStEngine, L"引擎: 请输入进程名(如 chrome.exe)或在下拉中选进程");
        return;
    }
    if (pAddFilterExeName && pAddFilterExeName(image)) {
        wchar_t msg[320];
        _snwprintf_s(msg, 320, _TRUNCATE, L"引擎: 已按进程名代理 %hs(现存/新进程自动登记)", image);
        SetText(g_hStEngine, msg);
    } else {
        SetText(g_hStEngine, L"引擎: 按进程名代理失败");
    }
    RefreshFlows();
    PullLog();
}

static void DoRefreshProcs(void)
{
    wchar_t fbuf[128];
    GetEdW(g_hEdPid, fbuf, 128);
    FillProcesses(fbuf);
    RefreshFlows();
}

static void DoPickProc(void)
{
    wchar_t line[320];
    int sel = (int)SendMessageW(g_hCbProcs, CB_GETCURSEL, 0, 0);
    if (sel < 0) return;
    SendMessageW(g_hCbProcs, CB_GETLBTEXT, sel, (LPARAM)line);
    {
        wchar_t* sp = wcschr(line, L' ');
        if (sp) { *sp = 0; SetText(g_hEdPid, line); }
    }
}

/* ---------- 布局 ---------- */
static HWND MkStatic(HWND parent, const wchar_t* text, int x, int y, int w, int h, int id)
{
    return CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE,
                         x, y, w, h, parent, (HMENU)(ULONG_PTR)id, NULL, NULL);
}
static HWND MkButton(HWND parent, const wchar_t* text, int x, int y, int w, int h, int id)
{
    return CreateWindowW(L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                         x, y, w, h, parent, (HMENU)(ULONG_PTR)id, NULL, NULL);
}
static HWND MkEdit(HWND parent, const wchar_t* text, int x, int y, int w, int h, int id)
{
    return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", text,
                           WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                           x, y, w, h, parent, (HMENU)(ULONG_PTR)id, NULL, NULL);
}
static HWND MkGroup(HWND parent, const wchar_t* text, int x, int y, int w, int h)
{
    return CreateWindowW(L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
                         x, y, w, h, parent, NULL, NULL, NULL);
}

static void BuildUi(HWND hwnd)
{
    HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    HWND h;
    int x0 = 12, y0 = 10, gw = 480;

    MkGroup(hwnd, L"驱动", x0, y0, gw, 84);
    MkButton(hwnd, L"安装驱动", x0 + 14, y0 + 22, 92, 26, IDC_BTN_INSTALL);
    MkButton(hwnd, L"卸载驱动", x0 + 116, y0 + 22, 92, 26, IDC_BTN_UNINSTALL);
    MkButton(hwnd, L"刷新状态", x0 + 218, y0 + 22, 92, 26, IDC_BTN_DRVSTATUS);
    g_hStDrv = MkStatic(hwnd, L"状态: 未知", x0 + 14, y0 + 54, gw - 30, 22, IDC_ST_DRV);

    MkGroup(hwnd, L"上游 SOCKS5 节点", x0, y0 + 94, gw, 84);
    MkStatic(hwnd, L"IP", x0 + 14, y0 + 118, 22, 22, -1);
    g_hEdNode = MkEdit(hwnd, L"10.10.10.254", x0 + 38, y0 + 115, 130, 24, IDC_ED_NODE);
    MkStatic(hwnd, L"端口", x0 + 176, y0 + 118, 32, 22, -1);
    g_hEdPort = MkEdit(hwnd, L"1081", x0 + 210, y0 + 115, 56, 24, IDC_ED_PORT);
    MkStatic(hwnd, L"用户", x0 + 14, y0 + 146, 30, 22, -1);
    g_hEdUser = MkEdit(hwnd, L"", x0 + 48, y0 + 143, 100, 24, IDC_ED_USER);
    MkStatic(hwnd, L"密码", x0 + 156, y0 + 146, 30, 22, -1);
    g_hEdPass = MkEdit(hwnd, L"", x0 + 190, y0 + 143, 100, 24, IDC_ED_PASS);
    MkButton(hwnd, L"测试连接", x0 + 360, y0 + 129, 100, 28, IDC_BTN_CHECKS5);

    MkGroup(hwnd, L"引擎", x0, y0 + 188, gw, 84);
    MkButton(hwnd, L"启动代理", x0 + 14, y0 + 210, 92, 26, IDC_BTN_START);
    MkButton(hwnd, L"停止代理", x0 + 116, y0 + 210, 92, 26, IDC_BTN_STOP);
    MkStatic(hwnd, L"UDP 回程", x0 + 218, y0 + 214, 62, 22, -1);
    g_hCbBack = CreateWindowW(L"COMBOBOX", NULL,
                              WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
                              x0 + 282, y0 + 211, 178, 200, hwnd,
                              (HMENU)(ULONG_PTR)IDC_CB_BACK, NULL, NULL);
    SendMessageW(g_hCbBack, CB_ADDSTRING, 0, (LPARAM)L"自动(本地化,推荐)");
    SendMessageW(g_hCbBack, CB_ADDSTRING, 0, (LPARAM)L"驱动注入(备选)");
    SendMessageW(g_hCbBack, CB_ADDSTRING, 0, (LPARAM)L"bind 伪造源(备选)");
    SendMessageW(g_hCbBack, CB_ADDSTRING, 0, (LPARAM)L"注入优先(备选)");
    SendMessageW(g_hCbBack, CB_SETCURSEL, 0, 0);
    g_hChkGlobal = CreateWindowW(L"BUTTON", L"\x5168\x5c40\x4ee3\x7406(\x6240\x6709\x8fdb\x7a0b)",
                                 WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                 x0 + gw - 168, y0 + 241, 160, 22, hwnd,
                                 (HMENU)(ULONG_PTR)IDC_CHK_GLOBAL, NULL, NULL);
    g_hStEngine = MkStatic(hwnd, L"引擎: 未启动", x0 + 14, y0 + 242, gw - 190, 22, IDC_ST_ENGINE);

    MkGroup(hwnd, L"按进程代理(PID / 进程名搜索)", x0, y0 + 282, gw, 292);
    MkStatic(hwnd, L"搜索", x0 + 14, y0 + 306, 34, 22, -1);
    g_hEdPid = MkEdit(hwnd, L"", x0 + 50, y0 + 303, 140, 24, IDC_ED_PID);
    g_hCbProcs = CreateWindowW(L"COMBOBOX", NULL,
                               WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
                               x0 + 198, y0 + 303, 262, 400, hwnd,
                               (HMENU)(ULONG_PTR)IDC_CB_PROCS, NULL, NULL);
    MkButton(hwnd, L"按PID代理", x0 + 14, y0 + 336, 92, 26, IDC_BTN_ADD);
    MkButton(hwnd, L"按进程名代理", x0 + 112, y0 + 336, 118, 26, IDC_BTN_ADDIMAGE);
    MkButton(hwnd, L"移除PID", x0 + 236, y0 + 336, 82, 26, IDC_BTN_REMOVE);
    MkButton(hwnd, L"刷新", x0 + 324, y0 + 336, 76, 26, IDC_BTN_REFRESHPROCS);
    g_hFlows = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                               WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                               x0 + 14, y0 + 368, gw - 30, 196, hwnd,
                               (HMENU)(ULONG_PTR)IDC_LV_FLOWS, NULL, NULL);
    {
        LVCOLUMNW col;
        memset(&col, 0, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = (wchar_t*)L"PID"; col.cx = 70;
        ListView_InsertColumn(g_hFlows, 0, &col);
        col.pszText = (wchar_t*)L"映像"; col.cx = 130;
        ListView_InsertColumn(g_hFlows, 1, &col);
        col.pszText = (wchar_t*)L"上行(B)"; col.cx = 85;
        ListView_InsertColumn(g_hFlows, 2, &col);
        col.pszText = (wchar_t*)L"下行(B)"; col.cx = 85;
        ListView_InsertColumn(g_hFlows, 3, &col);
        col.pszText = (wchar_t*)L"状态"; col.cx = 96;
        ListView_InsertColumn(g_hFlows, 4, &col);
        UpdateSortIndicator();
    }

    /* 右列:状态 / 流量 / 日志 */
    {
        int rx = x0 + gw + 12;
        int rw = 494;
        MkGroup(hwnd, L"状态 / 流量", rx, y0, rw, 124);
        g_hStDiag = MkStatic(hwnd, L"驱动计数: (未连接)", rx + 14, y0 + 22, rw - 30, 60, IDC_ST_DIAG);
        g_hStTotal = MkStatic(hwnd, L"总流量: 上行 0 B / 下行 0 B", rx + 14, y0 + 86, rw - 30, 22, IDC_ST_TOTAL);

        MkGroup(hwnd, L"引擎日志", rx, y0 + 134, rw, 440);
        g_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                                 WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
                                 rx + 14, y0 + 156, rw - 30, 372, hwnd,
                                 (HMENU)(ULONG_PTR)IDC_LB_LOG, NULL, NULL);
        MkButton(hwnd, L"清空日志", rx + 14, y0 + 532, 92, 26, IDC_BTN_CLRLOG);
    }

    for (h = GetWindow(hwnd, GW_CHILD); h; h = GetWindow(h, GW_HWNDNEXT))
        SendMessageW(h, WM_SETFONT, (WPARAM)font, TRUE);
}

/* ---------- 窗口过程 ---------- */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
        BuildUi(hwnd);
        SetTimer(hwnd, IDC_TIMER, 1000, NULL);
        FillProcesses(NULL);
        DoDrvStatus();
        return 0;
    case WM_TIMER:
        PullLog();
        RefreshDiag();
        RefreshFlows();
        return 0;
    case WM_NOTIFY:
        if (((LPNMHDR)lParam)->hwndFrom == g_hFlows && ((LPNMHDR)lParam)->code == LVN_COLUMNCLICK) {
            LPNMLISTVIEW nlv = (LPNMLISTVIEW)lParam;
            if (g_sortCol == nlv->iSubItem) g_sortDir = -g_sortDir;
            else { g_sortCol = nlv->iSubItem; g_sortDir = (g_sortCol == 1) ? 1 : -1; }
            UpdateSortIndicator();
            RefreshFlows();
        }
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_INSTALL:   DoInstall(); break;
        case IDC_BTN_UNINSTALL: DoUninstall(); break;
        case IDC_BTN_DRVSTATUS: DoDrvStatus(); break;
        case IDC_BTN_CHECKS5:   DoCheckS5(); break;
        case IDC_BTN_START:     DoStart(); break;
        case IDC_BTN_STOP:      DoStop(); break;
        case IDC_CHK_GLOBAL:
            if (pSetGlobal) pSetGlobal(SendMessageW(g_hChkGlobal, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0);
            break;
        case IDC_BTN_ADD:       DoAddPid(); break;
        case IDC_BTN_REMOVE:    DoRemovePid(); break;
        case IDC_BTN_ADDIMAGE:  DoAddImage(); break;
        case IDC_BTN_REFRESHPROCS: DoRefreshProcs(); break;
        case IDC_BTN_CLRLOG:    SendMessageW(g_hLog, LB_RESETCONTENT, 0, 0); break;
        case IDC_CB_PROCS:      if (HIWORD(wParam) == CBN_SELCHANGE) DoPickProc(); break;
        case IDC_ED_PID:        if (HIWORD(wParam) == EN_CHANGE) DoRefreshProcs(); break;
        }
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, IDC_TIMER);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmdLine, int showCmd)
{
    WNDCLASSW wc;
    HWND hwnd;
    MSG msg;
    INITCOMMONCONTROLSEX icc;

    (void)hPrev; (void)cmdLine; (void)showCmd;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    if (LoadEngine() != 0) {
        MessageBoxW(NULL, L"未找到 HookProxy.dll(需与本程序同目录)", L"HookProxy", MB_ICONERROR);
        return 1;
    }

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"HpxGuiClass";
    RegisterClassW(&wc);

    hwnd = CreateWindowW(wc.lpszClassName, L"HookProxy 透明代理 · 手动测试台",
                         WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                         80, 40, 1010, 670,
                         NULL, NULL, hInst, NULL);
    if (hwnd) {
        SetWindowPos(hwnd, HWND_TOP, 80, 40, 1010, 670, SWP_SHOWWINDOW);
        UpdateWindow(hwnd);
    }
    ShowWindow(hwnd, SW_SHOWNORMAL);

    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
