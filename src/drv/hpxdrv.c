/*
 * hpxdrv.c 鈥?HookProxy 鍔熻兘閲嶅疄鐜?閫忔槑浠ｇ悊鍐呮牳椹卞姩(x64,IPv4)
 *
 * 鍔熻兘(瀵瑰簲鍘熷巶 HookProxy.dll 鐨勯€忔槑浠ｇ悊鑳藉姏):
 *   TCP:ALE_CONNECT_REDIRECT_V4 鎶婄櫥璁拌繘绋嬬殑 connect 鏀瑰啓鍒版湰鍦颁腑缁х鍙?
 *   UDP:ALE 灞傚彧璁颁笉鏀?24H2 UDP 杩炴帴閲嶅畾鍚戜负鍗婂畬鎴愰粦娲?瀹炶瘉绂佹鏀瑰啓),
 *       DATAGRAM_DATA_V4 鍚告敹搴旂敤鏁版嵁鎶ュ苟鏁村寘娉ㄥ叆鍒版湰鍦颁腑缁?
 *   鍥炵▼:IOCTL 200/201 浼€犳簮(鍘熷鐩爣 ip:port)娉ㄥ叆鍥炲簲鐢ㄧ鐐?
 *   鎺у埗闈?鎻℃墜/鎺у埗鍛戒护/璁ら鍘熷鐩殑/浜嬩欢娉?娴侀噺闄愰/瀛楄妭鍥炴姤/娴侀噺鏌ヨ銆? *
 * 鍗忚涓庡瓧鑺傚簭濂戠害瑙?common\hpx_proto.h;瀹炵幇濂戠害瑕佺偣:
 *   - 璁板綍绔彛 = 涓绘満搴?璁板綍 IPv4 = sin_addr 鍐呭瓨搴?WFP fixed value IPv4 = 缃戠粶搴忔暟鍊?
 *   - Acquire 蹇呴』鎭板ソ Apply 涓€娆?localRedirectContext 涓ョ璁剧疆(24H2 鎸傛缃戠粶鏍?;
 *   - UDP 涓€寰嬩笉璁?localRedirectHandle / TargetPID / LOCAL_ONLY_MAPPING(榛戞礊);
 *   - Fwpm* 鏄?RPC,涓ョ杩?DriverEntry(涓?SCM 鍔犺浇鍣ㄩ攣姝婚攣)鈫?鎳掑紓姝ョ粦瀹?
 *   - 鎸佽嚜鏃嬮攣/DISPATCH 鎵ц鐨勫嚱鏁颁竴寰嬩笉杩?PAGE 娈?
 *   - 鍗歌浇:鏈夌晫绛夊伐浣滈」 鈫?鍙嶆敞鍐屽叏閮?callout 鈫?浜嬪姟鎵瑰垹 鈫?鍏冲紩鎿?鈫?鍒犵鍙烽摼鎺?璁惧銆? */
#define NDIS_WDM 1
#define NDIS_SUPPORT_NDIS6 1

#include <ntddk.h>
#include <ntstrsafe.h>
#include <initguid.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>

#include "hpx_proto.h"

#define HPX_POOL_TAG        'xPHK'

/* ---------------- GUID(鏈」鐩嚜鏈?鍕夸笌鍏跺畠椹卞姩鍏辩敤) ---------------- */
DEFINE_GUID(HPX_CALLOUT_REDIRECT_V4, 0xa7c3e9f1, 0x2b4d, 0x4e8a, 0x9c, 0x1f, 0x3d, 0x5e, 0x7a, 0x9b, 0x0c, 0x2d);
DEFINE_GUID(HPX_CALLOUT_DATAGRAM_V4, 0xb8d4fa02, 0x3c5e, 0x4f9b, 0x8d, 0x2e, 0x4e, 0x6f, 0x8b, 0x0c, 0x1d, 0x3e);
DEFINE_GUID(HPX_FILTER_REDIRECT_V4,  0xc9e5ab13, 0x4d6f, 0x4a0c, 0x9e, 0x3f, 0x5f, 0x7a, 0x9c, 0x1d, 0x2e, 0x4f);
DEFINE_GUID(HPX_FILTER_DATAGRAM_V4,  0xdaf6bc24, 0x5e7a, 0x4b1d, 0xaf, 0x40, 0x6a, 0x8b, 0x0d, 0x2e, 0x3f, 0x5a);
DEFINE_GUID(HPX_CALLOUT_REDIRECT_V6, 0x1a2b3c4d, 0x5e6f, 0x4a7b, 0x8c, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d);
DEFINE_GUID(HPX_FILTER_REDIRECT_V6,  0x2b3c4d5e, 0x6f7a, 0x4b8c, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e);
DEFINE_GUID(HPX_PROVIDER,            0xeb07cd35, 0x6f8b, 0x4c2e, 0xb0, 0x51, 0x7b, 0x9c, 0x1e, 0x3f, 0x4a, 0x6b);
DEFINE_GUID(HPX_SUBLAYER,            0xfc18de46, 0x7a9c, 0x4d3f, 0xc1, 0x62, 0x8c, 0xad, 0x2f, 0x4a, 0x5b, 0x7c);

/* ================= 鍏ㄥ眬鐘舵€?================= */
static PDEVICE_OBJECT   g_DeviceObj            = NULL;
static HANDLE           g_EngineHandle         = NULL;
static HANDLE           g_RedirectHandle       = NULL;
static HANDLE           g_InjectHandle         = NULL;
static NDIS_HANDLE      g_NblPool              = NULL;

static UINT32           g_CalloutIdR4          = 0;
static UINT32           g_CalloutIdD4          = 0;
static UINT32           g_CalloutIdR6          = 0;
static UINT64           g_FilterIdR4           = 0;
static UINT64           g_FilterIdR6           = 0;
static UINT64           g_FilterIdD4           = 0;

static BOOLEAN          g_WfpBound             = FALSE;
static NTSTATUS         g_WfpStatus            = STATUS_UNSUCCESSFUL;
static ULONG            g_WfpStep              = 0;
static ULONG            g_WfpLayers            = 0x3;
static ULONG            g_WfpMode              = 0;   /* 冻结二分:bit0=跳过注入设施 bit1=跳过重定向句柄 bit2=跳过过滤器层 bit3=完全不碰 WFP 管理面 */    /* 浣?1=ALE 閲嶅畾鍚?2=鏁版嵁鎶?娉ㄥ唽琛?Parameters\Layers 鍙檺) */
static BOOLEAN          g_Enabled              = FALSE;
static volatile LONG    g_RelayPid             = 0;

/* 存活中继登记表:StartRelay 成功监听后 HPX_CTRL_RELAY_UP 登记,
 * StopRelay/设备关闭注销。转发是否放行只看此表是否为空,
 * 不再被"最后一次握手进程退出"误伤(2026-10-18 间隔掉线根因)。 */
#define HPX_MAX_RELAYS 8
static ULONG            g_RelayPids[HPX_MAX_RELAYS];
static ULONG            g_RelayCount = 0;

static USHORT           g_RelayPortTcp         = 2018;   /* 涓绘満搴?*/
static USHORT           g_RelayPortUdp         = 2019;   /* 涓绘満搴?*/

static KSPIN_LOCK       g_TableLock;
static LIST_ENTRY       g_ProcList;            /* HPX_PROC:鎸?PID 鐨勪唬鐞?璁¤垂璁板綍 */
static LIST_ENTRY       g_FlowList;            /* HPX_FLOW:杩炴帴/娴佽褰?FIFO) */

static NPAGED_LOOKASIDE_LIST g_ProcLookaside;
static NPAGED_LOOKASIDE_LIST g_FlowLookaside;

static ULONG            g_NextProcId           = 1;
static ULONG            g_NextFlowId           = 1;

static WORK_QUEUE_ITEM  g_WfpWork;
static WORK_QUEUE_ITEM  g_GcWork;
static volatile LONG    g_WfpWorkQueued        = 0;
static volatile LONG    g_GcQueued             = 0;
static volatile LONG    g_Unloading            = 0;

/* GC TTL(100ns tick,DriverEntry 鎹㈢畻;娉ㄥ唽琛ㄥ彲瑕嗙洊) */
static LONGLONG         g_TickGcClaimed        = 0;
static LONGLONG         g_TickGcUnclaimed      = 0;

/* 璁℃暟鍣?璇婃柇鍛戒护杈撳嚭) */
static volatile LONG    g_CntClassify          = 0;
static volatile LONG    g_CntPidHit            = 0;
static volatile LONG    g_CntRewrite           = 0;
static volatile LONG    g_CntPrev              = 0;
static volatile LONG    g_CntAllocFail         = 0;
static volatile LONG    g_CntClaim             = 0;
static volatile LONG    g_CntDatagram          = 0;
static volatile LONG    g_CntDgHit             = 0;
static volatile LONG    g_CntDgPermit          = 0;
static volatile LONG    g_CntDgramRw           = 0;
static volatile LONG    g_CntBackRw            = 0;
static volatile LONG    g_CntExempt            = 0;
static volatile LONG    g_CntInjFail           = 0;
static volatile LONG    g_CntInjOk             = 0;
static volatile LONG    g_InjLastStatus        = 0;   /* 最近一次异步注入 NBL 的 Status(鉴别"接受≠送达") */
static volatile LONG    g_InjFailTag           = 0;   /* 最近失败注入来源:1=D4前向 2=IOCTL回程 */
static volatile LONG    g_CntV6Block           = 0;   /* 受代理进程 IPv6 连接被拦(fail-fast 回落 v4) */
static volatile LONG    g_CntQuicBlock         = 0;   /* 受代理进程 QUIC(UDP/443)被拦(fail-fast 回落 TCP) */
static volatile LONG    g_CntImgHit            = 0;   /* 映像名规则命中(接管转发) */
static volatile LONG    g_CntIoctl             = 0;
static volatile LONG    g_CntNoRights          = 0;
static volatile LONG    g_CntDenied            = 0;
static volatile LONG    g_CntEvent             = 0;
static volatile LONG    g_SnapPort             = 0;
static volatile LONG    g_SnapIp               = 0;

/* 闄愭祦:tick 绐楀彛(1 tick 鈮?15.6ms),瓒呴檺鎷掔粷,闃茬敤鎴锋€佸埛琛?*/
static volatile LONG    g_RateWin              = -1;
static volatile LONG    g_RateCnt              = 0;

static BOOLEAN HpxRateAllow(LONG perTickLimit)
{
    LARGE_INTEGER tick;
    LONG win;
    KeQueryTickCount(&tick);
    win = (LONG)tick.LowPart;
    if (InterlockedCompareExchange(&g_RateWin, win, win) != win) {
        InterlockedExchange(&g_RateWin, win);
        InterlockedExchange(&g_RateCnt, 0);
    }
    return (InterlockedIncrement(&g_RateCnt) <= perTickLimit) ? TRUE : FALSE;
}
static BOOLEAN HpxRateAllowClaim(void) { return HpxRateAllow(512); }

/* 杩囨护鐧藉悕鍗?绌?= 涓嶈繃婊?鍛戒腑鍏朵竴鍗虫斁琛屼唬鐞? */
static ULONG            g_FilterIps[16];
static ULONG            g_FilterIpCount        = 0;
static USHORT           g_FilterPorts[32];
static ULONG            g_FilterPortCount      = 0;

/* 局域网网段表(HPX_CTRL_SET_LAN:引擎下发本机接口 on-link 前缀,精确判定);
 * 空表回退固定私网。语义:访问局域网一律不代理(直连),全模式生效。 */
#define HPX_MAX_LAN 32
static ULONG            g_LanNets[HPX_MAX_LAN];
static ULONG            g_LanMasks[HPX_MAX_LAN];
static ULONG            g_LanCount             = 0;

/* 映像名规则(驱动侧 ALE_APP_ID 文件名尾匹配):引擎 AddFilterExeName 下推,
 * classify 即时命中,消除"进程创建→引擎扫描登记"窗口内的直连泄漏 */
static WCHAR            g_ImgRules[8][64];
static ULONG            g_ImgCount             = 0;

/* 全局模式:代理所有进程(排除中继);私网 LAN 例外直连 */
static volatile BOOLEAN g_Global               = FALSE;
static volatile LONG    g_TotalUp              = 0;   /* 全局/无记录流量合计(KB 计) */
static volatile LONG    g_TotalDown            = 0;

/* 浜嬩欢鐜?*/
#define HPX_EVENT_RING 128
static KSPIN_LOCK       g_EventLock;
static HPX_EVENT        g_EventRing[HPX_EVENT_RING];
static ULONG            g_EventHead            = 0;
static ULONG            g_EventTail            = 0;
static ULONG            g_EventCursor          = 0;

/* ================= 璁板綍缁撴瀯 ================= */
typedef struct _HPX_PROC {
    LIST_ENTRY  link;
    ULONG       id;              /* 璁¤垂璁板綍 ID(0x2201B8 鏌ヨ閿?0=鏃犳晥) */
    ULONG       pid;
    BOOLEAN     enabled;
    BOOLEAN     limitReached;
    UINT64      bytesUp, bytesDown;
    UINT64      limitUp, limitDown;
} HPX_PROC;

typedef struct _HPX_FLOW {
    LIST_ENTRY  link;
    ULONG       flowId;
    ULONG       pid;
    ULONG       remoteIpV4;      /* sin_addr 鍐呭瓨搴?*/
    USHORT      remotePort;      /* 涓绘満搴?*/
    USHORT      localPort;       /* 涓绘満搴?0 = ALE 鏃跺埢鏈垎閰?鐩? */
    ULONG       localIpV4;       /* sin_addr 鍐呭瓨搴?*/
    UCHAR       protocol;        /* 6 / 17 */
    BOOLEAN     claimed;
    UINT32      ifIndex;         /* UDP 鍥炲寘娉ㄥ叆鐢?D4 棣栧寘鍥炲～) */
    UINT32      compartmentId;
    LONGLONG    created;
} HPX_FLOW;

/* 娉ㄥ叆涓婁笅鏂?瀹屾垚鍥炶皟閲婃斁) */
typedef struct _HPX_INJ_CTX {
    PVOID   buf;
    PMDL    mdl;
    int     tag;
} HPX_INJ_CTX;

/* ================= 灏忓伐鍏?================= */
static __forceinline ULONG HpxSwap32(ULONG v) { return RtlUlongByteSwap(v); }
static __forceinline USHORT HpxSwap16(USHORT v) { return RtlUshortByteSwap(v); }

/* 只按 fixed-value 大端序判读(fixed value = 点分地址压成大端 UINT32,已实证):
 * 跳过环回/组播/保留。切勿对字节交换值再判——末字节 >=224 的普通单播
 * (如 122.114.192.226)交换后顶字节落进 224/4 区,曾被误判组播放行直连 */
static BOOLEAN HpxSkipDestV4(ULONG ipAny)
{
    if (ipAny == 0) return TRUE;
    if ((ipAny >> 24) == 127) return TRUE;               /* 127/8 */
    if ((ipAny >> 28) >= 0xE) return TRUE;               /* 224/4 组播 + 240/4 保留 */
    return FALSE;
}

/* 搴忔棤鍏?绔彛鏄惁涓户绔彛 */
static BOOLEAN HpxIsRelayPort(USHORT pAny)
{
    if (pAny == g_RelayPortTcp || pAny == g_RelayPortUdp) return TRUE;
    if (HpxSwap16(pAny) == g_RelayPortTcp || HpxSwap16(pAny) == g_RelayPortUdp) return TRUE;
    return FALSE;
}

/* IP 澶?16 浣嶄竴琛ユ牎楠屽拰(鍏堟竻 [10..11]) */
static void HpxFixIpChecksum(UCHAR* ip, ULONG ihl)
{
    ULONG sum = 0, i;
    for (i = 0; i < ihl; i += 2) sum += (ULONG)((ip[i] << 8) | ip[i + 1]);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    sum = ~sum & 0xFFFF;
    ip[10] = (UCHAR)(sum >> 8);
    ip[11] = (UCHAR)(sum & 0xFF);
}

/* ================= 浜嬩欢鐜?================= */
static void HpxEventPush(ULONG type, ULONG a, ULONG b, ULONG c, ULONG d)
{
    KIRQL irql;
    HPX_EVENT* e;
    KeAcquireSpinLock(&g_EventLock, &irql);
    e = &g_EventRing[g_EventHead];
    g_EventHead = (g_EventHead + 1) % HPX_EVENT_RING;
    if (g_EventHead == g_EventTail) g_EventTail = (g_EventTail + 1) % HPX_EVENT_RING;
    RtlZeroMemory(e, sizeof(*e));
    e->type   = type;
    e->cursor = ++g_EventCursor;
    e->size   = sizeof(HPX_EVENT);
    e->u.status.code = a;
    e->u.status.reserved[0] = b;
    e->u.status.reserved[1] = c;
    e->u.status.reserved[2] = d;
    InterlockedIncrement(&g_CntEvent);
    KeReleaseSpinLock(&g_EventLock, irql);
}

/* ================= 璁板綍绠＄悊(鎸?g_TableLock 璋冪敤) ================= */
static HPX_PROC* HpxFindProcByPidLocked(ULONG pid)
{
    PLIST_ENTRY p;
    for (p = g_ProcList.Flink; p != &g_ProcList; p = p->Flink) {
        HPX_PROC* rec = CONTAINING_RECORD(p, HPX_PROC, link);
        if (rec->pid == pid && rec->enabled) return rec;
    }
    return NULL;
}

static HPX_PROC* HpxFindProcByIdLocked(ULONG id)
{
    PLIST_ENTRY p;
    if (id == 0) return NULL;
    for (p = g_ProcList.Flink; p != &g_ProcList; p = p->Flink) {
        HPX_PROC* rec = CONTAINING_RECORD(p, HPX_PROC, link);
        if (rec->id == id) return rec;
    }
    return NULL;
}

/* PID 淇′换闂?鍏冩暟鎹?PID 涓庡綋鍓嶇嚎绋?PID 鍙栨垨(fail-closed:鍧囨湭鐧昏鍒欎笉浠ｇ悊)銆? * 涓户杩涚▼(g_RelayPid,鎻℃墜鑰?鑷韩鐨勬祦閲忔案涓嶄唬鐞嗏€斺€斿惁鍒欏紩鎿庡涓婃父鑺傜偣鐨? * 杩炴帴浼氳閲嶅畾鍚戝洖涓户 = 鑷幆;鑷祴鍦烘櫙鐢?瀹夸富杩涚▼ + 娴侀噺瀛愯繘绋?缁撴瀯婊¤冻銆?*/
/* ALE_APP_ID blob = UTF-16 设备路径(无终止符):取最后一个 '\'/'/' 之后的
 * 文件名与规则做不区分大小写比较;规则为引擎 AddFilterExeName 下推的映像名 */
static BOOLEAN HpxImgRuleHit(const FWP_BYTE_BLOB* appId)
{
    const WCHAR* p;
    ULONG nchars, i, start = 0, ci;
    BOOLEAN hit = FALSE;
    KIRQL irql;

    if (appId == NULL || appId->data == NULL || appId->size < sizeof(WCHAR)) return FALSE;
    p = (const WCHAR*)appId->data;
    nchars = appId->size / sizeof(WCHAR);
    while (nchars > 0 && (p[nchars - 1] == 0 || p[nchars - 1] == L' ' || p[nchars - 1] == L'\t'))
        nchars--;                                    /* blob 尾部常带 NUL/空白,不参与比较 */
    for (i = 0; i < nchars; i++)
        if (p[i] == L'\\' || p[i] == L'/') start = i + 1;
    if (start >= nchars) return FALSE;

    KeAcquireSpinLock(&g_TableLock, &irql);
    for (ci = 0; ci < g_ImgCount && !hit; ci++) {
        ULONG rl = 0, j;
        while (rl < 63 && g_ImgRules[ci][rl]) rl++;
        if (rl == 0 || nchars - start < rl) continue;
        hit = TRUE;
        for (j = 0; j < rl; j++) {
            WCHAR a = p[start + j], b = g_ImgRules[ci][j];
            if (a >= L'A' && a <= L'Z') a += 32;
            if (b >= L'A' && b <= L'Z') b += 32;
            if (a != b) { hit = FALSE; break; }
        }
        if (hit && nchars - start > rl) {
            WCHAR c = p[start + rl];
            if (c != 0 && c != L' ' && c != L':' && c != L'"' && c != L'\'') hit = FALSE;
        }
    }
    KeReleaseSpinLock(&g_TableLock, irql);
    return hit;
}

static HPX_PROC* HpxTrustGate(const FWPS_INCOMING_METADATA_VALUES0* md, ULONG* hitPid);

/* 局域网判定(大端序值):精确 = 引擎推送的本机接口 on-link 网段(凡本链路可达
 * 即局域网,公网编址的局域网同样命中);兜底 = 固定私网/链路本地。
 * 命中者一律不代理(直连),全模式生效。 */
static BOOLEAN HpxIsLanV4(ULONG ipAny)
{
    ULONG i, n, a = ipAny >> 24, b = (ipAny >> 16) & 0xFF;
    KIRQL irql;
    BOOLEAN hit = FALSE;
    KeAcquireSpinLock(&g_TableLock, &irql);
    n = g_LanCount;
    for (i = 0; i < n; i++)
        if ((ipAny & g_LanMasks[i]) == g_LanNets[i]) { hit = TRUE; break; }
    KeReleaseSpinLock(&g_TableLock, irql);
    if (hit) return TRUE;
    if (a == 10) return TRUE;
    if (a == 192 && b == 168) return TRUE;
    if (a == 172 && b >= 16 && b <= 31) return TRUE;
    if (a == 169 && b == 254) return TRUE;
    return FALSE;
}

/* 存活中继登记/注销:g_RelayPid 始终指向表尾一个存活中继;
 * 只有表为空才允许直连(否则继续重定向到任一存活中继口)。 */
static void HpxRelayUp(ULONG pid)
{
    KIRQL irql;
    ULONG i;
    KeAcquireSpinLock(&g_TableLock, &irql);
    for (i = 0; i < g_RelayCount; i++) {
        if (g_RelayPids[i] == pid) {
            if (i + 1 < g_RelayCount)
                RtlMoveMemory(&g_RelayPids[i], &g_RelayPids[i + 1],
                              (g_RelayCount - i - 1) * sizeof(ULONG));
            g_RelayCount--;
            break;
        }
    }
    if (g_RelayCount < HPX_MAX_RELAYS) {
        g_RelayPids[g_RelayCount++] = pid;
    } else {
        RtlMoveMemory(g_RelayPids, g_RelayPids + 1, (HPX_MAX_RELAYS - 1) * sizeof(ULONG));
        g_RelayPids[HPX_MAX_RELAYS - 1] = pid;
    }
    g_RelayPid = (LONG)pid;
    KeReleaseSpinLock(&g_TableLock, irql);
}

static void HpxRelayDown(ULONG pid)
{
    KIRQL irql;
    ULONG i;
    KeAcquireSpinLock(&g_TableLock, &irql);
    for (i = 0; i < g_RelayCount; i++) {
        if (g_RelayPids[i] == pid) {
            if (i + 1 < g_RelayCount)
                RtlMoveMemory(&g_RelayPids[i], &g_RelayPids[i + 1],
                              (g_RelayCount - i - 1) * sizeof(ULONG));
            g_RelayCount--;
            break;
        }
    }
    g_RelayPid = g_RelayCount ? (LONG)g_RelayPids[g_RelayCount - 1] : 0;
    if (g_RelayCount == 0) g_Enabled = FALSE;
    KeReleaseSpinLock(&g_TableLock, irql);
}


/* 是否接管该进程:中继自身永不代理;全局模式=其余全部;否则 PID 登记或映像名规则命中 */
static BOOLEAN HpxShouldProxy(const FWPS_INCOMING_METADATA_VALUES0* md,
                              const FWP_BYTE_BLOB* appId, ULONG* hitPid)
{
    HPX_PROC* proc;
    LONG relayPid = g_RelayPid;
    ULONG pidMeta = 0;

    if (md && FWPS_IS_METADATA_FIELD_PRESENT(md, FWPS_METADATA_FIELD_PROCESS_ID))
        pidMeta = (ULONG)(ULONG_PTR)md->processId;
    if ((pidMeta != 0 && (LONG)pidMeta == relayPid) ||
        (LONG)(ULONG_PTR)PsGetCurrentProcessId() == relayPid)
        return FALSE;

    if (g_Global) {
        if (hitPid) *hitPid = pidMeta;
        return TRUE;
    }
    proc = HpxTrustGate(md, hitPid);
    if (proc != NULL) return TRUE;
    if (HpxImgRuleHit(appId)) {
        InterlockedIncrement(&g_CntImgHit);
        if (hitPid) *hitPid = pidMeta;
        return TRUE;
    }
    return FALSE;
}

static HPX_PROC* HpxTrustGate(const FWPS_INCOMING_METADATA_VALUES0* md, ULONG* hitPid)
{
    HPX_PROC* rec = NULL;
    KIRQL irql;
    ULONG pidMeta = 0, pidCur;
    LONG relayPid = g_RelayPid;
    if (md && FWPS_IS_METADATA_FIELD_PRESENT(md, FWPS_METADATA_FIELD_PROCESS_ID))
        pidMeta = (ULONG)(ULONG_PTR)md->processId;
    pidCur = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if ((pidMeta != 0 && (LONG)pidMeta == relayPid) || (LONG)pidCur == relayPid)
        return NULL;
    KeAcquireSpinLock(&g_TableLock, &irql);
    if (pidMeta != 0 && (rec = HpxFindProcByPidLocked(pidMeta)) != NULL) {
        *hitPid = pidMeta;
    } else if ((rec = HpxFindProcByPidLocked(pidCur)) != NULL) {
        *hitPid = pidCur;
    }
    KeReleaseSpinLock(&g_TableLock, irql);
    return rec;
}

/* ================= GC ================= */
static void HpxGcWorker(PVOID ctx)
{
    LONGLONG now;
    ULONG budget = 256;
    KIRQL irql;
    UNREFERENCED_PARAMETER(ctx);
    if (g_Unloading) {
        InterlockedExchange(&g_GcQueued, 0);
        return;
    }
    KeQueryTickCount((PLARGE_INTEGER)&now);
    KeAcquireSpinLock(&g_TableLock, &irql);
    while (budget-- > 0) {
        PLIST_ENTRY p, next;
        BOOLEAN removed = FALSE;
        for (p = g_FlowList.Flink; p != &g_FlowList; p = next) {
            HPX_FLOW* f = CONTAINING_RECORD(p, HPX_FLOW, link);
            next = p->Flink;
            if (now - f->created > (f->claimed ? g_TickGcClaimed : g_TickGcUnclaimed)) {
                RemoveEntryList(&f->link);
                ExFreeToNPagedLookasideList(&g_FlowLookaside, f);
                removed = TRUE;
                break;
            }
        }
        if (!removed) break;
    }
    KeReleaseSpinLock(&g_TableLock, irql);
    InterlockedExchange(&g_GcQueued, 0);
}

static void HpxGcKick(void)
{
    if (g_Unloading) return;
    if ((InterlockedIncrement(&g_CntRewrite) & 0xFF) == 0 &&
        InterlockedCompareExchange(&g_GcQueued, 1, 0) == 0) {
        if (g_Unloading) {
            InterlockedExchange(&g_GcQueued, 0);
            return;
        }
        ExInitializeWorkItem(&g_GcWork, HpxGcWorker, NULL);
        ExQueueWorkItem(&g_GcWork, DelayedWorkQueue);
    }
}

/* ================= 娉ㄥ叆鍩虹璁炬柦 ================= */
static void NTAPI HpxInjectComplete(void* context, NET_BUFFER_LIST* nbl, BOOLEAN dispatchLevel)
{
    HPX_INJ_CTX* ic = (HPX_INJ_CTX*)context;
    UNREFERENCED_PARAMETER(dispatchLevel);
    if (nbl) {
        /* 异步注入失败的 NBL 仍会走完成例程:计数以鉴别"接受注入≠送达" */
        if (nbl->Status != STATUS_SUCCESS) {
            InterlockedIncrement(&g_CntInjFail);
            InterlockedExchange(&g_InjLastStatus, (LONG)nbl->Status);
            if (ic) InterlockedExchange(&g_InjFailTag, ic->tag);
        }
        FwpsFreeNetBufferList0(nbl);
    }
    if (ic) {
        if (ic->mdl) IoFreeMdl(ic->mdl);
        if (ic->buf) ExFreePoolWithTag(ic->buf, HPX_POOL_TAG);
        ExFreePoolWithTag(ic, HPX_POOL_TAG);
    }
}

/* 鏋勯€犳暣鍖?src鈫抎st,浼€犳簮鐢?骞舵敞鍏?isSend=0 缃戠粶鎺ユ敹娉ㄥ叆(鍥炵▼鑵?,
 * isSend=1 缃戠粶鍙戦€佹敞鍏?澶囬€?銆俿rc/dst IP 涓?sin_addr 鍐呭瓨搴?绔彛涓虹綉缁滃簭 2 瀛楄妭銆?*/
static NTSTATUS HpxInjectUdpPacket(
    ULONG srcIpMem, USHORT srcPortNet,
    ULONG dstIpMem, USHORT dstPortNet,
    const UCHAR* payload, ULONG plen,
    UINT32 ifIndex, UINT32 compartmentId, BOOLEAN isSend, int tag)
{
    ULONG tlen;
    UCHAR* buf;
    PMDL mdl = NULL;
    NET_BUFFER_LIST* nbl = NULL;
    HPX_INJ_CTX* ic = NULL;
    NTSTATUS st;
    UCHAR* ip;
    UCHAR* udp;

    if (g_InjectHandle == NULL || plen > 65507)
        return STATUS_INVALID_PARAMETER;

    tlen = 20 + 8 + plen;
    buf = (UCHAR*)ExAllocatePoolWithTag(NonPagedPoolNx, tlen, HPX_POOL_TAG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(buf, tlen);

    /* IP 澶?*/
    ip = buf;
    ip[0] = 0x45;
    ip[2] = (UCHAR)(tlen >> 8);
    ip[3] = (UCHAR)(tlen & 0xFF);
    ip[8] = 64;                       /* TTL */
    ip[9] = 17;                       /* UDP */
    *(ULONG*)(ip + 12) = srcIpMem;    /* 婧?= 鍘熷鐩爣(鍐呭瓨搴忕洿鍏ュ寘澶? */
    *(ULONG*)(ip + 16) = dstIpMem;    /* 鐩殑 = 搴旂敤绔偣 */
    HpxFixIpChecksum(ip, 20);

    /* UDP 澶?鏍￠獙鍜岀疆 0,IPv4 鍚堟硶)銆?     * 绔彛瀛楁 = 缃戠粶搴忓師濮?2 瀛楄妭(涓?sin_port 鍐呭瓨瀛楄妭涓€鑷?memcpy 鐩村叆鍖呭ご)銆?*/
    udp = buf + 20;
    RtlCopyMemory(udp + 0, &srcPortNet, 2);
    RtlCopyMemory(udp + 2, &dstPortNet, 2);
    udp[4] = (UCHAR)((8 + plen) >> 8);
    udp[5] = (UCHAR)((8 + plen) & 0xFF);
    udp[6] = udp[7] = 0;
    if (plen) RtlCopyMemory(buf + 28, payload, plen);

    ic = (HPX_INJ_CTX*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*ic), HPX_POOL_TAG);
    if (!ic) { ExFreePoolWithTag(buf, HPX_POOL_TAG); return STATUS_INSUFFICIENT_RESOURCES; }
    ic->buf = buf;
    ic->mdl = NULL;
    ic->tag = tag;

    mdl = IoAllocateMdl(buf, tlen, FALSE, FALSE, NULL);
    if (!mdl) {
        ExFreePoolWithTag(buf, HPX_POOL_TAG);
        ExFreePoolWithTag(ic, HPX_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(mdl);
    ic->mdl = mdl;

    st = FwpsAllocateNetBufferAndNetBufferList0(g_NblPool, 0, 0, mdl, 0, tlen, &nbl);
    if (!NT_SUCCESS(st)) {
        HpxInjectComplete(ic, NULL, FALSE);
        return st;
    }

    if (isSend) {
        st = FwpsInjectNetworkSendAsync0(g_InjectHandle, NULL, 0,
                (COMPARTMENT_ID)compartmentId, nbl, HpxInjectComplete, ic);
    } else {
        /* [鍥炵▼鑵垮叧閿甝 interfaceIndex 鍙栧簲鐢ㄦ祦鎵€鍦ㄦ帴鍙?0=缂虹渷閫€鐜洖);
         * 鍘嗗彶鏁欒:纭紪鐮?1 鍦ㄩ潪鐜洖娴侀噺涓婃敞鍏ユ垚鍔熶絾涓嶈揪搴旂敤銆?*/
        st = FwpsInjectNetworkReceiveAsync0(g_InjectHandle, NULL, 0,
                (COMPARTMENT_ID)compartmentId,
                (IF_INDEX)(ifIndex ? ifIndex : 1),
                (IF_INDEX)0, nbl, HpxInjectComplete, ic);
    }
    if (!NT_SUCCESS(st)) {
        HpxInjectComplete(ic, nbl, FALSE);   /* 娉ㄥ叆澶辫触:鍚屾鍥炴敹 */
        InterlockedIncrement(&g_CntInjFail);
        return st;
    }
    InterlockedIncrement(&g_CntInjOk);
    return STATUS_SUCCESS;
}

static NTSTATUS HpxInjectInit(void)
{
    NET_BUFFER_LIST_POOL_PARAMETERS pp;
    NTSTATUS st;
    if (g_InjectHandle == NULL) {
        st = FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_NETWORK, &g_InjectHandle);
        if (!NT_SUCCESS(st)) return st;
    }
    if (g_NblPool == NULL) {
        RtlZeroMemory(&pp, sizeof(pp));
        pp.Header.Type       = NDIS_OBJECT_TYPE_DEFAULT;
        pp.Header.Revision   = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        pp.Header.Size       = sizeof(pp);
        pp.ProtocolId        = NDIS_PROTOCOL_ID_DEFAULT;
        pp.fAllocateNetBuffer = TRUE;
        pp.ContextSize       = 0;
        pp.PoolTag           = HPX_POOL_TAG;
        g_NblPool = NdisAllocateNetBufferListPool(NULL, &pp);
        if (g_NblPool == NULL) {
            FwpsInjectionHandleDestroy0(g_InjectHandle);
            g_InjectHandle = NULL;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    return STATUS_SUCCESS;
}

/* ================= WFP:杩囨护鍣?缁戝畾 ================= */
static NTSTATUS WfpPurgeFilters(const GUID* layerKey, const GUID* calloutKey)
{
    FWPM_FILTER_ENUM_TEMPLATE0 tpl;
    HANDLE eh = NULL;
    UINT32 i;
    NTSTATUS st;
    RtlZeroMemory(&tpl, sizeof(tpl));
    tpl.layerKey   = *layerKey;
    tpl.calloutKey = (GUID*)calloutKey;
    tpl.actionMask = 0xFFFFFFFF;
    st = FwpmFilterCreateEnumHandle0(g_EngineHandle, &tpl, &eh);
    if (!NT_SUCCESS(st)) return st;
    for (i = 0; i < 256; i++) {
        FWPM_FILTER0** entries = NULL;
        UINT32 count = 0, j;
        st = FwpmFilterEnum0(g_EngineHandle, eh, 16, &entries, &count);
        if (!NT_SUCCESS(st) || count == 0) break;
        for (j = 0; j < count; j++) FwpmFilterDeleteById0(g_EngineHandle, entries[j]->filterId);
        FwpmFreeMemory0((void**)&entries);
    }
    FwpmFilterDestroyEnumHandle0(g_EngineHandle, eh);
    return STATUS_SUCCESS;
}

static NTSTATUS WfpAddOne(const GUID* layerKey, const GUID* calloutKey,
                          const GUID* filterKey, UINT32 calloutId, UINT64* filterId,
                          const WCHAR* name)
{
    FWPM_CALLOUT0 mCallout;
    FWPM_FILTER0 filter;
    UINT64 weight = 15;
    NTSTATUS st;

    RtlZeroMemory(&mCallout, sizeof(mCallout));
    mCallout.calloutKey = *calloutKey;
    mCallout.displayData.name = (wchar_t*)name;
    mCallout.displayData.description = (wchar_t*)name;
    mCallout.applicableLayer = *layerKey;
    st = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(st)) { g_WfpStep = 41; return st; }

    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = *filterKey;
    filter.layerKey = *layerKey;
    filter.subLayerKey = HPX_SUBLAYER;
    filter.displayData.name = (wchar_t*)name;
    filter.displayData.description = (wchar_t*)name;
    filter.weight.type = FWP_UINT64;
    filter.weight.uint64 = &weight;
    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = *calloutKey;
    filter.numFilterConditions = 0;
    st = FwpmFilterAdd0(g_EngineHandle, &filter, NULL, filterId);
    if (!NT_SUCCESS(st)) { g_WfpStep = 42; return st; }
    (void)calloutId;
    return STATUS_SUCCESS;
}

static void WfpUnregisterCallouts(void)
{
    if (g_CalloutIdR4) { FwpsCalloutUnregisterById0(g_CalloutIdR4); g_CalloutIdR4 = 0; }
    if (g_CalloutIdD4) { FwpsCalloutUnregisterById0(g_CalloutIdD4); g_CalloutIdD4 = 0; }
    if (g_CalloutIdR6) { FwpsCalloutUnregisterById0(g_CalloutIdR6); g_CalloutIdR6 = 0; }
}

static void WfpShutdown(void)
{
    /* 1) 鍙嶆敞鍐岃繍琛屾椂 callout(绛夊緟鍦ㄩ€?classify 鎺掔┖),鏃犳潯浠跺叏閮ㄦ竻闆?*/
    WfpUnregisterCallouts();

    /* 2) 娉ㄥ叆璁炬柦 */
    if (g_InjectHandle) { FwpsInjectionHandleDestroy0(g_InjectHandle); g_InjectHandle = NULL; }
    if (g_NblPool)      { NdisFreeNetBufferListPool(g_NblPool); g_NblPool = NULL; }

    if (g_EngineHandle == NULL) return;

    if (g_WfpBound) {
        /* 3) 浜嬪姟鎵瑰垹 */
        FwpmTransactionBegin0(g_EngineHandle, 0);
        if (g_FilterIdR4) FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdR4);
        if (g_FilterIdD4) FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdD4);
        FwpmFilterDeleteByKey0(g_EngineHandle, &HPX_FILTER_REDIRECT_V4);
        FwpmFilterDeleteByKey0(g_EngineHandle, &HPX_FILTER_DATAGRAM_V4);
        FwpmFilterDeleteByKey0(g_EngineHandle, &HPX_FILTER_REDIRECT_V6);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &HPX_CALLOUT_REDIRECT_V4);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &HPX_CALLOUT_DATAGRAM_V4);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &HPX_CALLOUT_REDIRECT_V6);
        FwpmSubLayerDeleteByKey0(g_EngineHandle, &HPX_SUBLAYER);
        FwpmTransactionCommit0(g_EngineHandle);
        g_FilterIdR4 = g_FilterIdD4 = 0;
        g_WfpBound = FALSE;
    }

    /* 4) 閲嶅畾鍚戝彞鏌?/ 寮曟搸 */
    if (g_RedirectHandle) { FwpsRedirectHandleDestroy0(g_RedirectHandle); g_RedirectHandle = NULL; }
    FwpmEngineClose0(g_EngineHandle);
    g_EngineHandle = NULL;
}

extern void RedirectClassify(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*,
                             void*, const void*, const FWPS_FILTER1*, UINT64, FWPS_CLASSIFY_OUT0*);
extern void DatagramClassify(const FWPS_INCOMING_VALUES0*, const FWPS_INCOMING_METADATA_VALUES0*,
                             void*, const void*, const FWPS_FILTER1*, UINT64, FWPS_CLASSIFY_OUT0*);

/* classify:ALE_CONNECT_REDIRECT_V6 —— 数据面仅实现 IPv4;对受代理进程的 IPv6
 * 连接直接 BLOCK(fail-fast),让 happy-eyeballs 立即回落 v4 主路,并封死
 * "IPv6 直连/污染旁路";非受代理进程照常放行 */
void RedirectClassifyV6(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER1* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    ULONG hitPid = 0;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) return;
    InterlockedIncrement(&g_CntClassify);   /* v6 也计入:验证 v6 分类是否被触发 */
    if (!g_Enabled) goto permit;

    {
        const FWP_BYTE_BLOB* appIdV6 = inFixedValues->incomingValue[
            FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_APP_ID].value.byteBlob;
        if (!HpxShouldProxy(inMetaValues, appIdV6, &hitPid)) goto permit;
    }
    InterlockedIncrement(&g_CntV6Block);
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    return;

permit:
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

static NTSTATUS NTAPI HpxCalloutNotify0(FWPS_CALLOUT_NOTIFY_TYPE t, const GUID* k, FWPS_FILTER1* f)
{
    UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(k); UNREFERENCED_PARAMETER(f);
    return STATUS_SUCCESS;
}
static void NTAPI HpxFlowDeleteNotify0(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId); UNREFERENCED_PARAMETER(calloutId); UNREFERENCED_PARAMETER(flowContext);
}

static NTSTATUS WfpRegisterCallouts(void)
{
    FWPS_CALLOUT1 co;
    NTSTATUS st;
    if (g_CalloutIdR4 == 0) {
        RtlZeroMemory(&co, sizeof(co));
        co.calloutKey = HPX_CALLOUT_REDIRECT_V4;
        co.classifyFn = RedirectClassify;
        co.notifyFn = HpxCalloutNotify0;
        co.flowDeleteFn = HpxFlowDeleteNotify0;
        st = FwpsCalloutRegister1(g_DeviceObj, &co, &g_CalloutIdR4);
        if (!NT_SUCCESS(st)) { g_WfpStep = 40; return st; }
    }
    if (g_CalloutIdD4 == 0) {
        RtlZeroMemory(&co, sizeof(co));
        co.calloutKey = HPX_CALLOUT_DATAGRAM_V4;
        co.classifyFn = DatagramClassify;
        co.notifyFn = HpxCalloutNotify0;
        co.flowDeleteFn = HpxFlowDeleteNotify0;
        st = FwpsCalloutRegister1(g_DeviceObj, &co, &g_CalloutIdD4);
        if (!NT_SUCCESS(st)) { g_WfpStep = 40; return st; }
    }
    if (g_CalloutIdR6 == 0) {
        RtlZeroMemory(&co, sizeof(co));
        co.calloutKey = HPX_CALLOUT_REDIRECT_V6;
        co.classifyFn = RedirectClassifyV6;
        co.notifyFn = HpxCalloutNotify0;
        co.flowDeleteFn = HpxFlowDeleteNotify0;
        st = FwpsCalloutRegister1(g_DeviceObj, &co, &g_CalloutIdR6);
        if (!NT_SUCCESS(st)) { g_WfpStep = 40; return st; }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS WfpStartup(void)
{
    FWPM_PROVIDER0 provider;
    FWPM_SUBLAYER0 sublayer;
    NTSTATUS st;

    /* 1) 引擎(RPC,严禁在 DriverEntry) */
    if ((g_WfpMode & 8) == 0 && g_EngineHandle == NULL) {
        st = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_EngineHandle);
        if (!NT_SUCCESS(st)) { g_WfpStep = 1; return st; }
    }

    /* 2) 重定向句柄(TCP 重定向自标记 + TargetPID 递交用) */
    if ((g_WfpMode & 2) == 0 && g_RedirectHandle == NULL) {
        st = FwpsRedirectHandleCreate0(&HPX_PROVIDER, 0, &g_RedirectHandle);
        if (!NT_SUCCESS(st)) { g_WfpStep = 48; return st; }
    }

    if (g_WfpMode & 8) {
        g_WfpStep = 100;
        g_WfpStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;      /* 冻结二分:完全不碰 WFP 管理面 */
    }
    if (g_WfpMode & 4) {
        g_WfpStep = 101;
        g_WfpStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;      /* 冻结二分:只做引擎打开+重定向句柄+注入设施 */
    }

    /* 3) provider + 注入设施 */
    RtlZeroMemory(&provider, sizeof(provider));
    provider.providerKey = HPX_PROVIDER;
    provider.displayData.name = (wchar_t*)L"HPX Provider";
    provider.displayData.description = (wchar_t*)L"HPX Provider";
    FwpmProviderAdd0(g_EngineHandle, &provider, NULL);

    if ((g_WfpMode & 1) == 0) {
        st = HpxInjectInit();
        if (!NT_SUCCESS(st)) { g_WfpStep = 49; return st; }
    }
    if (g_WfpMode & 16) {
        g_WfpStep = 102;
        g_WfpStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;      /* 冻结二分:只做引擎+句柄+注入+provider,不做 callout/子层/事务 */
    }

    /* 4) 杩愯鏃?callout(鑷剤閲嶈瘯) */
    if ((g_WfpMode & 32) == 0) {
        st = WfpRegisterCallouts();
        if (!NT_SUCCESS(st)) return st;
    }

    /* 5) 浜嬪姟:purge 鈫?瀛愬眰 鈫?涓や釜杩囨护鍣?*/
    /* purge 在事务外:事务内删除对枚举不可见,曾致同批 ID 反复删除累积数千操作、
     * BFE 大事务提交卡死网络分类(冻结根因) */
    WfpPurgeFilters(&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, &HPX_CALLOUT_REDIRECT_V4);
    WfpPurgeFilters(&FWPM_LAYER_DATAGRAM_DATA_V4, &HPX_CALLOUT_DATAGRAM_V4);
    WfpPurgeFilters(&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, &HPX_CALLOUT_REDIRECT_V6);
    st = FwpmTransactionBegin0(g_EngineHandle, 0);
    if (!NT_SUCCESS(st)) { g_WfpStep = 2; return st; }
    FwpmFilterDeleteByKey0(g_EngineHandle, &HPX_FILTER_REDIRECT_V4);
    FwpmFilterDeleteByKey0(g_EngineHandle, &HPX_FILTER_DATAGRAM_V4);
        FwpmFilterDeleteByKey0(g_EngineHandle, &HPX_FILTER_REDIRECT_V6);
    FwpmCalloutDeleteByKey0(g_EngineHandle, &HPX_CALLOUT_REDIRECT_V4);
    FwpmCalloutDeleteByKey0(g_EngineHandle, &HPX_CALLOUT_DATAGRAM_V4);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &HPX_CALLOUT_REDIRECT_V6);
    FwpmSubLayerDeleteByKey0(g_EngineHandle, &HPX_SUBLAYER);

    RtlZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey = HPX_SUBLAYER;
    sublayer.displayData.name = (wchar_t*)L"HPX SubLayer";
    sublayer.displayData.description = (wchar_t*)L"HPX SubLayer";
    sublayer.weight = 0xFFFF;
    st = FwpmSubLayerAdd0(g_EngineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(st)) { g_WfpStep = 3; FwpmTransactionAbort0(g_EngineHandle); return st; }

    if (g_WfpLayers & 1) {
        st = WfpAddOne(&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, &HPX_CALLOUT_REDIRECT_V4,
                       &HPX_FILTER_REDIRECT_V4, g_CalloutIdR4, &g_FilterIdR4,
                       L"HPX Redirect V4");
        if (!NT_SUCCESS(st)) { FwpmTransactionAbort0(g_EngineHandle); return st; }
        st = WfpAddOne(&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, &HPX_CALLOUT_REDIRECT_V6,
                       &HPX_FILTER_REDIRECT_V6, g_CalloutIdR6, &g_FilterIdR6,
                       L"HPX Redirect V6 (block)");
        if (!NT_SUCCESS(st)) { FwpmTransactionAbort0(g_EngineHandle); return st; }
    }
    if (g_WfpLayers & 2) {
        st = WfpAddOne(&FWPM_LAYER_DATAGRAM_DATA_V4, &HPX_CALLOUT_DATAGRAM_V4,
                       &HPX_FILTER_DATAGRAM_V4, g_CalloutIdD4, &g_FilterIdD4,
                       L"HPX Datagram V4");
        if (!NT_SUCCESS(st)) { FwpmTransactionAbort0(g_EngineHandle); return st; }
    }

    st = FwpmTransactionCommit0(g_EngineHandle);
    if (!NT_SUCCESS(st)) { g_WfpStep = 6; return st; }

    g_WfpStep = 100;
    g_WfpStatus = STATUS_SUCCESS;
    g_WfpBound = TRUE;
    return STATUS_SUCCESS;
}

static void HpxWfpWorker(PVOID ctx)
{
    NTSTATUS st;
    UNREFERENCED_PARAMETER(ctx);
    if (g_Unloading) {
        InterlockedExchange(&g_WfpWorkQueued, 0);
        return;
    }
    st = WfpStartup();
    if (!NT_SUCCESS(st)) g_WfpStatus = st;
    InterlockedExchange(&g_WfpWorkQueued, 0);
}

static void WfpStartupAsync(void)
{
    if (g_Unloading) return;
    if (InterlockedCompareExchange(&g_WfpWorkQueued, 1, 0) == 0) {
        if (g_Unloading) {
            InterlockedExchange(&g_WfpWorkQueued, 0);
            return;
        }
        ExInitializeWorkItem(&g_WfpWork, HpxWfpWorker, NULL);
        ExQueueWorkItem(&g_WfpWork, DelayedWorkQueue);
    }
}

/* ================= classify:ALE_CONNECT_REDIRECT_V4 ================= */
void RedirectClassify(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER1* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    UCHAR protocol;
    ULONG remoteIpF, localIpF;
    USHORT remotePortH, localPortH;
    ULONG hitPid = 0;
    KIRQL irql;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);

    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
        InterlockedIncrement(&g_CntNoRights);
        return;                          /* ALE 灞傞粯璁ゅ姩浣?= 鏀捐,瑁歌繑鍥炲畨鍏?*/
    }
    InterlockedIncrement(&g_CntClassify);

    if (!g_Enabled) goto permit;

    protocol = (UCHAR)inFixedValues->incomingValue[
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8;
    remoteIpF = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    remotePortH = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16;
    localIpF = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS].value.uint32;
    localPortH = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT].value.uint16;

    /* 鐩殑鍏滃簳:fixed value 杩滅▼鍦板潃鍙兘涓?0(24H2 瀹炶瘉),鍙栧厓鏁版嵁鍘熷鐩殑 */
    if (remoteIpF == 0 && inMetaValues &&
        FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_ORIGINAL_DESTINATION)) {
        SOCKADDR_IN* od = (SOCKADDR_IN*)inMetaValues->originalDestination;
        if (od && od->sin_family == AF_INET) {
            remoteIpF = HpxSwap32(od->sin_addr.S_un.S_addr);   /* sin_addr 鍐呭瓨搴?鈫?fixed 搴?*/
            if (remotePortH == 0) remotePortH = HpxSwap16(od->sin_port);
        }
    }

    /* 璺宠繃:鐜洖/闆?缁勬挱/淇濈暀/涓户绔彛(鍏ㄩ儴搴忔棤鍏? */
    if (HpxSkipDestV4(remoteIpF) || HpxIsRelayPort(remotePortH)) goto permit;
    if (HpxIsLanV4(remoteIpF)) goto permit;   /* 局域网一律不代理(精确网段判定,全模式) */

    /* 杩囨护鐧藉悕鍗?闈炵┖鏃?鐩殑 IP 鎴栫鍙ｅ懡涓叾涓€鎵嶄唬鐞? */
    if (g_FilterIpCount > 0 || g_FilterPortCount > 0) {
        ULONG i, memIp = HpxSwap32(remoteIpF);
        BOOLEAN hit = FALSE;
        for (i = 0; i < g_FilterIpCount; i++)
            if (g_FilterIps[i] == memIp || g_FilterIps[i] == remoteIpF) { hit = TRUE; break; }
        if (!hit)
            for (i = 0; i < g_FilterPortCount; i++)
                if (g_FilterPorts[i] == remotePortH) { hit = TRUE; break; }
        if (!hit) goto permit;
    }

    {
        const FWP_BYTE_BLOB* appIdV = inFixedValues->incomingValue[
            FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID].value.byteBlob;
        if (!HpxShouldProxy(inMetaValues, appIdV, &hitPid)) goto permit;
    }
    InterlockedIncrement(&g_CntPidHit);
    InterlockedExchange(&g_SnapPort, (LONG)remotePortH);
    InterlockedExchange(&g_SnapIp, (LONG)remoteIpF);

    if (protocol == 17) {
        /* QUIC(UDP/443)对受代理进程 fail-fast 拦截:经节点 UDP 中继的吞吐远逊
         * TCP(实测 30 vs 100+Mbps),且系统代理语义本就 TCP-only;拦截后应用
         * 立刻回落 TCP/443(透明代理可靠主路),对齐系统代理的速度与稳定性 */
        if (remotePortH == 443) {
            InterlockedIncrement(&g_CntQuicBlock);
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            return;
        }
        /* UDP:鍙涓嶆敼(24H2 杩炴帴閲嶅畾鍚戝崐瀹屾垚榛戞礊;鏀瑰啓涓嬫矇鍒版暟鎹姤灞? */
        HPX_FLOW* f = (HPX_FLOW*)ExAllocateFromNPagedLookasideList(&g_FlowLookaside);
        if (f == NULL) { InterlockedIncrement(&g_CntAllocFail); goto permit; }
        RtlZeroMemory(f, sizeof(*f));
        KeAcquireSpinLock(&g_TableLock, &irql);
        if (g_NextFlowId == 0) g_NextFlowId = 1;
        f->flowId = g_NextFlowId++;
        f->pid = hitPid;
        f->remoteIpV4 = HpxSwap32(remoteIpF);
        f->remotePort = remotePortH;
        f->localIpV4 = HpxSwap32(localIpF);
        f->localPort = localPortH;
        f->protocol = 17;
        f->compartmentId = inMetaValues ? (UINT32)inMetaValues->compartmentId : 0;
        KeQueryTickCount((PLARGE_INTEGER)&f->created);
        InsertTailList(&g_FlowList, &f->link);
        KeReleaseSpinLock(&g_TableLock, irql);
        HpxGcKick();
        HpxEventPush(EV_FLOW_REDIRECTED, f->flowId, hitPid, f->remoteIpV4, (remotePortH << 8) | 17);
        goto permit;
    }

    if (protocol == 6) {
        /* TCP:鏀瑰啓鍒?127.0.0.1:TCP 涓户鍙?*/
        UINT64 classifyHandle = 0;
        FWPS_CONNECT_REQUEST0* cr = NULL;
        NTSTATUS st;
        SOCKADDR_IN* rsa;
        HPX_FLOW* f;
        BOOLEAN alreadyRelay, oursBefore;

        /* 无存活中继才放行直连:g_RelayPid 来自"存活中继登记表"
         * (StartRelay 成功监听才 RELAY_UP,StopRelay/Close 注销),
         * 任一其他中继实例退出不再误伤在运中继(2026-10-18 间隔掉线修复)。 */
        if (g_RelayPid == 0) goto permit;

        st = FwpsAcquireClassifyHandle((void*)classifyContext, 0, &classifyHandle);
        if (!NT_SUCCESS(st)) goto permit;
        st = FwpsAcquireWritableLayerDataPointer0(classifyHandle, filter->filterId, 0,
                                                  (PVOID*)&cr, classifyOut);
        if (!NT_SUCCESS(st)) {
            FwpsReleaseClassifyHandle(classifyHandle);
            goto permit;
        }

        /* cr 鐩殑鍏滃簳(鍐呭瓨搴? */
        {
            SOCKADDR_IN* cra = (SOCKADDR_IN*)&cr->remoteAddressAndPort;
            if (remoteIpF == 0 && cra->sin_addr.S_un.S_addr != 0) {
                remoteIpF = HpxSwap32(cra->sin_addr.S_un.S_addr);
            }
        }

        alreadyRelay =
            (((SOCKADDR_IN*)&cr->remoteAddressAndPort)->sin_addr.S_un.S_addr == RtlUlongByteSwap(0x7F000001)) &&
            (((SOCKADDR_IN*)&cr->remoteAddressAndPort)->sin_port == HpxSwap16(g_RelayPortTcp));
        oursBefore = (cr->previousVersion != NULL && cr->localRedirectHandle == g_RedirectHandle);
        if (alreadyRelay || oursBefore) {
            InterlockedIncrement(&g_CntPrev);
            FwpsApplyModifiedLayerData0(classifyHandle, cr, 0);
            FwpsReleaseClassifyHandle(classifyHandle);
            goto permit;
        }

        f = (HPX_FLOW*)ExAllocateFromNPagedLookasideList(&g_FlowLookaside);
        if (f == NULL) {
            InterlockedIncrement(&g_CntAllocFail);
            FwpsApplyModifiedLayerData0(classifyHandle, cr, 0);
            FwpsReleaseClassifyHandle(classifyHandle);
            goto permit;               /* 闄嶇骇鐩磋繛 */
        }
        RtlZeroMemory(f, sizeof(*f));
        KeAcquireSpinLock(&g_TableLock, &irql);
        if (g_NextFlowId == 0) g_NextFlowId = 1;
        f->flowId = g_NextFlowId++;
        f->pid = hitPid;
        f->remoteIpV4 = HpxSwap32(remoteIpF);
        f->remotePort = remotePortH;
        f->localIpV4 = HpxSwap32(localIpF);
        f->localPort = localPortH;
        f->protocol = 6;
        f->compartmentId = inMetaValues ? (UINT32)inMetaValues->compartmentId : 0;
        KeQueryTickCount((PLARGE_INTEGER)&f->created);
        InsertTailList(&g_FlowList, &f->link);
        KeReleaseSpinLock(&g_TableLock, irql);

        /* 鏀瑰啓 cr:鐩殑 = 127.0.0.1:TCP 涓户鍙?*/
        rsa = (SOCKADDR_IN*)&cr->remoteAddressAndPort;
        rsa->sin_family = AF_INET;
        rsa->sin_addr.S_un.S_addr = RtlUlongByteSwap(0x7F000001);
        rsa->sin_port = HpxSwap16(g_RelayPortTcp);

        /* Win8+ 鍥炵幆閲嶅畾鍚戝绾?鑷爣璁板彞鏌?+ 浠呮湰鍦版槧灏?+ 鎵挎帴鏂?PID;
         * 涓ョ璁剧疆 localRedirectContext(24H2 瑙﹀彂鏀跺寘绨胯鐥?鎸傛缃戠粶鏍? */
        cr->localRedirectHandle = g_RedirectHandle;
        {
            FWP_VALUE0 v;
            v.type = FWP_UINT32;
            v.uint32 = FWP_OPTION_VALUE_ENABLE_LOCAL_ONLY_MAPPING;
            FwpsClassifyOptionSet0(inMetaValues, FWP_CLASSIFY_OPTION_LOCAL_ONLY_MAPPING, &v);
        }
        if (g_RelayPid != 0)
            cr->localRedirectTargetPID = (DWORD)(ULONG_PTR)g_RelayPid;

        FwpsApplyModifiedLayerData0(classifyHandle, cr, 0);
        FwpsReleaseClassifyHandle(classifyHandle);

        HpxGcKick();
        HpxEventPush(EV_FLOW_REDIRECTED, f->flowId, hitPid, f->remoteIpV4, (remotePortH << 8) | 6);
    }

permit:
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

/* ================= classify:DATAGRAM_DATA_V4 ================= */
void DatagramClassify(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER1* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    NET_BUFFER* nb;
    PMDL mdl;
    UCHAR* p;
    UCHAR* scratch = NULL;
    ULONG dlen;
    USHORT pktSrcH, pktDstH;
    ULONG srcIpF;
    KIRQL irql;

    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
        /* [瀹炶瘉濂戠害] 鏁版嵁鎶ュ眰鍏ョ珯鍒嗙被甯告棤鍐欐潈闄?瑁?return 浼氱户鎵垮紩鎿庨粯璁?BLOCK,
         * 鎶婅繙绔叆绔?UDP 涓€缃戞墦灏?鍙傝€冨伐绋嬫牴鍥犳敞閲?銆傚繀椤昏惤鍒?PERMIT 鏀跺熬銆?*/
        InterlockedIncrement(&g_CntNoRights);
        goto permit;
    }
    InterlockedIncrement(&g_CntDatagram);

    if (!g_Enabled) goto permit;

    if (layerData == NULL) goto permit;
    nb = ((NET_BUFFER_LIST*)layerData)->FirstNetBuffer;
    if (nb == NULL) goto permit;
    dlen = NET_BUFFER_DATA_LENGTH(nb);
    mdl = NET_BUFFER_CURRENT_MDL(nb);
    if (mdl == NULL) goto permit;
    if (dlen < 8 || dlen > 65535) goto permit;
    /* 整包连续化:NBL 的 MDL 常只含 UDP 头、载荷在后续 MDL,
     * 直接按 dlen 线性读会越过 MDL 边界取到脏内存(曾致注入载荷乱码) */
    p = (UCHAR*)NdisGetDataBuffer(nb, dlen, NULL, 1, 0);
    if (p == NULL) {
        scratch = (UCHAR*)ExAllocatePoolWithTag(NonPagedPoolNx, dlen, HPX_POOL_TAG);
        if (scratch == NULL) goto permit;
        p = (UCHAR*)NdisGetDataBuffer(nb, dlen, scratch, 1, 0);
        if (p == NULL) goto permit;
    }

    pktSrcH = (USHORT)((p[0] << 8) | p[1]);   /* 澶撮儴鎵嬪伐澶х瑙ｆ瀽 鈫?涓绘満搴?*/
    pktDstH = (USHORT)((p[2] << 8) | p[3]);

    /* 涓户鍙ｇ洿閫?鐩殑涓轰腑缁х鍙ｇ殑鍖?鍚湰椹卞姩鐨勬敞鍏ュ壇鏈?姘镐笉鍚告敹 */
    if (HpxIsRelayPort(pktDstH)) goto permit;

    if (HpxIsRelayPort(pktSrcH)) {
        /* 鍥炲寘鑵?婧愬彛 = UDP 涓户鍙?鈫?婧愬彛鏀瑰洖鍘熷鐩殑(鏈湴閫掗€佷笉缁忔暟鎹姤灞?
         * 24H2 涓婅鑵垮疄闄呰蛋涓嶅埌;鏈哄埗淇濈暀,璁℃暟鍙) */
        HPX_FLOW* hit = NULL;
        KeAcquireSpinLock(&g_TableLock, &irql);
        {
            PLIST_ENTRY e;
            ULONG guard = 512;   /* 闄愰暱鍖归厤:闃查摼琛ㄦ崯鍧忔椂鑷棆姝绘満 */
            for (e = g_FlowList.Flink; e != &g_FlowList && guard-- > 0; e = e->Flink) {
                HPX_FLOW* f = CONTAINING_RECORD(e, HPX_FLOW, link);
                if (f->protocol == 17 && f->localPort == pktDstH) { hit = f; break; }
            }
        }
        if (hit) {
            p[0] = (UCHAR)(hit->remotePort >> 8);
            p[1] = (UCHAR)(hit->remotePort & 0xFF);
            p[6] = p[7] = 0;
            InterlockedIncrement(&g_CntBackRw);
        }
        KeReleaseSpinLock(&g_TableLock, irql);
        goto permit;
    }

    /* 局域网一律不代理(全模式):对端为 LAN 的数据报直连,不吸收不重写。
     * 精确判定 = 引擎推送的 on-link 网段(对端命中即本链路可达,入/出向同义)。 */
    {
        ULONG remIpF = inFixedValues->incomingValue[
            FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32;
        if (HpxIsLanV4(remIpF)) goto permit;
    }

    /* 搴旂敤鑵?鍥炲寘璞佸厤(婧愬彛 = 浠讳竴璁板綍鐨勫師濮嬬洰鐨勫彛 = 浼€犲洖鍖?涓婃父鍥炲寘,缁濅笉鍐嶅惛鏀? */
    {
        BOOLEAN exempt = FALSE;
        HPX_FLOW* hit = NULL;
        BOOLEAN backfill = FALSE;
        UINT32 ifIndex, compId;

        KeAcquireSpinLock(&g_TableLock, &irql);
        {
            PLIST_ENTRY e;
            ULONG guard = 512;
            for (e = g_FlowList.Flink; e != &g_FlowList && guard-- > 0; e = e->Flink) {
                HPX_FLOW* f = CONTAINING_RECORD(e, HPX_FLOW, link);
                if (f->protocol == 17 && f->remotePort == pktSrcH) { exempt = TRUE; break; }
            }
        }
        if (exempt) {
            KeReleaseSpinLock(&g_TableLock, irql);
            InterlockedIncrement(&g_CntExempt);
            goto permit;
        }

        /* 4 鍏冪粍閰嶅:鐩殑鍙ｉ敋瀹?+ 婧愬彛鍖归厤/棣栧寘鍥炲～(鍥犳灉寰?搴旂敤鍙戝寘鍏堜簬涓户杞彂,
         * 鍥炲～鍚庝腑缁ц浆鍙戣吙婧愬彛涓嶅悓姘镐笉鍛戒腑,鑷埅鑾风幆缁撴瀯鎬у叧闂? */
        {
            PLIST_ENTRY e;
            ULONG guard = 512;
            for (e = g_FlowList.Flink; e != &g_FlowList && guard-- > 0; e = e->Flink) {
                HPX_FLOW* f = CONTAINING_RECORD(e, HPX_FLOW, link);
                if (f->protocol != 17) continue;
                if (f->remotePort != pktDstH) continue;
                if (f->localPort != 0 && f->localPort != pktSrcH) continue;
                hit = f;
                if (f->localPort == 0) { f->localPort = pktSrcH; backfill = TRUE; }
                break;
            }
        }
        if (hit == NULL) {
            KeReleaseSpinLock(&g_TableLock, irql);
            InterlockedIncrement(&g_CntDgPermit);
            goto permit;
        }

        InterlockedIncrement(&g_CntDgHit);
        ifIndex = hit->ifIndex;
        compId = hit->compartmentId;
        if (ifIndex == 0) {
            ifIndex = inFixedValues->incomingValue[
                FWPS_FIELD_DATAGRAM_DATA_V4_INTERFACE_INDEX].value.uint32;
            hit->ifIndex = ifIndex;
        }
        srcIpF = inFixedValues->incomingValue[
            FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS].value.uint32;
        KeReleaseSpinLock(&g_TableLock, irql);
        (void)backfill;

        /* 鍚告敹 + 鏁村寘娉ㄥ叆:src=搴旂敤绔偣(鍐呭瓨搴?,dst=127.0.0.1:UDP 涓户鍙?*/
        if (dlen > 8 && dlen <= 65535 && g_InjectHandle != NULL) {
            NTSTATUS st = HpxInjectUdpPacket(
                HpxSwap32(srcIpF), *(USHORT*)p,               /* 婧?IP 鍐呭瓨搴?+ 婧愬彛缃戠粶搴忓師鏍?*/
                RtlUlongByteSwap(0x7F000001), HpxSwap16(g_RelayPortUdp),
                p + 8, dlen - 8, 1, compId, FALSE, 1);   /* 入站注入(ifIndex=1 回环):出站注入被栈拒 STATUS_INVALID_ADDRESS_COMPONENT */
            if (NT_SUCCESS(st)) InterlockedIncrement(&g_CntDgramRw);
        }

        /* 鍘熷寘鍚告敹 */
        if (scratch) ExFreePoolWithTag(scratch, HPX_POOL_TAG);
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

permit:
    if (scratch) ExFreePoolWithTag(scratch, HPX_POOL_TAG);
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

/* ================= IOCTL 澶勭悊鍣?================= */
static NTSTATUS IoctlHandshake(PVOID buf, ULONG inLen, ULONG outLen, ULONG_PTR* info)
{
    HPX_HANDSHAKE* hs = (HPX_HANDSHAKE*)buf;
    if (inLen < sizeof(HPX_HANDSHAKE) || hs->cbSize != HPX_HANDSHAKE_SIZE)
        return STATUS_INVALID_PARAMETER;
    if (outLen < sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
    if (!g_WfpBound) WfpStartupAsync();
    /* relayPid 不再由握手提前占位:仅 StartRelay 成功监听后 RELAY_UP 才登记,
     * 避免"探测实例握手失败→退出"把在运中继的转发资格一并带走。 */
    *(ULONG*)buf = HPX_HANDSHAKE_SIZE;
    *info = sizeof(ULONG);
    return STATUS_SUCCESS;
}

static NTSTATUS IoctlControl(PVOID buf, ULONG inLen, ULONG outLen, ULONG_PTR* info)
{
    HPX_CONTROL_IN* in = (HPX_CONTROL_IN*)buf;
    ULONG cmd, param;
    if (inLen < sizeof(HPX_CONTROL_IN)) return STATUS_BUFFER_TOO_SMALL;
    cmd = in->cmd;
    param = in->param;

    switch (cmd) {
    case HPX_CTRL_ADD_PID: {
        HPX_PROC* rec;
        KIRQL irql;
        ULONG newId = 0;
        if (param == 0) return STATUS_INVALID_PARAMETER;
        if (!HpxRateAllow(32)) { InterlockedIncrement(&g_CntDenied); return STATUS_QUOTA_EXCEEDED; }
        KeAcquireSpinLock(&g_TableLock, &irql);
        rec = HpxFindProcByPidLocked(param);
        if (rec) {
            rec->enabled = TRUE;
            rec->limitReached = FALSE;
            newId = rec->id;
        } else {
            rec = (HPX_PROC*)ExAllocateFromNPagedLookasideList(&g_ProcLookaside);
            if (rec) {
                RtlZeroMemory(rec, sizeof(*rec));
                if (g_NextProcId == 0) g_NextProcId = 1;
                rec->id = g_NextProcId++;
                rec->pid = param;
                rec->enabled = TRUE;
                rec->limitUp = rec->limitDown = HPX_DEFAULT_FLOW_LIMIT;
                InsertTailList(&g_ProcList, &rec->link);
                newId = rec->id;
            }
        }
        KeReleaseSpinLock(&g_TableLock, irql);
        if (!rec) return STATUS_INSUFFICIENT_RESOURCES;
        HpxEventPush(EV_RECORD_ADDED, newId, param, 0, 0);
        if (outLen >= sizeof(ULONG)) { *(ULONG*)buf = newId; *info = sizeof(ULONG); }
        return STATUS_SUCCESS;
    }
    case HPX_CTRL_REMOVE_PID: {
        KIRQL irql;
        ULONG oldId = 0;
        KeAcquireSpinLock(&g_TableLock, &irql);
        {
            PLIST_ENTRY e;
            for (e = g_ProcList.Flink; e != &g_ProcList; e = e->Flink) {
                HPX_PROC* rec = CONTAINING_RECORD(e, HPX_PROC, link);
                if (rec->pid == param && rec->enabled) {
                    rec->enabled = FALSE;
                    oldId = rec->id;
                    break;
                }
            }
        }
        KeReleaseSpinLock(&g_TableLock, irql);
        if (oldId) HpxEventPush(EV_RECORD_REMOVED, oldId, param, 0, 0);
        return STATUS_SUCCESS;
    }
    case HPX_CTRL_SET_TCP_PORT:
        if (param >= 1 && param <= 0xFFFF) g_RelayPortTcp = (USHORT)param;
        return STATUS_SUCCESS;
    case HPX_CTRL_SET_UDP_PORT:
        if (param >= 1 && param <= 0xFFFF) g_RelayPortUdp = (USHORT)param;
        return STATUS_SUCCESS;
    case HPX_CTRL_ENABLE:
        if (param) {
            g_Enabled = TRUE;
        } else {
            KIRQL irql;
            ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            KeAcquireSpinLock(&g_TableLock, &irql);
            if (g_RelayCount == 0 ||
                (g_RelayCount == 1 && g_RelayPids[0] == pid)) g_Enabled = FALSE;
            KeReleaseSpinLock(&g_TableLock, irql);
        }
        return STATUS_SUCCESS;
    case HPX_CTRL_RESET: {
        KIRQL irql;
        KeAcquireSpinLock(&g_TableLock, &irql);
        while (!IsListEmpty(&g_FlowList)) {
            PLIST_ENTRY e = RemoveHeadList(&g_FlowList);
            HPX_FLOW* f = CONTAINING_RECORD(e, HPX_FLOW, link);
            ExFreeToNPagedLookasideList(&g_FlowLookaside, f);
        }
        while (!IsListEmpty(&g_ProcList)) {
            PLIST_ENTRY e = RemoveHeadList(&g_ProcList);
            HPX_PROC* r = CONTAINING_RECORD(e, HPX_PROC, link);
            ExFreeToNPagedLookasideList(&g_ProcLookaside, r);
        }
        /* 映像名规则是"配置"不是"状态":跨清空/重启保留(曾被误清,重启后
         * 新进程回到登记竞态=用户感知"刷新有时显示未代理 IP") */
        KeReleaseSpinLock(&g_TableLock, irql);
        return STATUS_SUCCESS;
    }
    case HPX_CTRL_ADD_IP:
        if (g_FilterIpCount < RTL_NUMBER_OF(g_FilterIps)) {
            KIRQL irql;
            KeAcquireSpinLock(&g_TableLock, &irql);
            g_FilterIps[g_FilterIpCount++] = param;
            KeReleaseSpinLock(&g_TableLock, irql);
        }
        return STATUS_SUCCESS;
    case HPX_CTRL_DEL_IP: {
        KIRQL irql;
        ULONG i;
        KeAcquireSpinLock(&g_TableLock, &irql);
        for (i = 0; i < g_FilterIpCount; i++) {
            if (g_FilterIps[i] == param) {
                g_FilterIps[i] = g_FilterIps[--g_FilterIpCount];
                break;
            }
        }
        KeReleaseSpinLock(&g_TableLock, irql);
        return STATUS_SUCCESS;
    }
    case HPX_CTRL_ADD_PORT:
        if (g_FilterPortCount < RTL_NUMBER_OF(g_FilterPorts)) {
            KIRQL irql;
            KeAcquireSpinLock(&g_TableLock, &irql);
            g_FilterPorts[g_FilterPortCount++] = (USHORT)param;
            KeReleaseSpinLock(&g_TableLock, irql);
        }
        return STATUS_SUCCESS;
    case HPX_CTRL_DEL_PORT: {
        KIRQL irql;
        ULONG i;
        KeAcquireSpinLock(&g_TableLock, &irql);
        for (i = 0; i < g_FilterPortCount; i++) {
            if (g_FilterPorts[i] == (USHORT)param) {
                g_FilterPorts[i] = g_FilterPorts[--g_FilterPortCount];
                break;
            }
        }
        KeReleaseSpinLock(&g_TableLock, irql);
        return STATUS_SUCCESS;
    }
    case HPX_CTRL_ADD_IMG: {
        /* 入参:buf = {cmd(4), pad(4), WCHAR name[64]}(经 IOCTL 入参缓冲) */
        const WCHAR* nm = (const WCHAR*)((const UCHAR*)buf + 2 * sizeof(ULONG));
        ULONG avail = (inLen > 2 * sizeof(ULONG)) ? (inLen - 2 * sizeof(ULONG)) : 0;
        KIRQL irql;
        if (avail < sizeof(WCHAR)) return STATUS_INVALID_PARAMETER;
        KeAcquireSpinLock(&g_TableLock, &irql);
        if (g_ImgCount < 8) {
            ULONG k;
            for (k = 0; k < 63 && (k + 1) * sizeof(WCHAR) <= avail && nm[k]; k++)
                g_ImgRules[g_ImgCount][k] = nm[k];
            g_ImgRules[g_ImgCount][k] = 0;
            if (k > 0) g_ImgCount++;
        }
        KeReleaseSpinLock(&g_TableLock, irql);
        return STATUS_SUCCESS;
    }
    case HPX_CTRL_SET_GLOBAL:
        g_Global = (param != 0);
        return STATUS_SUCCESS;
    case HPX_CTRL_CLEAR_LAN: {
        KIRQL irql;
        KeAcquireSpinLock(&g_TableLock, &irql);
        g_LanCount = 0;
        KeReleaseSpinLock(&g_TableLock, irql);
        return STATUS_SUCCESS;
    }
    case HPX_CTRL_SET_LAN: {
        /* buf = HPX_SET_LAN(整表替换);count×{net,mask} 均为大端序值 */
        const HPX_SET_LAN* sl = (const HPX_SET_LAN*)buf;
        KIRQL irql;
        ULONG i, n;
        if (inLen < 4 * sizeof(ULONG)) return STATUS_INVALID_PARAMETER;
        n = sl->count;
        if (n > HPX_MAX_LAN) n = HPX_MAX_LAN;
        if (inLen < (4 + 2 * n) * sizeof(ULONG)) return STATUS_INVALID_PARAMETER;
        KeAcquireSpinLock(&g_TableLock, &irql);
        for (i = 0; i < n; i++) {
            g_LanNets[i]  = sl->e[i].net;
            g_LanMasks[i] = sl->e[i].mask;
        }
        g_LanCount = n;
        KeReleaseSpinLock(&g_TableLock, irql);
        return STATUS_SUCCESS;
    }
    case HPX_CTRL_RELAY_UP:
        HpxRelayUp((ULONG)(ULONG_PTR)PsGetCurrentProcessId());
        return STATUS_SUCCESS;
    case HPX_CTRL_RELAY_DOWN:
        HpxRelayDown((ULONG)(ULONG_PTR)PsGetCurrentProcessId());
        return STATUS_SUCCESS;
    case HPX_CTRL_UDP_DIAG: {
        ULONG* out = (ULONG*)buf;
        if (outLen < 9 * sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
        out[0] = 0x3A3A3A4C;
        out[1] = (ULONG)g_CntDgHit;
        out[2] = (ULONG)g_CntDgramRw;
        out[3] = (ULONG)g_CntInjFail;
        out[4] = (ULONG)g_CntDatagram;
        out[5] = (ULONG)g_CntBackRw;
        out[6] = (ULONG)g_CntExempt;
        out[7] = (ULONG)g_CntDgPermit;
        out[8] = (ULONG)g_InjLastStatus;
        *info = 9 * sizeof(ULONG);
        return STATUS_SUCCESS;
    }
    case HPX_CTRL_DIAG: {
        ULONG* out = (ULONG*)buf;
        if (outLen < 8 * sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
        out[0] = 0x3A3A3A4A;
        out[1] = (ULONG)g_FilterIdR4;
        out[2] = (ULONG)g_FilterIdD4;
        out[3] = g_CalloutIdR4;
        out[4] = g_EngineHandle ? 1 : 0;
        out[5] = (ULONG)g_WfpStatus;
        out[6] = g_WfpBound ? 1 : 0;
        out[7] = g_WfpStep | (g_DeviceObj ? 0x100 : 0);
        *info = 8 * sizeof(ULONG);
        return STATUS_SUCCESS;
    }
    case HPX_CTRL_CLS_DIAG: {
        ULONG* out = (ULONG*)buf;
        if (outLen < 19 * sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
        out[0]  = 0x3A3A3A4B;
        out[1]  = (ULONG)g_CntClassify;
        out[2]  = (ULONG)g_CntPidHit;
        out[3]  = (ULONG)g_CntRewrite;
        out[4]  = (ULONG)g_CntPrev;
        out[5]  = (ULONG)g_CntAllocFail;
        out[6]  = (ULONG)g_CntClaim;
        out[7]  = (ULONG)g_CntInjOk;
        out[8]  = (ULONG)g_SnapPort;
        out[9]  = (ULONG)g_SnapIp;
        out[10] = (ULONG)g_CntDgHit;
        out[11] = (ULONG)g_CntDgramRw;
        out[12] = (ULONG)g_CntV6Block;
        out[13] = (ULONG)g_ImgCount;
        out[14] = (ULONG)g_CntImgHit;
        out[15] = (ULONG)(g_TotalUp / 1024);
        out[16] = (ULONG)(g_TotalDown / 1024);
        out[17] = (ULONG)g_InjFailTag;
        out[18] = (ULONG)g_CntQuicBlock;
        *info = 19 * sizeof(ULONG);
        return STATUS_SUCCESS;
    }
    case HPX_CTRL_WFP_STATUS:
        if (outLen < sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
        *(ULONG*)buf = (ULONG)g_WfpStatus;
        *info = sizeof(ULONG);
        return STATUS_SUCCESS;
    case HPX_CTRL_AUDIT: {
        ULONG* out = (ULONG*)buf;
        if (outLen < 8 * sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
        out[0] = 0x3A3A3A43;
        out[1] = (ULONG)g_CntIoctl;
        out[2] = (ULONG)g_CntDenied;
        out[3] = (ULONG)g_CntClaim;
        out[4] = (ULONG)g_CntEvent;
        out[5] = (ULONG)g_RelayPid;
        out[6] = g_Enabled ? 1 : 0;
        out[7] = (ULONG)g_CntInjOk;
        *info = 8 * sizeof(ULONG);
        return STATUS_SUCCESS;
    }
    case HPX_CTRL_UDP_INJECT:
    case HPX_CTRL_UDP_INJECT_SEND: {
        HPX_UDP_INJECT_HDR hdr;
        const UCHAR* payload;
        ULONG plen;
        UINT32 ifIndex, compId;
        KIRQL irql;
        if (inLen < sizeof(HPX_UDP_INJECT_HDR)) return STATUS_BUFFER_TOO_SMALL;
        RtlCopyMemory(&hdr, buf, sizeof(hdr));
        if (hdr.cmd != cmd) return STATUS_INVALID_PARAMETER;
        plen = inLen - sizeof(HPX_UDP_INJECT_HDR);
        if (hdr.payloadLen != plen) return STATUS_INVALID_PARAMETER;
        payload = (const UCHAR*)buf + sizeof(HPX_UDP_INJECT_HDR);
        /* 娉ㄥ叆鍙傛暟浼樺厛鍙栨祦璁板綍(D4 棣栧寘鍥炲～鐨勬帴鍙?闅旂);璋冪敤鏂?pad 瑕嗙洊 */
        ifIndex = hdr.pad1;
        compId = hdr.pad0;
        KeAcquireSpinLock(&g_TableLock, &irql);
        {
            PLIST_ENTRY e;
            USHORT wantPort = HpxSwap16((USHORT)hdr.dstPortNet);
            for (e = g_FlowList.Flink; e != &g_FlowList; e = e->Flink) {
                HPX_FLOW* f = CONTAINING_RECORD(e, HPX_FLOW, link);
                if (f->protocol == 17 && f->localPort == wantPort && f->localIpV4 == hdr.dstIp) {
                    if (ifIndex == 0) ifIndex = f->ifIndex;
                    if (compId == 0) compId = f->compartmentId;
                    break;
                }
            }
        }
        KeReleaseSpinLock(&g_TableLock, irql);
        return HpxInjectUdpPacket(hdr.srcIp, hdr.srcPortNet, hdr.dstIp, hdr.dstPortNet,
                                  payload, plen, ifIndex, compId,
                                  cmd == HPX_CTRL_UDP_INJECT_SEND, 2);
    }
    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static NTSTATUS IoctlClaim(PVOID buf, ULONG inLen, ULONG outLen, ULONG_PTR* info)
{
    HPX_REQRESP* req = (HPX_REQRESP*)buf;
    HPX_FLOW* hit = NULL;
    KIRQL irql;

    if (inLen < sizeof(HPX_REQRESP) || outLen < sizeof(HPX_REQRESP))
        return STATUS_BUFFER_TOO_SMALL;

    switch (req->hdr) {
    case HPX_REQ_BY_ID:
        KeAcquireSpinLock(&g_TableLock, &irql);
        {
            PLIST_ENTRY e;
            for (e = g_FlowList.Flink; e != &g_FlowList; e = e->Flink) {
                HPX_FLOW* f = CONTAINING_RECORD(e, HPX_FLOW, link);
                if (f->flowId == req->flowId) { hit = f; break; }
            }
        }
        if (hit == NULL) { KeReleaseSpinLock(&g_TableLock, irql); return STATUS_NOT_FOUND; }
        goto fill;

    case HPX_REQ_FIFO:
        if (!HpxRateAllowClaim()) { InterlockedIncrement(&g_CntDenied); return STATUS_QUOTA_EXCEEDED; }
        InterlockedIncrement(&g_CntClaim);
        KeAcquireSpinLock(&g_TableLock, &irql);
        {
            PLIST_ENTRY e;
            for (e = g_FlowList.Flink; e != &g_FlowList; e = e->Flink) {
                HPX_FLOW* f = CONTAINING_RECORD(e, HPX_FLOW, link);
                if (!f->claimed && f->protocol == 6) { hit = f; break; }
            }
        }
        if (hit == NULL) { KeReleaseSpinLock(&g_TableLock, irql); return STATUS_NOT_FOUND; }
        hit->claimed = TRUE;
        goto fill;

    case HPX_REQ_BY_ENDPOINT: {
        /* 鍏ュ弬:flowId = 鏈湴绔彛(缃戠粶搴?,arg = 鏈湴 IPv4(缃戠粶搴?鍐呭瓨搴?;
         * 鍏堢簿纭?鍗忚+绔偣),鍐嶇洸(localPort==0)鍙栨渶鏂?鏈€鍚庡彇鏈€鏂版湭璁ら鍚屽崗璁?*/
        USHORT wantPort = HpxSwap16((USHORT)req->flowId);
        ULONG wantIp = req->arg;
        UCHAR wantProto = (UCHAR)req->u.dst.protocol;
        HPX_FLOW* relaxed = NULL;
        HPX_FLOW* claimedHit = NULL;
        if (!HpxRateAllowClaim()) { InterlockedIncrement(&g_CntDenied); return STATUS_QUOTA_EXCEEDED; }
        InterlockedIncrement(&g_CntClaim);
        KeAcquireSpinLock(&g_TableLock, &irql);
        {
            PLIST_ENTRY e;
            for (e = g_FlowList.Blink; e != &g_FlowList; e = e->Blink) {
                HPX_FLOW* f = CONTAINING_RECORD(e, HPX_FLOW, link);
                if (wantProto && f->protocol != wantProto) continue;
                /* 精确:本地口 + (本地 IP 或 目标 IP[本地化后应用以目标 IP 为源] 或通配) */
                if (f->localPort == wantPort &&
                    (wantIp == 0 || f->localIpV4 == 0 || f->localIpV4 == wantIp ||
                     f->remoteIpV4 == wantIp)) {
                    if (!f->claimed) { hit = f; break; }
                    if (claimedHit == NULL) claimedHit = f;   /* 幂等复认:多包流逐包认领 */
                    continue;
                }
                if (relaxed == NULL && f->localPort == 0 &&
                    (wantIp == 0 || f->localIpV4 == 0 || f->localIpV4 == wantIp))
                    relaxed = f;
            }
        }
        if (hit == NULL) hit = claimedHit;
        if (hit == NULL) hit = relaxed;
        if (hit == NULL) {
            /* 鏈€鍚庡厹搴?鏈€鏂版湭璁ら鎸囧畾鍗忚璁板綍 */
            PLIST_ENTRY e;
            for (e = g_FlowList.Blink; e != &g_FlowList; e = e->Blink) {
                HPX_FLOW* f = CONTAINING_RECORD(e, HPX_FLOW, link);
                if (!f->claimed && (!wantProto || f->protocol == wantProto)) { hit = f; break; }
            }
        }
        if (hit == NULL) { KeReleaseSpinLock(&g_TableLock, irql); return STATUS_NOT_FOUND; }
        hit->claimed = TRUE;
        goto fill;
    }

    default:
        return STATUS_NOT_FOUND;
    }

fill:
    {
        ULONG flowId = hit->flowId;
        ULONG rip = hit->remoteIpV4, lip = hit->localIpV4;
        USHORT rp = hit->remotePort, lp = hit->localPort;
        ULONG pid = hit->pid;
        UCHAR proto = hit->protocol;
        KeReleaseSpinLock(&g_TableLock, irql);
        RtlZeroMemory(&req->u, sizeof(req->u));
        req->flowId = flowId;
        req->u.dst.remoteIpV4 = rip;     /* sin_addr 鍐呭瓨搴?*/
        req->u.dst.remotePort = rp;      /* 涓绘満搴?*/
        req->u.dst.localIpV4  = lip;
        req->u.dst.localPort  = lp;
        req->u.dst.pid        = pid;
        req->u.dst.protocol   = proto;
        *info = sizeof(HPX_REQRESP);
        return STATUS_SUCCESS;
    }
}

static NTSTATUS IoctlPollEvents(PVOID buf, ULONG inLen, ULONG outLen, ULONG_PTR* info)
{
    ULONG lastCursor, written = 0;
    KIRQL irql;
    if (inLen < sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
    if (outLen < sizeof(HPX_EVENT)) return STATUS_BUFFER_TOO_SMALL;
    lastCursor = *(ULONG*)buf;

    KeAcquireSpinLock(&g_EventLock, &irql);
    {
        ULONG idx = g_EventTail;
        while (idx != g_EventHead) {
            HPX_EVENT* e = &g_EventRing[idx];
            if (e->cursor > lastCursor) {
                if (written + sizeof(HPX_EVENT) > outLen) break;
                RtlCopyMemory((UCHAR*)buf + written, e, sizeof(HPX_EVENT));
                written += sizeof(HPX_EVENT);
            }
            idx = (idx + 1) % HPX_EVENT_RING;
        }
    }
    KeReleaseSpinLock(&g_EventLock, irql);
    *info = written;
    return STATUS_SUCCESS;
}

static NTSTATUS IoctlSetFlowLimit(PVOID buf, ULONG inLen, ULONG outLen, ULONG_PTR* info)
{
    HPX_FLOW_LIMIT* lim = (HPX_FLOW_LIMIT*)buf;
    ULONG applied = 0;
    KIRQL irql;
    if (inLen < sizeof(HPX_FLOW_LIMIT)) return STATUS_BUFFER_TOO_SMALL;
    if (outLen < sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
    KeAcquireSpinLock(&g_TableLock, &irql);
    {
        PLIST_ENTRY e;
        for (e = g_ProcList.Flink; e != &g_ProcList; e = e->Flink) {
            HPX_PROC* rec = CONTAINING_RECORD(e, HPX_PROC, link);
            if (rec->enabled) {
                rec->limitUp = lim->limitUp;
                rec->limitDown = lim->limitDown;
                applied++;
            }
        }
    }
    KeReleaseSpinLock(&g_TableLock, irql);
    *(ULONG*)buf = applied ? 1 : 0;
    *info = sizeof(ULONG);
    return STATUS_SUCCESS;
}

static NTSTATUS IoctlReport(PVOID buf, ULONG inLen, ULONG_PTR* info)
{
    HPX_REPORT rep;
    KIRQL irql;
    if (inLen < sizeof(HPX_REPORT)) return STATUS_BUFFER_TOO_SMALL;
    RtlCopyMemory(&rep, buf, sizeof(rep));

    KeAcquireSpinLock(&g_TableLock, &irql);
    {
        HPX_PROC* rec = HpxFindProcByIdLocked(rep.id);
        if (rec == NULL) rec = HpxFindProcByPidLocked(rep.id);   /* 鍏煎鎸?PID 鐩存姤 */
        if (rec) {
            if (rep.upDelta == 0 && rep.downDelta == 0) {
                HpxEventPush(EV_FLOW_CLOSED, rec->id, rec->pid, 0, 0);
            } else {
                rec->bytesUp += rep.upDelta;
                rec->bytesDown += rep.downDelta;
                if ((rec->limitUp && rec->bytesUp >= rec->limitUp) ||
                    (rec->limitDown && rec->bytesDown >= rec->limitDown)) {
                    if (!rec->limitReached) {
                        rec->limitReached = TRUE;
                        rec->enabled = FALSE;
                        HpxEventPush(EV_LIMIT_REACHED, rec->id, rec->pid, 0, 0);
                    }
                }
            }
        }
    }
    KeReleaseSpinLock(&g_TableLock, irql);
    if (rep.upDelta) InterlockedExchangeAdd(&g_TotalUp, (LONG)rep.upDelta);
    if (rep.downDelta) InterlockedExchangeAdd(&g_TotalDown, (LONG)rep.downDelta);
    *info = 0;
    return STATUS_SUCCESS;
}

static NTSTATUS IoctlQueryFlow(PVOID buf, ULONG inLen, ULONG outLen, ULONG_PTR* info)
{
    ULONG id;
    HPX_FLOW_STAT* st = (HPX_FLOW_STAT*)buf;
    KIRQL irql;
    HPX_PROC* rec;
    UINT64 up = 0, down = 0;
    BOOLEAN ok = FALSE;
    if (inLen < sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
    if (outLen < sizeof(HPX_FLOW_STAT)) return STATUS_BUFFER_TOO_SMALL;
    id = *(ULONG*)buf;
    KeAcquireSpinLock(&g_TableLock, &irql);
    rec = HpxFindProcByIdLocked(id);
    if (rec == NULL) rec = HpxFindProcByPidLocked(id);
    if (rec) { up = rec->bytesUp; down = rec->bytesDown; ok = TRUE; }
    KeReleaseSpinLock(&g_TableLock, irql);
    if (!ok) return STATUS_NOT_FOUND;
    st->up = up;
    st->down = down;
    *info = sizeof(HPX_FLOW_STAT);
    return STATUS_SUCCESS;
}

/* ================= IRP 澶勭悊 ================= */
static NTSTATUS HpxCreateClose(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    UNREFERENCED_PARAMETER(dev);
    if (sp->MajorFunction == IRP_MJ_CLOSE) {
        /* 设备关闭:按 PID 注销存活中继;仅当全部中继退出才允许直连 */
        HpxRelayDown((ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    }
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS HpxDeviceControl(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf = irp->AssociatedIrp.SystemBuffer;

    UNREFERENCED_PARAMETER(dev);
    InterlockedIncrement(&g_CntIoctl);

    switch (code) {
    case IOCTL_HPX_HANDSHAKE:   status = IoctlHandshake(buf, inLen, outLen, &info); break;
    case IOCTL_HPX_CONTROL:     status = IoctlControl(buf, inLen, outLen, &info); break;
    case IOCTL_HPX_CLAIM_DEST:  status = IoctlClaim(buf, inLen, outLen, &info); break;
    case IOCTL_HPX_POLL_EVENTS: status = IoctlPollEvents(buf, inLen, outLen, &info); break;
    case IOCTL_HPX_FLOW_LIMIT:  status = IoctlSetFlowLimit(buf, inLen, outLen, &info); break;
    case IOCTL_HPX_TCP_REPORT:
    case IOCTL_HPX_UDP_REPORT:  status = IoctlReport(buf, inLen, &info); break;
    case IOCTL_HPX_QUERY_FLOW:  status = IoctlQueryFlow(buf, inLen, outLen, &info); break;
    default: break;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = NT_SUCCESS(status) ? info : 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

/* ================= 鍗歌浇 ================= */
static void NTAPI HpxProcessNotify(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo);

static void HpxUnload(PDRIVER_OBJECT drv)
{
    UNICODE_STRING dosName;
    KIRQL irql;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
    g_Enabled = FALSE;
    InterlockedExchange(&g_Unloading, 1);
    PsSetCreateProcessNotifyRoutineEx(HpxProcessNotify, TRUE);   /* 注销进程通知 */

    /* 1) Wait for already-queued/running GC/WFP work items; new work is gated above. */
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -(10 * 10000LL);            /* 10ms */
        while (g_WfpWorkQueued || g_GcQueued)
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    /* 2) WFP 鏀跺熬(鍙嶆敞鍐屽墠缃?鈫?娉ㄥ叆璁炬柦 鈫?浜嬪姟鎵瑰垹 鈫?鍏冲紩鎿? */
    WfpShutdown();

    /* 3) 璁板綍琛ㄩ噴鏀?*/
    KeAcquireSpinLock(&g_TableLock, &irql);
    while (!IsListEmpty(&g_FlowList)) {
        PLIST_ENTRY e = RemoveHeadList(&g_FlowList);
        HPX_FLOW* f = CONTAINING_RECORD(e, HPX_FLOW, link);
        ExFreeToNPagedLookasideList(&g_FlowLookaside, f);
    }
    while (!IsListEmpty(&g_ProcList)) {
        PLIST_ENTRY e = RemoveHeadList(&g_ProcList);
        HPX_PROC* r = CONTAINING_RECORD(e, HPX_PROC, link);
        ExFreeToNPagedLookasideList(&g_ProcLookaside, r);
    }
    KeReleaseSpinLock(&g_TableLock, irql);
    ExDeleteNPagedLookasideList(&g_FlowLookaside);
    ExDeleteNPagedLookasideList(&g_ProcLookaside);

    /* 4) 绗﹀彿閾炬帴 + 璁惧(蹇呴』鐢ㄦ弿杩扮,涓嶈兘鎶?WCHAR[] 褰?UNICODE_STRING) */
    RtlInitUnicodeString(&dosName, HPX_DOS_LINK_NAME_W);
    IoDeleteSymbolicLink(&dosName);
    if (g_DeviceObj) { IoDeleteDevice(g_DeviceObj); g_DeviceObj = NULL; }
    UNREFERENCED_PARAMETER(drv);
}

/* ================= 鍏ュ彛 ================= */
static NTSTATUS HpxCreateDeviceSecure(PDRIVER_OBJECT drv)
{
    UNICODE_STRING devName, dosName;
    NTSTATUS st;
    RtlInitUnicodeString(&devName, HPX_DEVICE_NAME_W);
    st = IoCreateDevice(drv, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObj);
    if (!NT_SUCCESS(st)) {
        DbgPrint("HPX: IoCreateDevice(%wZ) st=0x%08x\n", &devName, st);
        return st;
    }
    RtlInitUnicodeString(&dosName, HPX_DOS_LINK_NAME_W);
    IoDeleteSymbolicLink(&dosName);          /* 娓呮畫鐣?宕╂簝/寮傚父鍗歌浇鍚庨仐鐥?,骞傜瓑 */
    st = IoCreateSymbolicLink(&dosName, &devName);
    if (!NT_SUCCESS(st)) {
        DbgPrint("HPX: IoCreateSymbolicLink(%wZ) st=0x%08x\n", &dosName, st);
        IoDeleteDevice(g_DeviceObj);
        g_DeviceObj = NULL;
        return st;
    }
    return STATUS_SUCCESS;
}

/* 璇绘湇鍔?Parameters\Layers(DWORD):闄愬埗缁戝畾鐨?WFP 灞?1=ALE 2=鏁版嵁鎶?缂虹渷 3) */
static void HpxReadConfig(PUNICODE_STRING regPath)
{
    UNICODE_STRING keyPath, valueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE key = NULL;
    NTSTATUS st;
    struct { ULONG title, type, len; ULONG data; } kv;
    ULONG need = 0;
    if (regPath == NULL || regPath->Buffer == NULL) return;
    {
        USHORT n = regPath->Length + (USHORT)(sizeof(L"\\Parameters") - sizeof(WCHAR));
        PWCH buf = (PWCH)ExAllocatePoolWithTag(NonPagedPoolNx, n + sizeof(WCHAR), HPX_POOL_TAG);
        if (!buf) return;
        RtlCopyMemory(buf, regPath->Buffer, regPath->Length);
        RtlCopyMemory((PUCHAR)buf + regPath->Length, L"\\Parameters", sizeof(L"\\Parameters"));
        RtlInitUnicodeString(&keyPath, buf);
        InitializeObjectAttributes(&oa, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        st = ZwOpenKey(&key, KEY_READ, &oa);
        ExFreePoolWithTag(buf, HPX_POOL_TAG);
    }
    if (!NT_SUCCESS(st)) return;
    RtlInitUnicodeString(&valueName, L"Layers");
    st = ZwQueryValueKey(key, &valueName, KeyValuePartialInformation, &kv, sizeof(kv), &need);
    if (NT_SUCCESS(st) && kv.len == sizeof(ULONG) && kv.data != 0) g_WfpLayers = kv.data;
    RtlInitUnicodeString(&valueName, L"WfpMode");
    st = ZwQueryValueKey(key, &valueName, KeyValuePartialInformation, &kv, sizeof(kv), &need);
    if (NT_SUCCESS(st) && kv.len == sizeof(ULONG)) g_WfpMode = kv.data;
    ZwClose(key);
}

/* 进程创建/退出通知:映像名命中规则的进程在诞生瞬间(首条指令之前)即登记入册,
 * 彻底消除"进程创建 → 扫描登记"竞态——新进程的第一个数据包即被信任闸识别,
 * 任何数据包不可能先于拦截发出(用户硬性要求:底层第一时间接管) */
static BOOLEAN HpxImgRuleHitUnicode(const UNICODE_STRING* path)
{
    const WCHAR* p;
    ULONG nchars, i, start = 0, ci;
    BOOLEAN hit = FALSE;
    KIRQL irql;

    if (path == NULL || path->Buffer == NULL || path->Length < sizeof(WCHAR)) return FALSE;
    p = path->Buffer;
    nchars = path->Length / sizeof(WCHAR);
    for (i = 0; i < nchars; i++)
        if (p[i] == L'\\' || p[i] == L'/') start = i + 1;
    if (start >= nchars) return FALSE;

    KeAcquireSpinLock(&g_TableLock, &irql);
    for (ci = 0; ci < g_ImgCount && !hit; ci++) {
        ULONG rl = 0, j;
        while (rl < 63 && g_ImgRules[ci][rl]) rl++;
        if (rl == 0 || nchars - start < rl) continue;
        hit = TRUE;
        for (j = 0; j < rl; j++) {
            WCHAR a = p[start + j], b = g_ImgRules[ci][j];
            if (a >= L'A' && a <= L'Z') a += 32;
            if (b >= L'A' && b <= L'Z') b += 32;
            if (a != b) { hit = FALSE; break; }
        }
        if (hit && nchars - start > rl) {
            WCHAR c = p[start + rl];
            if (c != 0 && c != L'.' && c != L' ' && c != L':') hit = FALSE;
        }
    }
    KeReleaseSpinLock(&g_TableLock, irql);
    return hit;
}

static void NTAPI HpxProcessNotify(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo)
{
    KIRQL irql;
    HPX_PROC* rec;

    UNREFERENCED_PARAMETER(process);
    if (createInfo != NULL) {
        if (!HpxImgRuleHitUnicode(createInfo->ImageFileName)) return;
        KeAcquireSpinLock(&g_TableLock, &irql);
        rec = HpxFindProcByPidLocked((ULONG)(ULONG_PTR)pid);
        if (rec == NULL) {
            rec = (HPX_PROC*)ExAllocateFromNPagedLookasideList(&g_ProcLookaside);
            if (rec) {
                RtlZeroMemory(rec, sizeof(*rec));
                rec->pid = (ULONG)(ULONG_PTR)pid;
                rec->enabled = TRUE;
                InsertTailList(&g_ProcList, &rec->link);
            }
        } else {
            rec->enabled = TRUE;
            rec->limitReached = FALSE;
        }
        KeReleaseSpinLock(&g_TableLock, irql);
    } else {
        /* 进程退出:即时注销(防 PID 复用误绑) */
        KeAcquireSpinLock(&g_TableLock, &irql);
        rec = HpxFindProcByPidLocked((ULONG)(ULONG_PTR)pid);
        if (rec && rec->id == 0) {          /* 仅回收驱动侧自登记项;引擎登记的交给引擎 */
            RemoveEntryList(&rec->link);
            ExFreeToNPagedLookasideList(&g_ProcLookaside, rec);
        }
        KeReleaseSpinLock(&g_TableLock, irql);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING regPath)
{
    NTSTATUS st;
    LONGLONG inc;
    BOOLEAN notifyRegistered;

    HpxReadConfig(regPath);

    KeInitializeSpinLock(&g_TableLock);
    KeInitializeSpinLock(&g_EventLock);
    InitializeListHead(&g_ProcList);
    InitializeListHead(&g_FlowList);
    ExInitializeNPagedLookasideList(&g_ProcLookaside, NULL, NULL, 0, sizeof(HPX_PROC), HPX_POOL_TAG, 0);
    ExInitializeNPagedLookasideList(&g_FlowLookaside, NULL, NULL, 0, sizeof(HPX_FLOW), HPX_POOL_TAG, 0);

    /* GC TTL:90s(宸茶棰?/ 300s(鏈棰? */
    inc = KeQueryTimeIncrement();
    if (inc > 0) {
        g_TickGcClaimed   = (90LL  * 10000000LL) / inc;
        g_TickGcUnclaimed = (300LL * 10000000LL) / inc;
    } else {
        g_TickGcClaimed = 6000;
        g_TickGcUnclaimed = 20000;
    }

    st = PsSetCreateProcessNotifyRoutineEx(HpxProcessNotify, FALSE);
    notifyRegistered = NT_SUCCESS(st);
    if (!notifyRegistered) {
        /* 部分测试签名环境拒绝该可选通知;引擎会显式推送映像规则,不阻止驱动加载。 */
        DbgPrint("HPX: process notify unavailable st=0x%08x\n", st);
    }
    st = HpxCreateDeviceSecure(drv);
    if (!NT_SUCCESS(st)) {
        if (notifyRegistered) PsSetCreateProcessNotifyRoutineEx(HpxProcessNotify, TRUE);
        ExDeleteNPagedLookasideList(&g_FlowLookaside);
        ExDeleteNPagedLookasideList(&g_ProcLookaside);
        return st;
    }

    drv->MajorFunction[IRP_MJ_CREATE]         = HpxCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE]          = HpxCreateClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HpxDeviceControl;
    drv->DriverUnload                          = HpxUnload;

    /* Fwps 杩愯鏃舵敞鍐?鍐呮牳鏈湴,鍙繘 DriverEntry);澶辫触涓嶈嚧瑁呰浇澶辫触鈥斺€?     * 璁板綍鐘舵€佸苟缁х画,鐢遍娆℃彙鎵嬭Е鍙戠殑 WfpStartup 鑷剤閲嶈瘯(瀹炶瘉濂戠害:WDAC/寮曟搸
     * 鏈氨缁椂娉ㄥ唽浼氬け璐?浣嗛┍鍔ㄦ湰浣撳繀椤诲彲瑁呰浇,鍚﹀垯璇婃柇鍙ｄ笉鍙敤) */
    st = WfpRegisterCallouts();
    if (!NT_SUCCESS(st)) {
        g_WfpStatus = st;
        g_WfpStep = 40;
        DbgPrint("HPX: DriverEntry callout register failed st=0x%08x (deferred retry)\n", st);
    }

    return STATUS_SUCCESS;
}
