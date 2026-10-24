/*
 * hpx_proto.h 鈥?HookProxy 鍔熻兘閲嶅疄鐜?椹卞姩涓庣敤鎴锋€佸叡浜崗璁?鍞竴瀹氫箟鐐?
 *
 * 鏈」鐩洰鏍?鍦ㄧ嫭绔嬪伐绋嬩腑瀹炵幇鍘熷巶 HookProxy.dll 鐨勯€忔槑浠ｇ悊鍔熻兘
 * (鎸?PID 閫忔槑浠ｇ悊鎸囧畾杩涚▼鐨?TCP/UDP 鍒?SOCKS5 涓婃父,鍚璐广€佽繃婊ゃ€佹湇鍔＄鐞?銆? *
 * 鍗忚褰㈢姸鍙栬嚜鍘熷巶閫嗗悜瀹炶瘉(璁惧鍚嶃€両OCTL 鐮佹棌銆佺紦鍐插尯褰㈢姸):
 *   - 璁惧鍚?\\.\QQ1289671197(鍘熷巶瀹炶瘉)
 *   - IOCTL 鏃?CTL_CODE(0x22, 101..110, METHOD_BUFFERED, FILE_ANY_ACCESS)
 *   - 鎻℃墜 0x9C(棣?DWORD 鑷姤闀垮害)銆佷簨浠舵车 0x400銆佹祦閲忛檺棰?16B銆? *     瀛楄妭鍥炴姤 12B {a,b,id}(鍘熷巶鍖呰鍑芥暟瀹炶瘉:id 鍦?+8)銆佹祦閲忔煡璇?{id}->{u64,u64}
 * 0x2201A0 鎺у埗鍛戒护鐨勬暟鍊肩爜鍘熷巶鏈鏄庣爜(VM 淇濇姢),鏈」鐩嚜瀹氫箟骞跺浐鍖栦簬姝ゃ€? *
 * 瀛楄妭搴忓绾?鍏ㄩ摼鏄撻敊鐐?鍐欐澶囨煡):
 *   - 璁板綍/缁撴瀯閲岀殑 IPv4 = sin_addr 鍐呭瓨搴?= 缃戠粶搴忔暟鍊?鍙洿鎺ヨ祴缁?s_addr);
 *   - 璁板綍閲岀殑绔彛 = 涓绘満搴?姣旇緝鐢?(p[0]<<8)|p[1] 涓绘満搴?鍙戝寘鏃?htons);
 *   - WFP 鍒嗙被鍥炶皟閲?value.uint32 鐨?IP 涓虹綉缁滃簭鏁板€笺€? */
#ifndef HPX_PROTO_H
#define HPX_PROTO_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

/* ---------------- 璁惧鍚?鍘熷巶瀹炶瘉) ---------------- */
#define HPX_DEVICE_NAME        "\\Device\\QQ1289671197"
#define HPX_DEVICE_NAME_W      L"\\Device\\QQ1289671197"
#define HPX_DOS_NAME           "QQ1289671197"
#define HPX_DOS_NAME_W         L"QQ1289671197"
#define HPX_DOS_LINK_NAME      "\\??\\QQ1289671197"
#define HPX_DOS_LINK_NAME_W    L"\\??\\QQ1289671197"
#define HPX_DOS_PATH           "\\\\.\\QQ1289671197"
#define HPX_DOS_PATH_W         L"\\\\.\\QQ1289671197"

/* 椹卞姩鏈嶅姟鍚?鏂囦欢鍚?鏈」鐩嚜鏈?閬垮厤涓庢棦鏈夋湇鍔″啿绐? */
#define HPX_SERVICE_NAME       "HpxDrv64"
#define HPX_SERVICE_NAME_W     L"HpxDrv64"
#define HPX_DRIVER_FILE        "HpxDrv64.sys"

#define HPX_CTL(fn)  CTL_CODE(0x22, (fn), METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HPX_CLAIM_DEST   HPX_CTL(101)  /* 0x220194 璁ら鍘熷鐩殑 */
#define IOCTL_HPX_POLL_EVENTS  HPX_CTL(102)  /* 0x220198 浜嬩欢娉?*/
#define IOCTL_HPX_HANDSHAKE    HPX_CTL(103)  /* 0x22019C 鎻℃墜 */
#define IOCTL_HPX_CONTROL      HPX_CTL(104)  /* 0x2201A0 鎺у埗鍛戒护 */
#define IOCTL_HPX_FLOW_LIMIT   HPX_CTL(105)  /* 0x2201A4 娴侀噺闄愰 */
#define IOCTL_HPX_TCP_REPORT   HPX_CTL(107)  /* 0x2201AC TCP 瀛楄妭鍥炴姤 */
#define IOCTL_HPX_UDP_REPORT   HPX_CTL(108)  /* 0x2201B0 UDP 瀛楄妭鍥炴姤 */
#define IOCTL_HPX_QUERY_FLOW   HPX_CTL(110)  /* 0x2201B8 娴侀噺鏌ヨ */

/* ---------------- 缂撳啿灏哄 ---------------- */
#define HPX_HANDSHAKE_SIZE     0x9C
#define HPX_EVENT_BUFFER_SIZE  0x400
#define HPX_REQRESP_SIZE       0x2C
#define HPX_REQRESP_DATA_LEN   0x1C

#pragma pack(push, 1)

/* ---------------- 鎻℃墜(0x22019C) ---------------- */
typedef struct _HPX_HANDSHAKE {
    ULONG  cbSize;                 /* 鍏ュ弬棣栧瓧娈?= sizeof(HPX_HANDSHAKE) = 0x9C */
    ULONG  driverVersion;          /* 鍏ュ弬:鐢ㄦ埛鎬佹湡鏈涚殑椹卞姩鐗堟湰 */
    ULONG  apiVersion;             /* 鍏ュ弬:鍗忚鐗堟湰 = HPX_API_VERSION */
    ULONG  flags;                  /* 鍏ュ弬:琛屼负寮€鍏?*/
    ULONG  relayPort;              /* 鍑哄弬:褰撳墠 TCP 涓户绔彛(椹卞姩渚ц褰? */
    ULONG  relayUdpPort;           /* 鍑哄弬:褰撳墠 UDP 涓户绔彛 */
    UCHAR  reserved[HPX_HANDSHAKE_SIZE - 24];
} HPX_HANDSHAKE;

#define HPX_API_VERSION        2018
#define HPX_DRIVER_VERSION     2018

/* ---------------- 鎺у埗鍛戒护(0x2201A0,8 瀛楄妭 {cmd,param}) ----------------
 * 鏁板€肩爜涓烘湰椤圭洰鑷畾涔?鍘熷巶鏈槑鐮佸疄璇?;涓€缁忓浐鍖栦笉鍐嶅彉鏇淬€? */
#define HPX_CTRL_ADD_PID        1   /* param=PID:鐧昏鍒颁唬鐞嗛泦(淇′换闂? */
#define HPX_CTRL_REMOVE_PID     2   /* param=PID:绉诲嚭浠ｇ悊闆?StopProxy) */
#define HPX_CTRL_SET_TCP_PORT   3   /* param=TCP 涓户绔彛(涓绘満搴? */
#define HPX_CTRL_SET_UDP_PORT   4   /* param=UDP 涓户绔彛(涓绘満搴? */
#define HPX_CTRL_ENABLE         5   /* param=0/1:鏁版嵁闈㈡€诲紑鍏?*/
#define HPX_CTRL_RESET          6   /* param=0:娓呯┖鍏ㄩ儴璁板綍(淇濈暀 PID 闆? */
#define HPX_CTRL_ADD_IP         7   /* param=IPv4(缃戠粶搴?:杩囨护鐧藉悕鍗?IP */
#define HPX_CTRL_DEL_IP         8   /* param=IPv4 */
#define HPX_CTRL_ADD_PORT       9   /* param=绔彛(涓绘満搴?:杩囨护鐧藉悕鍗曠鍙?*/
#define HPX_CTRL_DEL_PORT       10
#define HPX_CTRL_ADD_IMG        11  /* buf=struct{cmd,pad,WCHAR name[64]}:映像名规则(驱动侧 APP_ID 尾匹配,消进程登记竞态) */
#define HPX_CTRL_SET_GLOBAL     12  /* param=0/1:全局模式——代理所有进程(排除中继自身;私网 LAN 例外直连) */  /* param=绔彛 */
#define HPX_CTRL_CLEAR_LAN      13  /* param=0:清空局域网网段表 */
#define HPX_CTRL_SET_LAN        14  /* buf=HPX_SET_LAN:局域网网段表(精确判定,访问局域网一律不代理) */
#define HPX_CTRL_RELAY_UP       15  /* param=PID:中继监听已就绪,登记为可承接重定向的存活中继 */
#define HPX_CTRL_RELAY_DOWN     16  /* param=PID:中继停止监听,注销;仅当存活表为空才放行直连 */
#define HPX_CTRL_UDP_DIAG       96  /* param=0:UDP 鏁版嵁闈㈣鏁?鍑哄弬 32B) */
#define HPX_CTRL_DIAG           97  /* param=0:WFP 娉ㄥ唽鐜板満(鍑哄弬 32B) */
#define HPX_CTRL_CLS_DIAG       98  /* param=0:鍒嗙被/鏂偣璁℃暟(鍑哄弬 80B) */
#define HPX_CTRL_WFP_STATUS     99  /* param=0:WFP 缁戝畾 NTSTATUS(鍑哄弬 4B) */
#define HPX_CTRL_AUDIT          100 /* param=0:瀹¤璁℃暟(鍑哄弬 32B) */
#define HPX_CTRL_UDP_INJECT     200 /* UDP 鍥炲寘娉ㄥ叆(缃戠粶鎺ユ敹娉ㄥ叆):澶?24B + payload */
#define HPX_CTRL_UDP_INJECT_SEND 201 /* 鍚?200,浣嗚蛋缃戠粶鍙戦€佹敞鍏?澶囬€夊洖绋嬭吙) */

/* HPX_CTRL_UDP_INJECT 鐨勮緭鍏ュ竷灞€(鎬婚暱 = 24 + payloadLen,缁忓叆鍙傜紦鍐?:
 *   +0x00 cmd(=200)  +0x04 payloadLen   +0x08 srcIp(缃戠粶搴?
 *   +0x0C srcPortNet +0x10 dstIp(缃戠粶搴? +0x14 dstPortNet   +0x18 payload...
 * 璇箟:浠?缃戝崱鏀跺埌"璇箟鎶婁吉閫犳簮(srcIp:srcPort)鈫掔洰鐨?dstIp:dstPort)鐨勬暟鎹姤
 * 閫佸叆鍏ユ爤璺緞,浣?dst 绔偣涓婄殑搴旂敤鎸夊绔?src)鏀跺Ε 鈥斺€?UDP 鍥炵▼鑵裤€? */
typedef struct _HPX_UDP_INJECT_HDR {
    ULONG  cmd;                    /* = HPX_CTRL_UDP_INJECT */
    ULONG  payloadLen;
    ULONG  srcIp;                  /* 缃戠粶搴?= sin_addr 鍐呭瓨搴? */
    USHORT srcPortNet;             /* 缃戠粶搴?*/
    USHORT pad0;
    ULONG  dstIp;                  /* 缃戠粶搴?*/
    USHORT dstPortNet;             /* 缃戠粶搴?*/
    USHORT pad1;
} HPX_UDP_INJECT_HDR;              /* 24 瀛楄妭 */

typedef struct _HPX_CONTROL_IN {
    ULONG cmd;
    ULONG param;
} HPX_CONTROL_IN;

/* HPX_CTRL_SET_LAN 的入参布局(经 IOCTL 入参缓冲,替换式整表下发):
 *   +0x00 cmd(=14)  +0x04 pad  +0x08 count(≤32)  +0x0C pad2
 *   +0x10 count × { net(4), mask(4) }(大端序值:10.10.10.0 → 0x0A0A0A00)
 * 语义:命中任一网段的目标地址 = 局域网 → 一律不代理(直连),全模式生效。
 * 网段来源 = 引擎侧本机各接口 on-link 前缀(最准确的"局域网"定义)。 */
typedef struct _HPX_SET_LAN {
    ULONG cmd;
    ULONG pad;
    ULONG count;
    ULONG pad2;
    struct { ULONG net, mask; } e[32];
} HPX_SET_LAN;

/* ---------------- 璁ら鍘熷鐩殑(0x220194,0x2C in/out) ----------------
 * 鍏ュ弬 {hdr, flowId, arg, cbData=0x1C, data[0x1C]};
 * 鍑哄弬 u 涓?24 瀛楄妭:鍗忚/杩滅/鏈湴/PID銆? * hdr 瀛愬懡浠?
 *   1 = 鎸?flowId 鏌ヨ褰?鏈敤浣滈閫夋嫞閫?淇濈暀)
 *   2 = FIFO:鍙栨渶鑰佹湭棰嗗彇璁板綍(TCP 涓户璁ら,绋冲畾鏈哄埗)
 *   3 = 鎸夋湰鍦扮鐐硅棰?UDP:鍏ュ弬 data 鍐呭～鏈湴绔偣;鍥犳灉寰嬭璁捐鏂囨。)
 *   4 = IPv6 璁ら鍝嶅簲(淇濈暀,鏈疄鐜?
 */
#define HPX_REQ_BY_ID        1
#define HPX_REQ_FIFO         2
#define HPX_REQ_BY_ENDPOINT  3

typedef struct _HPX_REQRESP {
    ULONG  hdr;                    /* +0x00 瀛愬懡浠?*/
    ULONG  flowId;                 /* +0x04 璁板綍 ID(鏌ヨ閿?0=鏃犳晥) */
    ULONG  arg;                    /* +0x08 澶囩敤 */
    ULONG  cbData;                 /* +0x0C = 0x1C */
    union {
        struct {
            ULONG remoteIpV4;      /* 鍘熷鐩殑 IPv4(缃戠粶搴? */
            ULONG remotePort;      /* 鍘熷鐩殑绔彛(涓绘満搴?) */
            ULONG localIpV4;       /* 鏈湴绔偣 IP(缃戠粶搴? */
            ULONG localPort;       /* 鏈湴绔偣绔彛(涓绘満搴? */
            ULONG pid;             /* 鍙戣捣杩涚▼ */
            ULONG protocol;        /* 6=TCP 17=UDP */
        } dst;
        UCHAR raw[HPX_REQRESP_DATA_LEN];
    } u;
} HPX_REQRESP;

/* hdr=HPX_REQ_BY_ENDPOINT 鏃?鍏ュ弬 u.dst 濉?localIpV4/localPort(protocol 閫夊～) */
#define HPX_REQ_GET_ORIGINAL_DST 1   /* 鍏煎鏃ц涔夊埆鍚?*/

/* ---------------- 浜嬩欢娉?0x220198) ---------------- */
#define EV_PROCESS_CREATED    1
#define EV_PROCESS_EXITED     2
#define EV_RECORD_ADDED       3
#define EV_RECORD_REMOVED     4
#define EV_FLOW_REDIRECTED    5
#define EV_FLOW_CLOSED        6
#define EV_LIMIT_REACHED      7
#define EV_DRIVER_ERROR       8

typedef struct _HPX_EVENT {
    ULONG type;
    ULONG cursor;                  /* 鍗曡皟閫掑搴忓彿 */
    ULONG size;                    /* 鏈簨浠舵€婚暱,8 瀛楄妭瀵归綈 */
    union {
        struct { ULONG pid; ULONG parentPid; ULONG created; UCHAR image[16]; } process;
        struct { ULONG id;  ULONG pid;  ULONG proto; } record;
        struct { ULONG id;  ULONG pid;  ULONG remoteIpV4; ULONG remotePort; ULONG protocol; ULONG flags; } flow;
        struct { ULONG code; ULONG reserved[3]; } status;
    } u;
} HPX_EVENT;

/* ---------------- 娴侀噺闄愰(0x2201A4) ---------------- */
typedef struct _HPX_FLOW_LIMIT {
    unsigned __int64 limitUp;      /* 榛樿 100MB = 0x6400000 */
    unsigned __int64 limitDown;
} HPX_FLOW_LIMIT;
#define HPX_DEFAULT_FLOW_LIMIT  0x6400000ULL

/* ---------------- 瀛楄妭鍥炴姤(0x2201AC / 0x2201B0) ----------------
 * 鍘熷巶鍖呰鍑芥暟瀹炶瘉:12 瀛楄妭 {a@0, b@4, id@8}銆? * 鏈」鐩涔?a=涓婅澧為噺瀛楄妭,b=涓嬭澧為噺瀛楄妭,id=璁板綍 ID;
 * a==0 && b==0 涓?id!=0 鈫?杩炴帴/娴佸叧闂€氱煡銆? */
typedef struct _HPX_REPORT {
    ULONG upDelta;
    ULONG downDelta;
    ULONG id;
} HPX_REPORT;

/* ---------------- 娴侀噺鏌ヨ(0x2201B8) ---------------- */
typedef struct _HPX_FLOW_STAT {
    unsigned __int64 up;
    unsigned __int64 down;
} HPX_FLOW_STAT;

#pragma pack(pop)

/* 璇婃柇鍛戒护(97/99/100)鐨勮緭鍑?浠?HPX_CONTROL_IN 鍏ュ弬缂撳啿鍥炲啓 40 瀛楄妭 DWORD 缁?*/
#define HPX_DIAG_WORDS   10

#endif /* HPX_PROTO_H */
