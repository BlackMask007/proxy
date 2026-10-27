/* socks5.c 鈥?SOCKS5 瀹㈡埛绔?RFC 1928)鏈€灏忓疄鐜? * 瀹炴祴鑺傜偣濂戠害(10.10.10.254:1081):
 *   - greeting 蹇呴』鍚屾椂鎻愪緵 0x00 涓?0x02(`\x05\x02\x00\x02`),鍙彂 0x00 浼氳鎷?0xFF);
 *   - UDP ASSOCIATE 鐨?BND 鍙兘鍥?0.0.0.0/鐜洖 鈫?瀹為檯鐢ㄨ妭鐐?IP + BND 绔彛;
 *   - 鑺傜偣鐨?UDP 浼氳瘽閽夋鍦?*棣栦釜鏁版嵁鎶?*鐨勬簮绔彛涓庣洰鏍囦笂 鈫?姣忔祦涓€涓叧鑱斻€? *     涓€涓笂琛屽鎺ュ瓧(濂楁帴瀛楀嵆娴佽韩浠?,鎹㈡簮绔彛鐨勬暟鎹姤浼氳闈欓粯涓㈠純銆? */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include "socks5.h"

int s5_recvn(SOCKET s, void* buf, int len)
{
    char* p = (char*)buf;
    int got = 0;
    while (got < len) {
        int n = recv(s, p + got, len - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    return got;
}

int s5_recvn_to(SOCKET s, void* buf, int len, int timeoutMs)
{
    char* p = (char*)buf;
    int got = 0;
    while (got < len) {
        fd_set rf;
        struct timeval tv;
        int r;
        FD_ZERO(&rf);
        FD_SET(s, &rf);
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        r = select(0, &rf, NULL, NULL, &tv);
        if (r <= 0) return -1;
        {
            int n = recv(s, p + got, len - got, 0);
            if (n <= 0) return -1;
            got += n;
        }
    }
    return got;
}

int s5_sendn(SOCKET s, const void* buf, int len)
{
    const char* p = (const char*)buf;
    int sent = 0;
    while (sent < len) {
        int n = send(s, p + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

static int s5_read_reply(SOCKET s, struct sockaddr_in* bndOut)
{
    unsigned char head[4];
    unsigned char addr[256];
    unsigned char pbuf[2];
    struct sockaddr_in bnd;
    if (s5_recvn(s, head, 4) < 0) return -1;
    if (head[0] != 5 || head[1] != 0) return -1;
    memset(&bnd, 0, sizeof(bnd));
    bnd.sin_family = AF_INET;
    switch (head[3]) {
    case 1:
        if (s5_recvn(s, addr, 4) < 0) return -1;
        memcpy(&bnd.sin_addr, addr, 4);
        break;
    case 3: {
        unsigned char ln;
        if (s5_recvn(s, &ln, 1) < 0) return -1;
        if (s5_recvn(s, addr, ln) < 0) return -1;
        /* 鍩熷悕褰?BND:涓嶈В鏋?缃?0(璋冪敤鏂瑰洖閫€鑺傜偣 IP) */
        bnd.sin_addr.s_addr = 0;
        break;
    }
    case 4:
        if (s5_recvn(s, addr, 16) < 0) return -1;
        bnd.sin_addr.s_addr = 0;
        break;
    default:
        return -1;
    }
    if (s5_recvn(s, pbuf, 2) < 0) return -1;
    memcpy(&bnd.sin_port, pbuf, 2);
    if (bndOut) *bndOut = bnd;
    return 0;
}

int s5_open(const S5_NODE* node, SOCKET* out)
{
    struct sockaddr_in sa;
    SOCKET s;
    unsigned char greet[3], resp[2];
    int timeoutMs = 8000;
    int big = 1 << 20;
    int nodelay = 1;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;

    /* 吞吐强化:大缓冲 + 关 Nagle(中继按块转发,小缓冲会封顶速率) */
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char*)&big, sizeof(big));
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char*)&big, sizeof(big));
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)node->port);
    if (inet_pton(AF_INET, node->ip, &sa.sin_addr) != 1) {
        closesocket(s);
        return -1;
    }
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        closesocket(s);
        return -1;
    }

    /* greeting 蹇呴』 05 02 00 02(瀹炴祴鑺傜偣鍙粰 0x00 鏃跺洖 0xFF) */
    greet[0] = 5; greet[1] = 2; greet[2] = 0;
    {
        unsigned char g2[4] = { 5, 2, 0, 2 };
        if (s5_sendn(s, g2, 4) < 0) { closesocket(s); return -1; }
    }
    (void)greet;
    if (s5_recvn(s, resp, 2) < 0) { closesocket(s); return -1; }
    if (resp[0] != 5 || resp[1] == 0xFF) { closesocket(s); return -1; }
    if (resp[1] == 2) {
        unsigned char u[257], a[2];
        int ul = (int)strlen(node->user), pl = (int)strlen(node->pass);
        if (ul > 255) ul = 255;
        if (pl > 255) pl = 255;
        u[0] = 1;
        u[1] = (unsigned char)ul;
        memcpy(u + 2, node->user, ul);
        u[2 + ul] = (unsigned char)pl;
        memcpy(u + 3 + ul, node->pass, pl);
        if (s5_sendn(s, u, 3 + ul + pl) < 0) { closesocket(s); return -1; }
        if (s5_recvn(s, a, 2) < 0 || a[1] != 0) { closesocket(s); return -1; }
    }
    *out = s;
    return 0;
}

int s5_connect(SOCKET s, const struct sockaddr_in* dst)
{
    unsigned char req[10], * p = req;
    struct sockaddr_in bnd;
    *p++ = 5; *p++ = 1; *p++ = 0; *p++ = 1;
    memcpy(p, &dst->sin_addr, 4); p += 4;
    memcpy(p, &dst->sin_port, 2); p += 2;
    if (s5_sendn(s, req, 10) < 0) return -1;
    return s5_read_reply(s, &bnd);
}

int s5_connect_host(SOCKET s, const char* host, unsigned short portHost)
{
    unsigned char req[280], * p = req;
    struct sockaddr_in bnd;
    int hl = host ? (int)strlen(host) : 0;
    if (hl <= 0 || hl > 255) return -1;
    *p++ = 5; *p++ = 1; *p++ = 0; *p++ = 3;
    *p++ = (unsigned char)hl;
    memcpy(p, host, (size_t)hl); p += hl;
    *p++ = (unsigned char)(portHost >> 8);
    *p++ = (unsigned char)(portHost & 0xFF);
    if (s5_sendn(s, req, (int)(p - req)) < 0) return -1;
    return s5_read_reply(s, &bnd);
}

int s5_associate(SOCKET s, struct sockaddr_in* bndOut)
{
    unsigned char req[10], * p = req;
    struct sockaddr_in bnd;
    *p++ = 5; *p++ = 3; *p++ = 0; *p++ = 1;
    memset(p, 0, 4); p += 4;
    memset(p, 0, 2); p += 2;
    if (s5_sendn(s, req, 10) < 0) return -1;
    if (s5_read_reply(s, &bnd) < 0) return -1;
    if (bnd.sin_port == 0) return -1;              /* BND 绔彛涓虹┖ = 鎷掔粷 */
    if (bnd.sin_addr.s_addr == 0 ||
        (ntohl(bnd.sin_addr.s_addr) >> 24) == 127) {
        /* 鍗犱綅/鐜洖 鈫?鐢ㄨ妭鐐?IP(璋冪敤鏂逛繚璇佹帶鍒惰繛鎺ュ绔嵆鑺傜偣) */
        struct sockaddr_in peer;
        int plen = sizeof(peer);
        if (getpeername(s, (struct sockaddr*)&peer, &plen) == 0)
            bnd.sin_addr = peer.sin_addr;
    }
    if (bndOut) *bndOut = bnd;
    return 0;
}

int s5_udp_encap(const struct sockaddr_in* dst, const void* payload, int plen,
                 void* out, int outCap)
{
    unsigned char* p = (unsigned char*)out;
    if (outCap < 10 + plen) return -1;
    p[0] = 0; p[1] = 0; p[2] = 0; p[3] = 1;
    memcpy(p + 4, &dst->sin_addr, 4);
    memcpy(p + 8, &dst->sin_port, 2);
    if (plen) memcpy(p + 10, payload, plen);
    return 10 + plen;
}

int s5_udp_decap(const void* pkt, int len, struct sockaddr_in* srcOut,
                 const void** payload, int* plen)
{
    const unsigned char* p = (const unsigned char*)pkt;
    int off;
    struct sockaddr_in src;
    if (len < 10) return -1;
    if (p[0] != 0 || p[1] != 0) return -1;          /* RSV */
    /* p[2]=FRAG;鍒嗙墖涓嶆敮鎸?闈?0 鐩存帴涓?*/
    if (p[2] != 0) return -1;
    memset(&src, 0, sizeof(src));
    src.sin_family = AF_INET;
    switch (p[3]) {
    case 1:
        memcpy(&src.sin_addr, p + 4, 4);
        memcpy(&src.sin_port, p + 8, 2);
        off = 10;
        break;
    case 3: {
        int ln = p[4];
        if (len < 5 + ln + 2) return -1;
        src.sin_addr.s_addr = 0;
        memcpy(&src.sin_port, p + 5 + ln, 2);
        off = 5 + ln + 2;
        break;
    }
    case 4:
        if (len < 22) return -1;
        src.sin_addr.s_addr = 0;
        memcpy(&src.sin_port, p + 20, 2);
        off = 22;
        break;
    default:
        return -1;
    }
    if (srcOut) *srcOut = src;
    if (payload) *payload = p + off;
    if (plen) *plen = len - off;
    return 0;
}
