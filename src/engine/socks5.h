/* socks5.h 鈥?SOCKS5 瀹㈡埛绔?RFC 1928)鏈€灏忓疄鐜?CONNECT + UDP ASSOCIATE */
#ifndef HPX_SOCKS5_H
#define HPX_SOCKS5_H

#include <winsock2.h>
#include <ws2tcpip.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _S5_NODE {
    char ip[64];
    int  port;
    char user[64];
    char pass[64];
} S5_NODE;

/* 杩炶妭鐐?+ greeting(05 02 00 02)+ 鍙€夌敤鎴峰悕瀵嗙爜瀛愬崗鍟?澶辫触杩斿洖 0 */
int s5_open(const S5_NODE* node, SOCKET* out);

/* CONNECT 鍒?dst(缃戠粶搴?sin_addr + 缂冨喖搴?sin_port);鎴愬姛杩斿洖 0 */
int s5_connect(SOCKET s, const struct sockaddr_in* dst);

/* CONNECT 鍒板煕鍚嶇О(ATYP=3,鑺傜偣璐熻矗瑙ｆ瀽=闃叉薄鏌?);鎴愬姛杩斿洖 0 */
int s5_connect_host(SOCKET s, const char* host, unsigned short portHost);

/* UDP ASSOCIATE;鎴愬姛杩斿洖 0,bndOut 涓哄疄闄?UDP 涓户绔偣 */
int s5_associate(SOCKET s, struct sockaddr_in* bndOut);

/* RFC1928 UDP 灏佽:00 00 FRAG=00 ATYP=01 addr(4) port(2) + payload */
int s5_udp_encap(const struct sockaddr_in* dst, const void* payload, int plen,
                 void* out, int outCap);

/* 瑙ｅ皝瑁?鎴愬姛杩斿洖 0 骞剁粰鍑哄唴灞傛簮绔偣涓?payload 瑙嗗浘 */
int s5_udp_decap(const void* pkt, int len, struct sockaddr_in* srcOut,
                 const void** payload, int* plen);

/* 鍏ㄩ噺鏀?鍙?瀹瑰繊鐭啓鐭;select 鍒嗙墖鏀寔鍋滄満) */
int s5_sendn(SOCKET s, const void* buf, int len);
int s5_recvn(SOCKET s, void* buf, int len);
/* 甯︽€昏秴鏃?姣)鐨勫叏閲忔敹 */
int s5_recvn_to(SOCKET s, void* buf, int len, int timeoutMs);

#ifdef __cplusplus
}
#endif
#endif /* HPX_SOCKS5_H */
