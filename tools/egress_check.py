#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
egress_check.py — 经 10.10.10.254:1081 访问 ip111.cn,读取页面里展示的出口 IP。
仅连接 10.10.10.254:1081(硬约束);目标 ip111.cn 由节点出网访问。
输出页面中"从国内测试/从国外测试"两行的 IP,供与直连 IP 对照。
"""
import socket
import ssl
import struct
import sys
import re

NODE = ("10.10.10.254", 1081)


def recvn(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise RuntimeError("eof")
        b += c
    return b


def main():
    # 1. SOCKS5 到节点
    s = socket.create_connection(NODE, timeout=10)
    s.sendall(b"\x05\x02\x00\x02")
    r = recvn(s, 2)
    if r[0] != 5 or r[1] == 0xFF:
        print("greeting fail:", r.hex())
        return 1
    print("[+] greeting ok, method=%d" % r[1])

    # 2. 解析 ip111.cn(经链的域名解析:用本地解析仅取地址,连接仍走节点)
    ip = socket.gethostbyname("ip111.cn")
    print("[+] ip111.cn -> %s" % ip)

    # 3. CONNECT ip111.cn:443
    req = b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack("!H", 443)
    s.sendall(req)
    r = recvn(s, 4)
    if r[1] != 0:
        print("CONNECT fail code=%d" % r[1])
        return 1
    atyp = r[3]
    if atyp == 1:
        recvn(s, 6)
    elif atyp == 3:
        ln = recvn(s, 1)[0]
        recvn(s, ln + 2)
    else:
        recvn(s, 18)
    print("[+] CONNECT ok (经节点)")

    # 4. TLS + GET /
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t = ctx.wrap_socket(s, server_hostname="ip111.cn")
    t.sendall(b"GET / HTTP/1.1\r\nHost: ip111.cn\r\nConnection: close\r\n\r\n")
    data = b""
    while True:
        c = t.recv(65536)
        if not c:
            break
        data += c
        if len(data) > 200000:
            break
    t.close()
    text = data.decode("utf-8", "replace")
    ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)
    seen = []
    for i in ips:
        if i not in seen and not i.startswith("0.") and i != ip:
            seen.append(i)
    print("[+] 页面出现的 IP(前 8 个):%s" % ", ".join(seen[:8]))
    m = re.search(r"从国内测试(.{0,220})从国外测试(.{0,220})", text, re.S)
    if m:
        a = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", m.group(1))
        b = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", m.group(2))
        print("[+] 从国内测试 =", a[0] if a else "?")
        print("[+] 从国外测试 =", b[0] if b else "?")
    print("RESULT: DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
