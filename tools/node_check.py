#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
node_check.py — 10.10.10.254:1081 SOCKS5 节点能力基线检查(宿主侧,免驱动)
硬约束:仅连接 10.10.10.254:1081;经节点的出网目标仅作链路验证(节点自身出网)。
检查项:
  1. SOCKS5 greeting(无认证/用户名密码两方法)
  2. TCP CONNECT -> 223.5.5.5:80,发 HTTP GET,读响应
  3. UDP ASSOCIATE -> 223.5.5.5:53,发 DNS 查询,读应答
输出 MARKER 行 + RESULT,供自动化判据。
"""
import socket
import struct
import sys

NODE_IP = "10.10.10.254"
NODE_PORT = 1081
TCP_TGT = ("223.5.5.5", 80)
UDP_TGT = ("223.5.5.5", 53)


def recvn(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise RuntimeError("EOF after %d/%d" % (len(buf), n))
        buf += c
    return buf


def socks5_greeting(s):
    s.sendall(b"\x05\x02\x00\x02")
    resp = recvn(s, 2)
    if resp[0] != 5 or resp[1] == 0xFF:
        raise RuntimeError("greeting fail: %s" % resp.hex())
    method = resp[1]
    if method == 2:
        s.sendall(b"\x01\x00\x00")
        a = recvn(s, 2)
        if a[1] != 0:
            raise RuntimeError("auth fail: %s" % a.hex())
    return method


def socks5_read_reply(s):
    r = recvn(s, 4)
    if r[1] != 0:
        raise RuntimeError("reply fail code=%d" % r[1])
    atyp = r[3]
    if atyp == 1:
        ip = socket.inet_ntoa(recvn(s, 4))
    elif atyp == 3:
        ln = recvn(s, 1)[0]
        ip = recvn(s, ln).decode("ascii", "replace")
    else:
        recvn(s, 16)
        ip = "?v6"
    port = struct.unpack("!H", recvn(s, 2))[0]
    return ip, port


def socks5_connect(s, tgt):
    req = b"\x05\x01\x00\x01" + socket.inet_aton(tgt[0]) + struct.pack("!H", tgt[1])
    s.sendall(req)
    return socks5_read_reply(s)


def dns_query_bytes():
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for lbl in b"example.com".split(b"."):
        q += bytes([len(lbl)]) + lbl
    q += b"\x00" + struct.pack("!HH", 1, 1)
    return q


def main():
    ok = True

    # 1. TCP CONNECT
    s = socket.create_connection((NODE_IP, NODE_PORT), timeout=8)
    try:
        m = socks5_greeting(s)
        bnd = socks5_connect(s, TCP_TGT)
        s.sendall(b"GET / HTTP/1.0\r\nHost: 223.5.5.5\r\n\r\n")
        data = s.recv(256)
        head = data.split(b"\r\n")[0][:60]
        if data:
            print("MARKER-TCP method=%d bnd=%s:%d resp=%r len=%d" % (m, bnd[0], bnd[1], head, len(data)))
        else:
            print("MARKER-TCP-FAIL empty response")
            ok = False
    except Exception as e:
        print("MARKER-TCP-FAIL %s" % e)
        ok = False
    finally:
        s.close()

    # 2. UDP ASSOCIATE
    ctrl = socket.create_connection((NODE_IP, NODE_PORT), timeout=8)
    try:
        socks5_greeting(ctrl)
        bnd_ip, bnd_port = socks5_read_reply_ctrl(ctrl)
        print("MARKER-UDP-ASSOC bnd=%s:%d" % (bnd_ip, bnd_port))
        us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        us.settimeout(8)
        pkt = b"\x00\x00\x00\x00" + socket.inet_aton(UDP_TGT[0]) + struct.pack("!H", UDP_TGT[1]) + dns_query_bytes()
        us.sendto(pkt, (bnd_ip if bnd_port else NODE_IP, bnd_port or NODE_PORT))
        try:
            data, src = us.recvfrom(2048)
            if len(data) > 10 and data[3] == 1:
                rip = socket.inet_ntoa(data[4:8])
                rport = struct.unpack("!H", data[8:10])[0]
                payload = data[10:]
            else:
                rip, rport, payload = "?", 0, data
            rcode = payload[3] & 0x0F if len(payload) > 3 else -1
            ancount = struct.unpack("!H", payload[6:8])[0] if len(payload) > 7 else -1
            print("MARKER-UDP-REPLY from=%s:%d rcode=%d ancount=%d n=%d" % (rip, rport, rcode, ancount, len(payload)))
            if rcode != 0 or ancount < 1:
                ok = False
        except Exception as e:
            print("MARKER-UDP-FAIL %s" % e)
            ok = False
        us.close()
    except Exception as e:
        print("MARKER-UDP-ASSOC-FAIL %s" % e)
        ok = False
    finally:
        ctrl.close()

    print("RESULT: %s" % ("PASS" if ok else "FAIL"))
    sys.exit(0 if ok else 1)


def socks5_read_reply_ctrl(s):
    req = b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0)
    s.sendall(req)
    return socks5_read_reply(s)


if __name__ == "__main__":
    main()
