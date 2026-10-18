#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""udp_probe_node.py — 节点 UDP ASSOCIATE 数据面变体探测(一次性诊断)"""
import socket, struct, sys, time

NODE = ("10.10.10.254", 1081)

def recvn(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c: raise RuntimeError("EOF")
        b += c
    return b

def greet(s):
    s.sendall(b"\x05\x01\x00")
    r = recvn(s, 2)
    return r[1]

def read_reply(s):
    r = recvn(s, 4)
    if r[1] != 0: raise RuntimeError("code=%d" % r[1])
    atyp = r[3]
    if atyp == 1: ip = socket.inet_ntoa(recvn(s, 4))
    elif atyp == 3:
        ln = recvn(s, 1)[0]; ip = recvn(s, ln).decode()
    else:
        recvn(s, 16); ip = "?"
    port = struct.unpack("!H", recvn(s, 2))[0]
    return ip, port

def dns(name):
    q = struct.pack("!HHHHHH", 0x7777, 0x0100, 1, 0, 0, 0)
    for lbl in name.split("."):
        q += bytes([len(lbl)]) + lbl.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)
    return q

def encap(tgt_ip, tgt_port, payload):
    return b"\x00\x00\x00\x01" + socket.inet_aton(tgt_ip) + struct.pack("!H", tgt_port) + payload

def trial(label, send_dest, tgt, count=3, timeout=4):
    ctrl = socket.create_connection(NODE, timeout=8)
    greet(ctrl)
    ctrl.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
    bnd = read_reply(ctrl)
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    us.settimeout(timeout)
    got = 0
    for i in range(count):
        pkt = encap(tgt[0], tgt[1], dns("www.qq.com"))
        us.sendto(pkt, send_dest(bnd))
        try:
            data, src = us.recvfrom(2048)
            got += 1
            pl = data[10:] if len(data) > 10 else data
            an = struct.unpack("!H", pl[6:8])[0] if len(pl) > 7 else -1
            print("  [%s#%d] reply from %s n=%d an=%d" % (label, i, src, len(data), an))
        except Exception as e:
            print("  [%s#%d] %s" % (label, i, e))
    us.close(); ctrl.close()
    print("  [%s] got=%d/%d bnd=%s:%d" % (label, got, count, bnd[0], bnd[1]))
    return got

print("== variant A: send to bnd ip:port ==")
trial("A", lambda b: (b[0], b[1]), ("223.5.5.5", 53))
print("== variant B: send to node ip:control port ==")
trial("B", lambda b: NODE, ("223.5.5.5", 53))
print("== variant C: send to bnd ip:control port ==")
trial("C", lambda b: (b[0], NODE[1]), ("223.5.5.5", 53))
print("== variant D: bnd with tcp connect first (reuse conn) ==")
ctrl = socket.create_connection(NODE, timeout=8)
greet(ctrl)
ctrl.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
bnd = read_reply(ctrl)
print("  bnd", bnd)
us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); us.settimeout(5)
for i in range(3):
    us.sendto(encap("223.5.5.5", 53, dns("www.baidu.com")), (bnd[0], bnd[1]))
    try:
        d, src = us.recvfrom(2048); print("  [D#%d] reply from %s n=%d" % (i, src, len(d)))
    except Exception as e:
        print("  [D#%d] %s" % (i, e))
us.close(); ctrl.close()
print("DONE")
