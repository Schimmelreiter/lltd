#!/usr/bin/env python3
"""Minimal LLTD mapper for the end-to-end test.

Follows the sequence of the "LLTD-Netzwerkuebersicht" mapper: quick and
topology Discover, Hello acknowledgement, Verify (Query), and topology test
rounds with Charge / acknowledged Emit (Trains) / unacknowledged Emit (one
Probe) / Query, then Reset for ToS 0 and 1.

Usage: mapper.py <interface> <round> [<round> ...]
       round = c_mac,d_mac   (the mapper itself is the root)
Prints one line per round and exits 1 if a round is INVALID.
"""
import os
import random
import select
import socket
import struct
import sys
import time

ETH_P_LLTD = 0x88D9
TOS_TOPO, TOS_QUICK = 0, 1
F_DISCOVER, F_HELLO, F_EMIT, F_TRAIN, F_PROBE, F_ACK, F_QUERY, F_QUERYRESP, F_RESET, F_CHARGE, F_FLAT = range(11)
BCAST = b"\xff" * 6


def mac_str(b):
    return ":".join("%02x" % x for x in b)


def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))


class Mapper:
    def __init__(self, ifname):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_LLTD))
        self.sock.bind((ifname, ETH_P_LLTD))
        self.me = self.sock.getsockname()[4][:6]
        self.hosts = {}
        self.ack = {TOS_TOPO: [], TOS_QUICK: []}
        self.acks, self.flats, self.qresps, self.seen = set(), set(), {}, set()
        self.seqs = {}
        self.xid = {TOS_TOPO: random.randint(1, 65534), TOS_QUICK: random.randint(1, 65534)}
        self.spoof = 0x000D3AD7F140 + random.randint(0x100, 0x200000)
        self.gen = 0

    # ---------------------------------------------------------------- frames
    def frame(self, tos, fn, eth_dst, eth_src, real_dst, real_src, seq, payload=b""):
        f = eth_dst + eth_src + struct.pack("!HBBBB", ETH_P_LLTD, 1, tos, 0, fn)
        f += real_dst + real_src + struct.pack("!H", seq) + payload
        return f.ljust(60, b"\0")

    def send(self, f):
        self.sock.send(f)

    def discover(self, tos):
        st = self.ack[tos][:200]
        p = struct.pack("!HH", self.gen if tos == TOS_TOPO else 0, len(st)) + b"".join(st)
        self.send(self.frame(tos, F_DISCOVER, BCAST, self.me, BCAST, self.me, self.xid[tos], p))

    def process(self, f):
        if len(f) < 32 or f[12:14] != b"\x88\xd9" or f[14] != 1:
            return
        tos, fn = f[15], f[17]
        rs = mac_str(f[24:30])
        if tos > 1 or rs == mac_str(self.me):
            return
        seq = struct.unpack("!H", f[30:32])[0]
        if fn == F_HELLO:
            gen = struct.unpack("!H", f[32:34])[0]
            name, i = "", 46
            while i + 2 <= len(f) and f[i] != 0:
                t, ln = f[i], f[i + 1]
                if t == 0x0F:
                    name = f[i + 2:i + 2 + ln].decode("utf-16-le", "replace")
                i += 2 + ln
            if rs not in self.hosts:
                print("hello %s %s tos%d" % (rs, name, tos))
            self.hosts[rs] = name
            if mac_bytes(rs) not in self.ack[tos]:
                self.ack[tos].append(mac_bytes(rs))
            if tos == TOS_TOPO and self.gen == 0 and gen:
                self.gen = gen
        elif fn == F_ACK:
            self.acks.add((rs, seq))
        elif fn == F_FLAT:
            self.flats.add((rs, seq))
        elif fn == F_QUERYRESP:
            self.qresps[(rs, seq)] = f
        elif fn == F_PROBE:
            self.seen.add((rs, mac_str(f[0:6])))

    def pump(self, ms):
        end = time.monotonic() + ms / 1000.0
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return
            r, _, _ = select.select([self.sock], [], [], min(left, 0.02))
            if r:
                self.process(self.sock.recv(2048))

    def wait_for(self, cond, ms):
        end = time.monotonic() + ms / 1000.0
        while not cond():
            left = end - time.monotonic()
            if left <= 0:
                return False
            r, _, _ = select.select([self.sock], [], [], min(left, 0.02))
            if r:
                self.process(self.sock.recv(2048))
        return True

    # ------------------------------------------------------------- commands
    def cur_seq(self, mac):
        return self.seqs.setdefault(mac, random.randint(1, 65000))

    def adv_seq(self, mac):
        s = self.cur_seq(mac) + 1
        self.seqs[mac] = 1 if s > 0xFFFF else s

    def next_spoof(self):
        self.spoof += 1
        return self.spoof.to_bytes(6, "big")

    def charge(self, mac, n):
        to = mac_bytes(mac)
        for _ in range(n):
            self.send(self.frame(TOS_TOPO, F_CHARGE, to, self.me, to, self.me, 0, b"\0" * 28))

    def emit_frame(self, mac, seq, descs):
        to = mac_bytes(mac)
        p = struct.pack("!H", len(descs))
        for t, pause, src, dst in descs:
            p += struct.pack("!BB", t, pause) + src + dst
        return self.frame(TOS_TOPO, F_EMIT, to, self.me, to, self.me, seq, p)

    def emit_acked(self, mac, descs):
        pause = sum(d[1] for d in descs)
        self.charge(mac, len(descs) + 1)
        for _ in range(2):
            seq = self.cur_seq(mac)
            key = (mac, seq)
            for _ in range(3):
                self.send(self.emit_frame(mac, seq, descs))
                if self.wait_for(lambda: key in self.acks or key in self.flats, 350 + pause):
                    self.adv_seq(mac)
                    if key in self.acks:
                        return True
                    print("flat from", mac)
                    self.charge(mac, len(descs) + 3)
                    break
            else:
                print("emit timeout", mac, seq)
                self.adv_seq(mac)
                self.charge(mac, len(descs) + 1)
        return False

    def query(self, mac):
        res, to = [], mac_bytes(mac)
        for _ in range(50):
            seq = self.cur_seq(mac)
            key = (mac, seq)
            got = False
            for _ in range(4):
                self.send(self.frame(TOS_TOPO, F_QUERY, to, self.me, to, self.me, seq))
                if self.wait_for(lambda: key in self.qresps, 300):
                    got = True
                    break
            self.adv_seq(mac)
            if not got:
                print("query timeout", mac, seq)
                return None
            f = self.qresps.pop(key)
            hdr = struct.unpack("!H", f[32:34])[0]
            for i in range(hdr & 0x3FFF):
                o = 34 + 20 * i
                if f[o:o + 2] == b"\0\0":
                    res.append((mac_str(f[o + 2:o + 8]), mac_str(f[o + 14:o + 20])))
            if not hdr & 0x8000:
                break
        return res

    # ---------------------------------------------------------------- phases
    def discover_phase(self):
        start = time.monotonic()
        for at in (0, 600, 1400, 2400, 3400):
            while (time.monotonic() - start) * 1000 < at:
                self.pump(50)
            self.discover(TOS_QUICK)
            self.discover(TOS_TOPO)
        self.pump(4500 - (time.monotonic() - start) * 1000)
        for _ in range(2):
            self.discover(TOS_QUICK)
            self.discover(TOS_TOPO)
            self.pump(150)
        self.send(self.frame(TOS_QUICK, F_RESET, BCAST, self.me, BCAST, self.me, 0))

    def round(self, c, d, probers):
        x = self.next_spoof()
        xs = mac_str(x)
        for _ in range(2):   # the mapper is the root: teach X here
            self.send(self.frame(TOS_TOPO, F_TRAIN, BCAST, x, BCAST, self.me, 0))
        if not self.emit_acked(c, [(0, 120, x, mac_bytes(d)), (0, 5, x, mac_bytes(d))]):
            return None
        for a in probers:
            to = mac_bytes(a)
            p = struct.pack("!HBB", 1, 1, 120) + to + x
            self.send(self.frame(TOS_TOPO, F_EMIT, to, self.me, to, self.me, 0, p))
        self.pump(120 + 250)
        at_c = {rs for rs, dst in (self.query(c) or []) if dst == xs}
        at_root = {rs for rs, dst in self.seen if dst == xs}
        self.seen.clear()
        return at_c, at_root


def main():
    ifname, rounds = sys.argv[1], sys.argv[2:]
    m = Mapper(ifname)
    m.discover_phase()
    print("discovered:", ", ".join("%s (%s)" % kv for kv in sorted(m.hosts.items())))
    for h in list(m.hosts):
        if mac_bytes(h) not in m.ack[TOS_TOPO]:
            m.ack[TOS_TOPO].append(mac_bytes(h))
    for _ in range(2):
        m.discover(TOS_TOPO)
        m.pump(100)
    resp = []
    for h in sorted(m.hosts):
        if m.query(h) is not None:
            resp.append(h)
        else:
            print("no topology session:", h)
    ok = len(resp) == len(m.hosts) and len(resp) > 0
    for spec in rounds:
        c, d = spec.split(",")
        probers = [h for h in resp if h != c]
        res = m.round(c, d, probers)
        if res is None:
            print("round c=%s d=%s FAILED" % (c, d))
            ok = False
            continue
        at_c, at_root = res
        missing = [p for p in probers if p not in at_c and p not in at_root]
        flooded = [p for p in probers if p in at_c and p in at_root]
        valid = d in at_c and not missing and not flooded
        print("round c=%s d=%s atC=%s atRoot=%s missing=%s%s%s" % (
            c, d, sorted(at_c), sorted(at_root), missing, " FLOOD" if flooded else "",
            "" if valid else " INVALID"))
        ok = ok and valid
    m.send(m.frame(TOS_TOPO, F_RESET, BCAST, m.me, BCAST, m.me, 0))
    m.send(m.frame(TOS_QUICK, F_RESET, BCAST, m.me, BCAST, m.me, 0))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
