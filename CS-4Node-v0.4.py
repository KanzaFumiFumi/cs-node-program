import network
import espnow
import struct
import sys
import select
import time
import os

NODE_ID = 'A'

MACS = {
    'A': '00:00:00:00:00:00',
    'B': '00:00:00:00:00:00',
    'C': '00:00:00:00:00:00',
    'D': '00:00:00:00:00:00',
}

GS_MAC = '00:00:00:00:00:00'

NODES = 'ABCD'
CHANNEL = 6
TX_INTERVAL_MS = 100
START_INTERVAL_MS = 1000
START_REPEAT = 10
RESET_WINDOW_MS = START_INTERVAL_MS * START_REPEAT
MIN_FREE_BYTES = 16 * 1024
LOG_CHECK_ROWS = 10

MAGIC = 0x52
T_BEACON = 0x01
T_START = 0x02
T_RESET = 0x03
T_AGG = 0x04
T_ASSIGN = 0x05
BCAST = b'\xff' * 6

N = len(NODES)
M = N - 1
ME = NODES.index(NODE_ID)
OTHERS = [[j for j in range(N) if j != i] for i in range(N)]
COLS = ['%s->%s' % (NODES[i], NODES[j]) for i in range(N) for j in OTHERS[i]]
MAC_OF = [bytes([int(x, 16) for x in MACS[c].split(':')]) for c in NODES]
ID_OF = {mac: i for i, mac in enumerate(MAC_OF)}
GS_MAC_B = bytes([int(x, 16) for x in GS_MAC.split(':')])

FMT_BEACON = '<BBBHI%db' % M
FMT_START = '<BBI'
FMT_RESET = '<BB'
FMT_AGG = '<BBIH%db' % (N * M)
FMT_ASSIGN = '<BBB'
LEN_BEACON = struct.calcsize(FMT_BEACON)
LEN_START = struct.calcsize(FMT_START)
LEN_RESET = struct.calcsize(FMT_RESET)
LEN_AGG = struct.calcsize(FMT_AGG)
LEN_ASSIGN = struct.calcsize(FMT_ASSIGN)


def setup_espnow():
    sta = network.WLAN(network.STA_IF)
    sta.active(True)
    sta.disconnect()
    sta.config(channel=CHANNEL)
    sta.config(pm=sta.PM_NONE)
    e = espnow.ESPNow()
    e.active(True)
    if not hasattr(e, 'peers_table'):
        print('ERROR: peers_table is not supported by this firmware')
        raise SystemExit
    try:
        e.add_peer(BCAST)
    except OSError:
        pass
    return e


def free_bytes():
    st = os.statvfs('/')
    return st[0] * st[3]


class Node:
    def __init__(self, e):
        self.e = e
        self.agg = [0] * (N * M)
        self.t0 = time.ticks_ms()
        self.seq = 0
        self.started = False
        self.last_reset = self.t0
        self.gw = None
        self.start_left = 0
        self.next_start = self.t0
        self.f = None
        self.log_rows = 0

    def now(self):
        return time.ticks_diff(time.ticks_ms(), self.t0)

    def reset(self):
        self.t0 = time.ticks_ms()
        self.seq = 0
        self.started = True
        self.last_reset = self.t0

    def send(self, pkt):
        try:
            self.e.send(BCAST, pkt, False)
        except OSError:
            pass

    def on_command(self, line):
        if line.strip().lower() == 'r':
            self.t0 = time.ticks_ms()
            self.seq = 0
            self.start_log()

    def start_log(self):
        self.close_log()
        try:
            names = os.listdir()
            n = 0
            while '%s_%03d.csv' % (NODE_ID, n) in names:
                n += 1
            if free_bytes() < MIN_FREE_BYTES:
                return
            self.f = open('%s_%03d.csv' % (NODE_ID, n), 'w')
            self.f.write('time_s,gw,' + ','.join(COLS) + '\n')
            self.f.flush()
        except OSError:
            self.close_log()
            return
        self.log_rows = 0

    def log_row(self, t):
        if self.f is None:
            return
        d = (t + 50) // 100
        gw = '-' if self.gw is None else NODES[self.gw]
        try:
            self.f.write('%d.%d,%s,%s\n' % (d // 10, d % 10, gw, ','.join([str(x) for x in self.agg])))
            self.f.flush()
            self.log_rows += 1
            low = self.log_rows % LOG_CHECK_ROWS == 0 and free_bytes() < MIN_FREE_BYTES
        except OSError:
            self.close_log()
            return
        if low:
            self.close_log()

    def close_log(self):
        if self.f is None:
            return
        try:
            self.f.close()
        except OSError:
            pass
        self.f = None

    def set_gw(self, gid):
        if gid == self.gw:
            return
        self.gw = gid
        self.start_left = 0

    def begin_start_burst(self):
        self.reset()
        self.start_left = START_REPEAT
        self.next_start = time.ticks_ms()

    def send_start(self):
        if self.start_left <= 0:
            return
        if time.ticks_diff(time.ticks_ms(), self.next_start) < 0:
            return
        self.send(struct.pack(FMT_START, MAGIC, T_START, self.now() & 0xFFFFFFFF))
        self.start_left -= 1
        self.next_start = time.ticks_add(self.next_start, START_INTERVAL_MS)

    def on_recv(self, mac, msg):
        m = bytes(mac)
        n = len(msg)
        if m == GS_MAC_B:
            if n == LEN_RESET:
                v = struct.unpack(FMT_RESET, msg)
                if v[0] == MAGIC and v[1] == T_RESET and self.gw == ME:
                    self.begin_start_burst()
            elif n == LEN_ASSIGN:
                v = struct.unpack(FMT_ASSIGN, msg)
                if v[0] == MAGIC and v[1] == T_ASSIGN and v[2] < N:
                    self.set_gw(v[2])
            return
        sid = ID_OF.get(m)
        if sid is None or sid == ME:
            return
        if n == LEN_BEACON:
            v = struct.unpack(FMT_BEACON, msg)
            if v[0] != MAGIC or v[1] != T_BEACON or v[2] != sid:
                return
            b = sid * M
            for k in range(M):
                self.agg[b + k] = v[5 + k]
        elif n == LEN_START:
            v = struct.unpack(FMT_START, msg)
            if v[0] != MAGIC or v[1] != T_START or sid != self.gw:
                return
            if self.started and time.ticks_diff(time.ticks_ms(), self.last_reset) < RESET_WINDOW_MS:
                return
            self.reset()
        elif n == LEN_AGG:
            v = struct.unpack(FMT_AGG, msg)
            if v[0] != MAGIC or v[1] != T_AGG or self.gw == ME:
                return
            self.gw = sid

    def update_own(self):
        pt = self.e.peers_table
        b = ME * M
        for k, j in enumerate(OTHERS[ME]):
            p = pt.get(MAC_OF[j])
            if p is not None:
                self.agg[b + k] = p[0]

    def tick(self):
        is_gw = self.gw == ME
        if is_gw:
            self.send_start()
        self.update_own()
        t = self.now() & 0xFFFFFFFF
        b = ME * M
        own = self.agg[b:b + M]
        self.send(struct.pack(FMT_BEACON, MAGIC, T_BEACON, ME, self.seq, t, *own))
        if is_gw:
            self.send(struct.pack(FMT_AGG, MAGIC, T_AGG, t, self.seq, *self.agg))
        print(' '.join(['%s:%d' % (COLS[i], self.agg[i]) for i in range(N * M)]))
        self.log_row(t)
        self.seq = (self.seq + 1) & 0xFFFF


def main():
    e = setup_espnow()
    node = Node(e)
    keys = select.poll()
    keys.register(sys.stdin, select.POLLIN)
    next_tx = time.ticks_ms()
    try:
        while True:
            if keys.poll(0):
                node.on_command(sys.stdin.readline())
            wait = time.ticks_diff(next_tx, time.ticks_ms())
            if wait > 0:
                mac, msg = e.recv(wait)
                if msg:
                    node.on_recv(mac, msg)
                continue
            node.tick()
            next_tx = time.ticks_add(next_tx, TX_INTERVAL_MS)
            if time.ticks_diff(time.ticks_ms(), next_tx) > TX_INTERVAL_MS:
                next_tx = time.ticks_add(time.ticks_ms(), TX_INTERVAL_MS)
    finally:
        node.close_log()


main()
