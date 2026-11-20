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

START_CODE = 0x02
RESET_CODE = 0xFF
GW_NONE = 7
BCAST = b'\xff' * 6

N = len(NODES)
M = N - 1
ME = NODES.index(NODE_ID)
OTHERS = [[j for j in range(N) if j != i] for i in range(N)]
COLS = ['%s->%s' % (NODES[i], NODES[j]) for i in range(N) for j in OTHERS[i]]
MAC_OF = [bytes([int(x, 16) for x in MACS[c].split(':')]) for c in NODES]
ID_OF = {mac: i for i, mac in enumerate(MAC_OF)}
GS_MAC_B = bytes([int(x, 16) for x in GS_MAC.split(':')])

FMT_BEACON = '<B%db' % M
LEN_BEACON = struct.calcsize(FMT_BEACON)


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
    try:
        e.add_peer(GS_MAC_B)
    except (OSError, ValueError):
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
        self.started = True
        self.last_reset = self.t0

    def send(self, pkt):
        try:
            self.e.send(BCAST, pkt, False)
        except OSError:
            pass

    def forward(self, pkt):
        try:
            self.e.send(GS_MAC_B, pkt, False)
        except OSError:
            pass

    def on_command(self, line):
        if line.strip().lower() == 'r':
            self.t0 = time.ticks_ms()
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
        self.send(bytes([START_CODE]))
        self.start_left -= 1
        self.next_start = time.ticks_add(self.next_start, START_INTERVAL_MS)

    def on_recv(self, mac, msg):
        m = bytes(mac)
        n = len(msg)
        if m == GS_MAC_B:
            if n == 1:
                c = msg[0]
                if c == RESET_CODE:
                    if self.gw == ME:
                        self.begin_start_burst()
                elif c < N:
                    self.set_gw(c)
            return
        sid = ID_OF.get(m)
        if sid is None or sid == ME:
            return
        if self.gw == ME:
            self.forward(msg)
        if n == LEN_BEACON:
            v = struct.unpack(FMT_BEACON, msg)
            h = v[0]
            g = (h >> 2) & 7
            if h >> 5 or (h & 3) != sid or (g >= N and g != GW_NONE):
                return
            b = sid * M
            for k in range(M):
                self.agg[b + k] = v[1 + k]
            if g == sid and self.gw != ME:
                self.gw = sid
        elif n == 1:
            if msg[0] != START_CODE or sid != self.gw:
                return
            if self.started and time.ticks_diff(time.ticks_ms(), self.last_reset) < RESET_WINDOW_MS:
                return
            self.reset()

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
        self.send(struct.pack(FMT_BEACON, ME | ((GW_NONE if self.gw is None else self.gw) << 2), *own))
        print(' '.join(['%s:%d' % (COLS[i], self.agg[i]) for i in range(N * M)]))
        self.log_row(t)


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
