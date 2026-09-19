import network
import espnow
import struct
import time

NODE_ID = 'A'

MACS = {
    'A': '00:00:00:00:00:00',
    'B': '00:00:00:00:00:00',
    'C': '00:00:00:00:00:00',
    'D': '00:00:00:00:00:00',
}

GS_MAC = '00:00:00:00:00:00'

NODES = 'ABCD'
GW_ID = 'A'
CHANNEL = 6
TX_INTERVAL_MS = 100
START_INTERVAL_MS = 1000
START_REPEAT = 10
RESET_WINDOW_MS = START_INTERVAL_MS * START_REPEAT

MAGIC = 0x52
T_BEACON = 0x01
T_START = 0x02
T_RESET = 0x03
T_AGG = 0x04
BCAST = b'\xff' * 6

N = len(NODES)
M = N - 1
ME = NODES.index(NODE_ID)
GW = NODES.index(GW_ID)
IS_GW = ME == GW
OTHERS = [[j for j in range(N) if j != i] for i in range(N)]
COLS = ['%s->%s' % (NODES[i], NODES[j]) for i in range(N) for j in OTHERS[i]]
MAC_OF = [bytes([int(x, 16) for x in MACS[c].split(':')]) for c in NODES]
ID_OF = {mac: i for i, mac in enumerate(MAC_OF)}
GS_MAC_B = bytes([int(x, 16) for x in GS_MAC.split(':')])

FMT_BEACON = '<BBBHI%db' % M
FMT_START = '<BBI'
FMT_RESET = '<BB'
FMT_AGG = '<BBIH%db' % (N * M)
LEN_BEACON = struct.calcsize(FMT_BEACON)
LEN_START = struct.calcsize(FMT_START)
LEN_RESET = struct.calcsize(FMT_RESET)


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


class Node:
    def __init__(self, e):
        self.e = e
        self.agg = [0] * (N * M)
        self.t0 = time.ticks_ms()
        self.seq = 0
        self.started = False
        self.last_reset = self.t0
        self.start_left = 0
        self.next_start = self.t0

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
        if n == LEN_RESET:
            if not IS_GW or m != GS_MAC_B:
                return
            v = struct.unpack(FMT_RESET, msg)
            if v[0] != MAGIC or v[1] != T_RESET:
                return
            self.begin_start_burst()
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
            if v[0] != MAGIC or v[1] != T_START or sid != GW or IS_GW:
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
        if IS_GW:
            self.send_start()
        self.update_own()
        t = self.now() & 0xFFFFFFFF
        b = ME * M
        own = self.agg[b:b + M]
        self.send(struct.pack(FMT_BEACON, MAGIC, T_BEACON, ME, self.seq, t, *own))
        if IS_GW:
            self.send(struct.pack(FMT_AGG, MAGIC, T_AGG, t, self.seq, *self.agg))
        print(' '.join(['%s:%d' % (COLS[i], self.agg[i]) for i in range(N * M)]))
        self.seq = (self.seq + 1) & 0xFFFF


def main():
    e = setup_espnow()
    node = Node(e)
    next_tx = time.ticks_ms()
    while True:
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


main()
