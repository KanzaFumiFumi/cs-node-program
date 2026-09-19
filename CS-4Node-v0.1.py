import network
import espnow
import struct
import time
import os

NODE_ID = 'A'

MACS = {
    'A': '00:00:00:00:00:00',
    'B': '00:00:00:00:00:00',
    'C': '00:00:00:00:00:00',
    'D': '00:00:00:00:00:00',
}

NODES = 'ABCD'
GW_ID = 'A'
CHANNEL = 6
TX_INTERVAL_MS = 100
START_DELAY_MS = 30000
START_INTERVAL_MS = 1000
START_REPEAT = 10
FLUSH_ROWS = 10
MIN_FREE_BYTES = 16 * 1024
LOG_ENABLE = False

MAGIC = 0x52
T_BEACON = 0x01
T_START = 0x02
FMT_BEACON = '<BBBHI3b'
FMT_START = '<BBI'
LEN_BEACON = struct.calcsize(FMT_BEACON)
LEN_START = struct.calcsize(FMT_START)
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


class Logger:
    def __init__(self):
        names = os.listdir()
        n = 0
        while '%s_%03d.csv' % (NODE_ID, n) in names:
            n += 1
        self.name = '%s_%03d.csv' % (NODE_ID, n)
        self.buf = []
        self.f = None
        if not LOG_ENABLE:
            return
        if free_bytes() < MIN_FREE_BYTES:
            print('LOG OFF: low flash space')
            return
        self.f = open(self.name, 'w')
        self.f.write('t_ms,seq,' + ','.join(COLS) + '\n')
        self.f.flush()

    def add(self, line):
        if self.f is None:
            return
        self.buf.append(line)
        if len(self.buf) >= FLUSH_ROWS:
            self.flush()

    def flush(self):
        if self.f is None or not self.buf:
            return
        try:
            self.f.write(''.join(self.buf))
            self.f.flush()
        except OSError:
            print('LOG OFF: write error')
            self.close()
        self.buf = []
        if self.f is not None and free_bytes() < MIN_FREE_BYTES:
            print('LOG OFF: low flash space')
            self.close()

    def close(self):
        if self.f is None:
            return
        try:
            self.f.close()
        except OSError:
            pass
        self.f = None


class Node:
    def __init__(self, e, log):
        self.e = e
        self.log = log
        self.agg = [0] * (N * M)
        self.t0 = time.ticks_ms()
        self.seq = 0
        self.started = False
        self.start_sent = 0
        self.next_start = time.ticks_add(self.t0, START_DELAY_MS)

    def now(self):
        return time.ticks_diff(time.ticks_ms(), self.t0)

    def reset(self):
        self.t0 = time.ticks_ms()
        self.seq = 0
        self.started = True

    def send(self, pkt):
        try:
            self.e.send(BCAST, pkt, False)
        except OSError:
            pass

    def on_recv(self, mac, msg):
        sid = ID_OF.get(bytes(mac))
        if sid is None or sid == ME:
            return
        n = len(msg)
        if n == LEN_BEACON:
            v = struct.unpack(FMT_BEACON, msg)
            if v[0] != MAGIC or v[1] != T_BEACON or v[2] != sid:
                return
            b = sid * M
            for k in range(M):
                self.agg[b + k] = v[5 + k]
        elif n == LEN_START:
            v = struct.unpack(FMT_START, msg)
            if v[0] != MAGIC or v[1] != T_START or sid != GW:
                return
            if not IS_GW and not self.started:
                self.reset()

    def update_own(self):
        pt = self.e.peers_table
        b = ME * M
        for k, j in enumerate(OTHERS[ME]):
            p = pt.get(MAC_OF[j])
            if p is not None:
                self.agg[b + k] = p[0]

    def maybe_start(self):
        if not IS_GW or self.start_sent >= START_REPEAT:
            return
        if time.ticks_diff(time.ticks_ms(), self.next_start) < 0:
            return
        if not self.started:
            self.reset()
        self.send(struct.pack(FMT_START, MAGIC, T_START, self.now() & 0xFFFFFFFF))
        self.start_sent += 1
        self.next_start = time.ticks_add(self.next_start, START_INTERVAL_MS)

    def tick(self):
        self.maybe_start()
        self.update_own()
        t = self.now() & 0xFFFFFFFF
        b = ME * M
        own = self.agg[b:b + M]
        self.send(struct.pack(FMT_BEACON, MAGIC, T_BEACON, ME, self.seq, t, *own))
        self.log.add('%d,%d,%s\n' % (t, self.seq, ','.join([str(x) for x in self.agg])))
        print(' '.join(['%s:%d' % (COLS[i], self.agg[i]) for i in range(N * M)]))
        self.seq = (self.seq + 1) & 0xFFFF


def main():
    e = setup_espnow()
    log = Logger()
    node = Node(e, log)
    print('NODE', NODE_ID, 'GW' if IS_GW else '', 'LOG', log.name if log.f else 'OFF')
    next_tx = time.ticks_ms()
    try:
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
    finally:
        log.flush()
        log.close()


main()
