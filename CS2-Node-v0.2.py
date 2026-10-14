import network
import espnow
import struct
import time
import gc

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
PRESENCE_INTERVAL_MS = 100
CYCLE_MS = 1000
DETECT_WINDOW_MS = 800
DETECT_COUNT = 8
CYCLE_LOST_MS = 1500
CYCLE_SWITCH_MS = 800
IDLE_WAIT_MS = 100
RX_BUF = 4096
SEND_TRIES = 3
SEND_RETRY_MS = 2

MAGIC = 0x53
T_PRESENCE = 0x11
T_CYCLE = 0x12
T_DETECT = 0x13
T_REPORT = 0x14
T_ASSIGN = 0x15
BCAST = b'\xff' * 6

N = len(NODES)
M = N - 1
ME = NODES.index(NODE_ID)
OTHERS = [[j for j in range(N) if j != i] for i in range(N)]
MAC_OF = [bytes([int(x, 16) for x in MACS[c].split(':')]) for c in NODES]
ID_OF = {mac: i for i, mac in enumerate(MAC_OF)}
GS_MAC_B = bytes([int(x, 16) for x in GS_MAC.split(':')])
SLOT_MS = DETECT_WINDOW_MS // DETECT_COUNT
OFFSET_MS = ME * (SLOT_MS // 4)

FMT_PRESENCE = '<BBBH'
FMT_CYCLE = '<BBBH'
FMT_DETECT = '<BBBHB'
FMT_REPORT = '<BBBH%db' % (M * DETECT_COUNT)
FMT_ASSIGN = '<BBB'
LEN_PRESENCE = struct.calcsize(FMT_PRESENCE)
LEN_CYCLE = struct.calcsize(FMT_CYCLE)
LEN_DETECT = struct.calcsize(FMT_DETECT)
LEN_ASSIGN = struct.calcsize(FMT_ASSIGN)


def setup_espnow():
    sta = network.WLAN(network.STA_IF)
    sta.active(True)
    sta.disconnect()
    sta.config(channel=CHANNEL)
    sta.config(pm=sta.PM_NONE)
    e = espnow.ESPNow()
    e.config(rxbuf=RX_BUF)
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


def newer(a, b):
    return ((a - b) & 0xFFFF) < 0x8000


class Node:
    def __init__(self, e):
        self.e = e
        self.gw = None
        self.assigned = False
        self.pseq = 0
        self.next_presence = time.ticks_ms()
        self.cycle = None
        self.max_cycle = None
        self.last_cycle_rx = None
        self.next_cycle = 0
        self.next_cycle_at = time.ticks_ms()
        self.plan = []
        self.rec = [[0] * DETECT_COUNT for _ in range(M)]

    def push(self, mac, pkt):
        for k in range(SEND_TRIES):
            try:
                self.e.send(mac, pkt, False)
                return
            except OSError:
                if k + 1 < SEND_TRIES:
                    time.sleep_ms(SEND_RETRY_MS)

    def send(self, pkt):
        self.push(BCAST, pkt)
        if self.gw == ME:
            self.forward(pkt)

    def forward(self, pkt):
        self.push(GS_MAC_B, pkt)

    def set_gw(self, gid):
        self.assigned = True
        if gid == self.gw:
            return
        self.gw = gid
        if gid != ME:
            return
        now = time.ticks_ms()
        if self.max_cycle is None:
            self.next_cycle = 0
            self.next_cycle_at = now
        else:
            self.next_cycle = (self.max_cycle + 1) & 0xFFFF
            self.next_cycle_at = time.ticks_add(self.last_cycle_rx, CYCLE_MS)
            if time.ticks_diff(self.next_cycle_at, now) < 0:
                self.next_cycle_at = now

    def note_cycle(self, c, at):
        if self.max_cycle is None or newer(c, self.max_cycle):
            self.max_cycle = c
        self.last_cycle_rx = at

    def begin_cycle(self, c, t0):
        if self.plan and self.plan[-1][1] == 'R':
            self.send_report()
        self.cycle = c
        self.rec = [[0] * DETECT_COUNT for _ in range(M)]
        self.plan = [(time.ticks_add(t0, k * SLOT_MS + OFFSET_MS), 'D', k) for k in range(DETECT_COUNT)]
        self.plan.append((time.ticks_add(t0, DETECT_WINDOW_MS + OFFSET_MS), 'R', 0))

    def on_cycle(self, sid, c):
        now = time.ticks_ms()
        if self.gw == ME:
            self.note_cycle(c, now)
            return
        if sid != self.gw:
            age = CYCLE_LOST_MS + 1 if self.last_cycle_rx is None else time.ticks_diff(now, self.last_cycle_rx)
            ahead = self.max_cycle is None or (c != self.max_cycle and newer(c, self.max_cycle))
            if self.gw is not None and age <= CYCLE_LOST_MS and (self.assigned or not (ahead and age >= CYCLE_SWITCH_MS)):
                return
            self.gw = sid
        self.note_cycle(c, now)
        self.begin_cycle(c, now)

    def on_recv(self, mac, msg):
        m = bytes(mac)
        n = len(msg)
        if m == GS_MAC_B:
            if n == LEN_ASSIGN:
                v = struct.unpack(FMT_ASSIGN, msg)
                if v[0] == MAGIC and v[1] == T_ASSIGN and v[2] < N:
                    self.set_gw(v[2])
            return
        sid = ID_OF.get(m)
        if sid is None or sid == ME:
            return
        if self.gw == ME:
            self.forward(msg)
        if n < 2 or msg[0] != MAGIC:
            return
        if msg[1] == T_CYCLE and n == LEN_CYCLE:
            v = struct.unpack(FMT_CYCLE, msg)
            if v[2] == sid:
                self.on_cycle(sid, v[3])
        elif msg[1] == T_DETECT and n == LEN_DETECT:
            v = struct.unpack(FMT_DETECT, msg)
            if v[2] != sid or v[3] != self.cycle or v[4] >= DETECT_COUNT:
                return
            p = self.e.peers_table.get(m)
            if p is not None:
                self.rec[OTHERS[ME].index(sid)][v[4]] = p[0]

    def send_cycle(self):
        c = self.next_cycle
        self.send(struct.pack(FMT_CYCLE, MAGIC, T_CYCLE, ME, c))
        now = time.ticks_ms()
        self.note_cycle(c, now)
        self.begin_cycle(c, now)
        self.next_cycle = (c + 1) & 0xFFFF
        self.next_cycle_at = time.ticks_add(self.next_cycle_at, CYCLE_MS)
        if time.ticks_diff(now, self.next_cycle_at) >= 0:
            self.next_cycle_at = time.ticks_add(now, CYCLE_MS)

    def send_report(self):
        vals = []
        for row in self.rec:
            vals.extend(row)
        self.send(struct.pack(FMT_REPORT, MAGIC, T_REPORT, ME, self.cycle, *vals))
        got = ['%s:%d/%d' % (NODES[j], len([x for x in self.rec[k] if x != 0]), DETECT_COUNT) for k, j in enumerate(OTHERS[ME])]
        gw = '-' if self.gw is None else NODES[self.gw]
        print('cycle:%d GW:%s %s' % (self.cycle, gw, ' '.join(got)))

    def due(self):
        times = []
        if self.gw is None:
            times.append(self.next_presence)
        if self.gw == ME:
            times.append(self.next_cycle_at)
        if self.plan:
            times.append(self.plan[0][0])
        if not times:
            return IDLE_WAIT_MS
        now = time.ticks_ms()
        return max(0, min([time.ticks_diff(t, now) for t in times]))

    def run(self):
        now = time.ticks_ms()
        if self.gw is None and time.ticks_diff(now, self.next_presence) >= 0:
            self.send(struct.pack(FMT_PRESENCE, MAGIC, T_PRESENCE, ME, self.pseq))
            self.pseq = (self.pseq + 1) & 0xFFFF
            self.next_presence = time.ticks_add(self.next_presence, PRESENCE_INTERVAL_MS)
            if time.ticks_diff(now, self.next_presence) >= 0:
                self.next_presence = time.ticks_add(now, PRESENCE_INTERVAL_MS)
        if self.gw == ME and time.ticks_diff(now, self.next_cycle_at) >= 0:
            self.send_cycle()
        while self.plan and time.ticks_diff(time.ticks_ms(), self.plan[0][0]) >= 0:
            at, what, k = self.plan.pop(0)
            if what == 'D':
                self.send(struct.pack(FMT_DETECT, MAGIC, T_DETECT, ME, self.cycle, k))
            else:
                self.send_report()
                gc.collect()


def main():
    e = setup_espnow()
    node = Node(e)
    while True:
        wait = node.due()
        if wait > 0:
            mac, msg = e.recv(wait)
            if msg:
                node.on_recv(mac, msg)
            continue
        node.run()


main()
