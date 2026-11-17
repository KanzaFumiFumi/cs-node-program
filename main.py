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

# ---- 通過速報の値（実験に合わせてここを書き換える） ----
# 基準値の時間 X [秒]：基準値は、その方向の直前この秒数の RSSI の平均（今の値と未受信の0は含めない）。
# その方向を最初に受信してからこの秒数たつまでは判定しない。
PASS_X_S = 10
# 通過1回の時間 Y [秒]：区間として最初に検知した時刻からこの秒数を通過1回とする。
# この秒数たった時点でまだ検知していれば、そこから2回目とする。
PASS_Y_S = 5
# 下側閾値 [dB]：RSSI ≦ 基準値 − この値 なら反応あり。
PASS_LO_DB = 2
# 上側閾値 [dB]：RSSI ≧ 基準値 ＋ この値 なら反応あり。
PASS_HI_DB = 2
# 判定ルール：'both' ＝ 2方向とも反応ありで検知、'one' ＝ 2方向のどちらかが反応ありで検知。
PASS_RULE = 'both'

NODES = 'ABCD'
CHANNEL = 6
TX_INTERVAL_MS = 100
START_INTERVAL_MS = 1000
START_REPEAT = 10
RESET_WINDOW_MS = START_INTERVAL_MS * START_REPEAT
MIN_FREE_BYTES = 16 * 1024
LOG_CHECK_ROWS = 10
PASS_REPEAT = 3
PASS_X_MS = round(PASS_X_S * 1000)
PASS_Y_MS = round(PASS_Y_S * 1000)

MAGIC = 0x52
T_BEACON = 0x01
T_START = 0x02
T_RESET = 0x03
T_ASSIGN = 0x05
T_PASS = 0x08
BCAST = b'\xff' * 6

N = len(NODES)
M = N - 1
ME = NODES.index(NODE_ID)
OTHERS = [[j for j in range(N) if j != i] for i in range(N)]
COLS = ['%s->%s' % (NODES[i], NODES[j]) for i in range(N) for j in OTHERS[i]]
MAC_OF = [bytes([int(x, 16) for x in MACS[c].split(':')]) for c in NODES]
ID_OF = {mac: i for i, mac in enumerate(MAC_OF)}
GS_MAC_B = bytes([int(x, 16) for x in GS_MAC.split(':')])
DIRS = [(ME * M + k, j * M + OTHERS[j].index(ME)) for k, j in enumerate(OTHERS[ME])]

FMT_BEACON = '<BBBHI%dbB' % M
FMT_START = '<BBI'
FMT_RESET = '<BB'
FMT_ASSIGN = '<BBB'
FMT_PASS = '<BBBBHIBbbhh'
LEN_BEACON = struct.calcsize(FMT_BEACON)
LEN_START = struct.calcsize(FMT_START)
LEN_RESET = struct.calcsize(FMT_RESET)
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
    try:
        e.add_peer(GS_MAC_B)
    except (OSError, ValueError):
        pass
    return e


def free_bytes():
    st = os.statvfs('/')
    return st[0] * st[3]


class Ref:
    def __init__(self):
        self.ts = []
        self.vals = []
        self.total = 0
        self.first = None
        self.ready = False

    def judge(self, now, v):
        while self.ts and time.ticks_diff(now, self.ts[0]) > PASS_X_MS:
            self.ts.pop(0)
            self.total -= self.vals.pop(0)
        if not self.ready and self.first is not None and time.ticks_diff(now, self.first) >= PASS_X_MS:
            self.ready = True
        hit = None
        base = 0
        if v != 0 and self.ready and self.ts:
            base = self.total / len(self.ts)
            hit = v <= base - PASS_LO_DB or v >= base + PASS_HI_DB
        if v != 0:
            self.ts.append(now)
            self.vals.append(v)
            self.total += v
            if self.first is None:
                self.first = now
        return hit, base


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
        self.refs = [Ref() for _ in range(2 * M)]
        self.pass_at = [None] * M
        self.pass_no = 0
        self.pass_out = []

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
        if self.gw == ME:
            self.forward(pkt)

    def forward(self, pkt):
        try:
            self.e.send(GS_MAC_B, pkt, False)
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
        if self.gw == ME:
            self.forward(msg)
        if n == LEN_BEACON:
            v = struct.unpack(FMT_BEACON, msg)
            if v[0] != MAGIC or v[1] != T_BEACON or v[2] != sid:
                return
            b = sid * M
            for k in range(M):
                self.agg[b + k] = v[5 + k]
            if v[5 + M] == sid and self.gw != ME:
                self.gw = sid
        elif n == LEN_START:
            v = struct.unpack(FMT_START, msg)
            if v[0] != MAGIC or v[1] != T_START or sid != self.gw:
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

    def judge_pass(self, t):
        now = time.ticks_ms()
        for k in range(M):
            f, r = DIRS[k]
            hf, bf = self.refs[2 * k].judge(now, self.agg[f])
            hr, br = self.refs[2 * k + 1].judge(now, self.agg[r])
            if self.pass_at[k] is not None and time.ticks_diff(now, self.pass_at[k]) >= PASS_Y_MS:
                self.pass_at[k] = None
            on = (hf or hr) if PASS_RULE == 'one' else (hf and hr)
            if on and self.pass_at[k] is None:
                self.pass_at[k] = now
                hit = (1 if hf else 0) | (2 if hr else 0)
                pkt = struct.pack(FMT_PASS, MAGIC, T_PASS, ME, OTHERS[ME][k], self.pass_no, t, hit, self.agg[f], self.agg[r], round(bf * 10), round(br * 10))
                self.pass_out.append([pkt, PASS_REPEAT])
                self.pass_no = (self.pass_no + 1) & 0xFFFF
        for p in self.pass_out:
            self.send(p[0])
            p[1] -= 1
        self.pass_out = [p for p in self.pass_out if p[1] > 0]

    def tick(self):
        is_gw = self.gw == ME
        if is_gw:
            self.send_start()
        self.update_own()
        t = self.now() & 0xFFFFFFFF
        self.judge_pass(t)
        b = ME * M
        own = self.agg[b:b + M]
        self.send(struct.pack(FMT_BEACON, MAGIC, T_BEACON, ME, self.seq, t, *(own + [0xFF if self.gw is None else self.gw])))
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
