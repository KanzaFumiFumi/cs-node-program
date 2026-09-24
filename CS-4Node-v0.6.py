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

# ---- 熊検知の値（実験に合わせてここを書き換える） ----
# 閾値 [dB]：落ち込み量（平常値 − 受信強度）がこの値以上なら遮蔽とみなす。区間の往復2方向がどちらも超えたときだけ遮蔽。
# 静置時の揺れより大きく、通過時の落ち込みより小さくする。仮の値（9/17 の静置データでは揺れは最大約6dB）。
BEAR_THRESHOLD_DB = 6
# 最短持続時間 [ms]：遮蔽がこの長さ以上続いてから終わったときだけ「通過1回」として速報する。
# ノイズによる短い反応より長く、通過時の遮蔽より短くする。仮の値（0.5秒＝判定5回分）。
BEAR_MIN_MS = 500
# 追従の時定数 [ms]：非遮蔽のとき、平常値をこの時間で受信強度の方へ約63%寄せる（遮蔽中は寄せない）。
# 通過時間よりゆっくり、環境のゆっくりした変化には追いつく長さにする。
BEAR_TAU_MS = 30000
# 平常値の学習時間 [ms]：起動直後と作り直しのとき、この間の受信強度の平均を平常値にする。この間は判定しない。
BEAR_LEARN_MS = 3000
# 最長遮蔽時間 [ms]：遮蔽がこれより長く続いたら環境の変化とみなし、速報せずに平常値を作り直す。
BEAR_MAX_MS = 30000
# 速報の送信回数：取りこぼし対策として、同じ速報を100msごとにこの回数送る（GW はその1回ずつを無変更で GS へ転送する）。
BEAR_REPEAT = 3

MAGIC = 0x52
T_BEACON = 0x01
T_START = 0x02
T_RESET = 0x03
T_ASSIGN = 0x05
T_BEAR = 0x06
BCAST = b'\xff' * 6

N = len(NODES)
M = N - 1
ME = NODES.index(NODE_ID)
OTHERS = [[j for j in range(N) if j != i] for i in range(N)]
COLS = ['%s->%s' % (NODES[i], NODES[j]) for i in range(N) for j in OTHERS[i]]
MAC_OF = [bytes([int(x, 16) for x in MACS[c].split(':')]) for c in NODES]
ID_OF = {mac: i for i, mac in enumerate(MAC_OF)}
GS_MAC_B = bytes([int(x, 16) for x in GS_MAC.split(':')])
REV_IDX = [j * M + OTHERS[j].index(ME) for j in OTHERS[ME]]
BEAR_ALPHA = TX_INTERVAL_MS / BEAR_TAU_MS

FMT_BEACON = '<BBBHI%dbB' % M
FMT_START = '<BBI'
FMT_RESET = '<BB'
FMT_ASSIGN = '<BBB'
FMT_BEAR = '<BBBBBHHB'
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
        self.b_ready = [False] * M
        self.b_n = [0] * M
        self.b_t0 = [0] * M
        self.b_sf = [0] * M
        self.b_sr = [0] * M
        self.base_f = [0.0] * M
        self.base_r = [0.0] * M
        self.shaded = [False] * M
        self.sh_t0 = [0] * M
        self.sh_mf = [0.0] * M
        self.sh_mr = [0.0] * M
        self.rid = 0
        self.bear_out = []

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

    def bear_learn(self, k, f, r, now):
        if self.b_n[k] == 0:
            self.b_t0[k] = now
            self.b_sf[k] = 0
            self.b_sr[k] = 0
        self.b_sf[k] += f
        self.b_sr[k] += r
        self.b_n[k] += 1
        if time.ticks_diff(now, self.b_t0[k]) >= BEAR_LEARN_MS:
            self.base_f[k] = self.b_sf[k] / self.b_n[k]
            self.base_r[k] = self.b_sr[k] / self.b_n[k]
            self.b_ready[k] = True
            self.b_n[k] = 0

    def bear_detect(self):
        now = time.ticks_ms()
        for k, j in enumerate(OTHERS[ME]):
            f = self.agg[ME * M + k]
            r = self.agg[REV_IDX[k]]
            if f == 0 or r == 0:
                continue
            if not self.b_ready[k]:
                self.bear_learn(k, f, r, now)
                continue
            df = self.base_f[k] - f
            dr = self.base_r[k] - r
            if df >= BEAR_THRESHOLD_DB and dr >= BEAR_THRESHOLD_DB:
                if not self.shaded[k]:
                    self.shaded[k] = True
                    self.sh_t0[k] = now
                    self.sh_mf[k] = df
                    self.sh_mr[k] = dr
                else:
                    self.sh_mf[k] = max(self.sh_mf[k], df)
                    self.sh_mr[k] = max(self.sh_mr[k], dr)
                if time.ticks_diff(now, self.sh_t0[k]) > BEAR_MAX_MS:
                    self.shaded[k] = False
                    self.b_ready[k] = False
                    self.b_n[k] = 0
                continue
            if self.shaded[k]:
                self.shaded[k] = False
                length = time.ticks_diff(now, self.sh_t0[k])
                if length >= BEAR_MIN_MS:
                    self.bear_report(j, self.sh_t0[k], length, min(self.sh_mf[k], self.sh_mr[k]))
            self.base_f[k] += BEAR_ALPHA * (f - self.base_f[k])
            self.base_r[k] += BEAR_ALPHA * (r - self.base_r[k])

    def bear_report(self, j, t0, length, drop):
        self.rid = (self.rid + 1) & 0xFF
        length = min(length, 0xFFFF)
        drop = max(0, min(255, int(drop + 0.5)))
        self.bear_out.append([ME, self.rid, j, t0, length, drop, BEAR_REPEAT])

    def send_bears(self):
        if not self.bear_out:
            return
        now = time.ticks_ms()
        for it in self.bear_out:
            age = max(0, min(time.ticks_diff(now, it[3]), 0xFFFF))
            self.send(struct.pack(FMT_BEAR, MAGIC, T_BEAR, it[0], it[1], it[2], age, it[4], it[5]))
            it[6] -= 1
        self.bear_out = [it for it in self.bear_out if it[6] > 0]

    def tick(self):
        is_gw = self.gw == ME
        if is_gw:
            self.send_start()
        self.update_own()
        self.bear_detect()
        t = self.now() & 0xFFFFFFFF
        b = ME * M
        own = self.agg[b:b + M]
        self.send(struct.pack(FMT_BEACON, MAGIC, T_BEACON, ME, self.seq, t, *(own + [0xFF if self.gw is None else self.gw])))
        self.send_bears()
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
