import network
import espnow
import struct
import sys
import select
import time
import os
import machine
import binascii

MACS = {
    'A': '00:00:00:00:00:00',
    'B': '00:00:00:00:00:00',
    'C': '00:00:00:00:00:00',
    'D': '00:00:00:00:00:00',
}

# ---- 害獣検知の表示（ここを書き換える） ----
# 表示する区間：12個の値の行の後ろに、この順で区間ごとの状態を付ける。
ALERT_SECTIONS = ['A-B', 'A-C', 'A-D', 'B-C', 'B-D', 'C-D']
# 表示時間 [ms]：その区間で通過を検知してから、この時間「害獣を検知」と表示する。新しく検知したら、そこから数え直す。
ALERT_MS = 5000

# ---- 通過の判定の値（実験に合わせてここを書き換える） ----
# 地上局が0.1秒ごとに、GW 経由で届いた最新の12個の値で、6区間を往復2方向ずつ判定する。
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
RECV_TIMEOUT_MS = 50
RX_BUF = 8192
MEASURE_MS = 10000
MEASURE_SHOW_MS = 100
RESULT_HOLD_MS = 5000
ASSIGN_INTERVAL_MS = 100
ASSIGN_KEEP_MS = 1000
FWD_TIMEOUT_MS = 3000
FLUSH_MS = 1000
JUDGE_MS = 100
PASS_X_MS = round(PASS_X_S * 1000)
PASS_Y_MS = round(PASS_Y_S * 1000)

SD_MOUNT = '/sd'
SD_SLOT = 2
SD_SCK = 8
SD_MISO = 9
SD_MOSI = 10
SD_CS = 4
SD_FREQ = 1000000
ERR_NODEV = 19
ERR_NOSPC = 28

START_CODE = 0x02
RESET_CODE = 0xFF
GW_NONE = 7
BCAST = b'\xff' * 6

N = len(NODES)
M = N - 1
OTHERS = [[j for j in range(N) if j != i] for i in range(N)]
COLS = ['%s->%s' % (NODES[i], NODES[j]) for i in range(N) for j in OTHERS[i]]
RAW_NAMES = [c for c in NODES] + ['GS']
RAW_HEAD = ['time_ms', 'gw', 'gs_rssi', 'type', 'len', 'hex', 'node_gw']
RAW_COLS = [RAW_HEAD + COLS[i * M:(i + 1) * M] for i in range(N)] + [RAW_HEAD + ['rssi_%d' % (k + 1) for k in range(M)]]
EMPTY = [''] * (1 + M)
MAC_OF = [bytes([int(x, 16) for x in MACS[c].split(':')]) for c in NODES]
ID_OF = {mac: i for i, mac in enumerate(MAC_OF)}
ALERT_PAIRS = [sorted([NODES.index(c) for c in s.split('-')]) for s in ALERT_SECTIONS]
SECTIONS = [(i, j) for i in range(N) for j in range(i + 1, N)]
SEC_DIRS = [(i * M + OTHERS[i].index(j), j * M + OTHERS[j].index(i)) for i, j in SECTIONS]
SEC_NAMES = ['%s-%s' % (NODES[i], NODES[j]) for i, j in SECTIONS]
PASS_HEAD = 'time_s,time_ms,gw,section,rssi_1,base_1,hit_1,rssi_2,base_2,hit_2'

FMT_BEACON = '<B%db' % M
LEN_BEACON = struct.calcsize(FMT_BEACON)


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
    return e


def err_no(e):
    return e.args[0] if e.args else None


def log_names(n):
    return ['GS_%03d.csv' % n] + ['GS_%03d_%s.csv' % (n, s) for s in RAW_NAMES] + ['GS_%03d_PASS.csv' % n]


def decode(msg):
    n = len(msg)
    if n == LEN_BEACON:
        v = struct.unpack(FMT_BEACON, msg)
        h = v[0]
        g = (h >> 2) & 7
        if not h >> 5 and (g < N or g == GW_NONE):
            return h & 3, 'BEACON', v
    elif n == 1 and msg[0] == START_CODE:
        return None, 'START', None
    return None, '?', None


def fields(kind, v):
    if kind == 'BEACON':
        g = (v[0] >> 2) & 7
        return [NODES[g] if g < N else '-'] + [str(x) for x in v[1:1 + M]]
    return EMPTY


def base_text(hit, base):
    return '' if hit is None else '%.1f' % base


def hit_text(hit):
    return '' if hit is None else ('1' if hit else '0')


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


class Station:
    def __init__(self, e):
        self.e = e
        self.gw = None
        self.last_fwd = None
        self.other_fwd = False
        self.last_assign = time.ticks_add(time.ticks_ms(), -ASSIGN_KEEP_MS)
        self.measuring = False
        self.meas_end = time.ticks_ms()
        self.next_show = time.ticks_ms()
        self.holding = False
        self.hold_end = time.ticks_ms()
        self.sums = [0] * N
        self.counts = [0] * N
        self.latest = [0] * N
        self.vals = [0] * (N * M)
        self.f = None
        self.raw = []
        self.log_t0 = time.ticks_ms()
        self.last_flush = time.ticks_ms()
        self.sd = None
        self.sd_ok = False
        self.alert_at = [None] * len(ALERT_SECTIONS)
        self.refs = [Ref() for _ in range(N * M)]
        self.pass_at = [None] * len(SECTIONS)
        self.next_judge = time.ticks_ms()
        self.pf = None

    def send(self, pkt):
        try:
            self.e.send(BCAST, pkt, False)
        except OSError:
            pass

    def on_command(self, line):
        t = time.ticks_ms()
        cmd = line.strip().lower()
        if cmd == 'r':
            if self.gw is not None:
                pkt = bytes([RESET_CODE])
                self.send(pkt)
                self.start_log(t)
                self.raw_row(N, '', 'RESET', pkt, EMPTY, t)
        elif cmd == 'g':
            if not self.measuring:
                self.start_measure()

    def mount_sd(self):
        if self.sd_ok:
            try:
                os.listdir(SD_MOUNT)
                return None
            except OSError:
                self.unmount_sd()
        try:
            self.sd = machine.SDCard(slot=SD_SLOT, width=1, sck=machine.Pin(SD_SCK), miso=machine.Pin(SD_MISO), mosi=machine.Pin(SD_MOSI), cs=machine.Pin(SD_CS), freq=SD_FREQ)
            self.sd.info()
        except Exception:
            self.unmount_sd()
            return 'LOG OFF: no SD card'
        try:
            os.mount(self.sd, SD_MOUNT)
        except Exception as e:
            self.unmount_sd()
            if err_no(e) == ERR_NODEV:
                return 'LOG OFF: SD not FAT32'
            return 'LOG OFF: no SD card'
        self.sd_ok = True
        return None

    def unmount_sd(self):
        try:
            os.umount(SD_MOUNT)
        except Exception:
            pass
        if self.sd is not None:
            try:
                self.sd.deinit()
            except Exception:
                pass
        self.sd = None
        self.sd_ok = False

    def start_log(self, t0):
        self.close_log()
        if not hasattr(machine, 'SDCard'):
            print('LOG OFF: SDCard not supported')
            return
        msg = self.mount_sd()
        if msg:
            print(msg)
            return
        try:
            names = os.listdir(SD_MOUNT)
            n = 0
            while [s for s in log_names(n) if s in names]:
                n += 1
            files = log_names(n)
            self.f = open('%s/%s' % (SD_MOUNT, files[0]), 'w')
            self.f.write('time_s,gw,' + ','.join(COLS) + '\n')
            for i in range(N + 1):
                self.raw.append(open('%s/%s' % (SD_MOUNT, files[i + 1]), 'w'))
                self.raw[i].write(','.join(RAW_COLS[i]) + '\n')
            self.pf = open('%s/%s' % (SD_MOUNT, files[-1]), 'w')
            self.pf.write(PASS_HEAD + '\n')
            self.f.flush()
            for g in self.raw:
                g.flush()
            self.pf.flush()
        except OSError as e:
            self.log_fail(e)
            return
        self.log_t0 = t0
        self.last_flush = time.ticks_ms()

    def log_fail(self, e):
        print('LOG OFF: SD full' if err_no(e) == ERR_NOSPC else 'LOG OFF: write error')
        self.close_log()
        self.unmount_sd()

    def write(self, f, s):
        try:
            f.write(s)
        except OSError as e:
            self.log_fail(e)

    def flush_log(self):
        if self.f is None:
            return
        if time.ticks_diff(time.ticks_ms(), self.last_flush) < FLUSH_MS:
            return
        self.last_flush = time.ticks_ms()
        try:
            self.f.flush()
            for g in self.raw:
                g.flush()
            if self.pf is not None:
                self.pf.flush()
        except OSError as e:
            self.log_fail(e)

    def log_row(self, sid, vals):
        if self.f is None:
            return
        d = (time.ticks_diff(time.ticks_ms(), self.log_t0) + 50) // 100
        self.write(self.f, '%d.%d,%s,%s\n' % (d // 10, d % 10, NODES[sid], ','.join([str(x) for x in vals])))

    def raw_row(self, idx, rssi, kind, pkt, extra, at=None):
        if self.f is None:
            return
        if at is None:
            at = time.ticks_ms()
        gw = '-' if self.gw is None else NODES[self.gw]
        hexs = binascii.hexlify(pkt).decode().upper()
        self.write(self.raw[idx], '%d,%s,%s,%s,%d,%s,%s\n' % (time.ticks_diff(at, self.log_t0), gw, rssi, kind, len(pkt), hexs, ','.join(extra)))

    def pass_row(self, now, k, hf, bf, hr, br):
        if self.pf is None:
            return
        f, r = SEC_DIRS[k]
        t = time.ticks_diff(now, self.log_t0)
        d = (t + 50) // 100
        gw = '-' if self.gw is None else NODES[self.gw]
        self.write(self.pf, '%d.%d,%d,%s,%s,%d,%s,%s,%d,%s,%s\n' % (d // 10, d % 10, t, gw, SEC_NAMES[k], self.vals[f], base_text(hf, bf), hit_text(hf), self.vals[r], base_text(hr, br), hit_text(hr)))

    def close_log(self):
        for g in [self.f, self.pf] + self.raw:
            if g is None:
                continue
            try:
                g.close()
            except OSError:
                pass
        self.f = None
        self.pf = None
        self.raw = []

    def start_measure(self):
        self.measuring = True
        self.holding = False
        self.meas_end = time.ticks_add(time.ticks_ms(), MEASURE_MS)
        self.next_show = time.ticks_ms()
        self.sums = [0] * N
        self.counts = [0] * N
        self.latest = [0] * N

    def finish_measure(self):
        avgs = [self.sums[i] / self.counts[i] if self.counts[i] else None for i in range(N)]
        best = None
        for i in range(N):
            if avgs[i] is not None and (best is None or avgs[i] > avgs[best]):
                best = i
        if best is None:
            self.start_measure()
            return
        self.measuring = False
        vals = ['%s:%s' % (NODES[i], '--' if avgs[i] is None else '%.1f' % avgs[i]) for i in range(N)]
        print('GW:%s %s' % (NODES[best], ' '.join(vals)))
        self.holding = True
        self.hold_end = time.ticks_add(time.ticks_ms(), RESULT_HOLD_MS)
        self.gw = best
        self.last_fwd = None
        self.other_fwd = False
        self.last_assign = time.ticks_add(time.ticks_ms(), -ASSIGN_KEEP_MS)

    def show_measure(self):
        if time.ticks_diff(time.ticks_ms(), self.next_show) < 0:
            return
        print(' '.join(['%s:%d' % (NODES[i], self.latest[i]) for i in range(N)]))
        self.next_show = time.ticks_add(self.next_show, MEASURE_SHOW_MS)
        if time.ticks_diff(time.ticks_ms(), self.next_show) > MEASURE_SHOW_MS:
            self.next_show = time.ticks_add(time.ticks_ms(), MEASURE_SHOW_MS)

    def judge(self):
        if time.ticks_diff(time.ticks_ms(), self.next_judge) < 0:
            return
        self.next_judge = time.ticks_add(self.next_judge, JUDGE_MS)
        if time.ticks_diff(time.ticks_ms(), self.next_judge) > JUDGE_MS:
            self.next_judge = time.ticks_add(time.ticks_ms(), JUDGE_MS)
        now = time.ticks_ms()
        res = [self.refs[d].judge(now, self.vals[d]) for d in range(N * M)]
        for k in range(len(SECTIONS)):
            f, r = SEC_DIRS[k]
            hf, bf = res[f]
            hr, br = res[r]
            if self.pass_at[k] is not None and time.ticks_diff(now, self.pass_at[k]) >= PASS_Y_MS:
                self.pass_at[k] = None
            on = (hf or hr) if PASS_RULE == 'one' else (hf and hr)
            if on and self.pass_at[k] is None:
                self.pass_at[k] = now
                for i, p in enumerate(ALERT_PAIRS):
                    if p == list(SECTIONS[k]):
                        self.alert_at[i] = now
                self.pass_row(now, k, hf, bf, hr, br)

    def alert_text(self):
        now = time.ticks_ms()
        out = ''
        for i, s in enumerate(ALERT_SECTIONS):
            a = self.alert_at[i]
            if a is not None and time.ticks_diff(now, a) >= ALERT_MS:
                self.alert_at[i] = None
            out += '｜%s %s' % (s, '―' if self.alert_at[i] is None else '害獣を検知')
        return ' ' + out

    def on_recv(self, mac, msg):
        m = bytes(mac)
        sid = ID_OF.get(m)
        if sid is None:
            return
        msg = bytes(msg)
        origin, kind, v = decode(msg)
        if self.measuring and kind == 'BEACON' and origin == sid:
            p = self.e.peers_table.get(m)
            if p is not None:
                self.sums[sid] += p[0]
                self.counts[sid] += 1
                self.latest[sid] = p[0]
        if sid != self.gw:
            if self.gw is not None and origin is not None and origin != sid:
                self.other_fwd = True
            return
        if origin is not None and origin != sid:
            self.last_fwd = time.ticks_ms()
        p = self.e.peers_table.get(m)
        self.raw_row(sid if origin is None else origin, '' if p is None else str(p[0]), kind, msg, fields(kind, v))
        if kind == 'BEACON':
            b = origin * M
            for k in range(M):
                self.vals[b + k] = v[1 + k]
            self.log_row(sid, self.vals)
            if self.measuring or self.holding:
                return
            print(' '.join(['%s:%d' % (COLS[i], self.vals[i]) for i in range(N * M)]) + self.alert_text())

    def need_assign(self):
        if self.other_fwd or self.last_fwd is None:
            return True
        return time.ticks_diff(time.ticks_ms(), self.last_fwd) >= FWD_TIMEOUT_MS

    def update(self):
        self.judge()
        if self.measuring and time.ticks_diff(time.ticks_ms(), self.meas_end) >= 0:
            self.finish_measure()
        if self.measuring:
            self.show_measure()
        if self.holding and time.ticks_diff(time.ticks_ms(), self.hold_end) >= 0:
            self.holding = False
        self.flush_log()
        if self.gw is None:
            return
        gap = ASSIGN_INTERVAL_MS if self.need_assign() else ASSIGN_KEEP_MS
        if time.ticks_diff(time.ticks_ms(), self.last_assign) < gap:
            return
        pkt = bytes([self.gw])
        self.send(pkt)
        self.raw_row(N, '', 'ASSIGN', pkt, EMPTY)
        self.other_fwd = False
        self.last_assign = time.ticks_ms()


def main():
    e = setup_espnow()
    st = Station(e)
    keys = select.poll()
    keys.register(sys.stdin, select.POLLIN)
    try:
        while True:
            if keys.poll(0):
                st.on_command(sys.stdin.readline())
            mac, msg = e.recv(RECV_TIMEOUT_MS)
            if msg:
                st.on_recv(mac, msg)
            st.update()
    finally:
        st.close_log()


main()
