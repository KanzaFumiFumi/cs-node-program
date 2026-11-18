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
# 表示時間 [ms]：その区間の通過速報を受けてから、この時間「害獣を検知」と表示する。新しい速報を受けたら、そこから数え直す。
ALERT_MS = 5000

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
DEDUP_MS = 1000
FLUSH_MS = 1000

SD_MOUNT = '/sd'
SD_SLOT = 2
SD_SCK = 8
SD_MISO = 9
SD_MOSI = 10
SD_CS = 4
SD_FREQ = 1000000
ERR_NODEV = 19
ERR_NOSPC = 28

MAGIC = 0x52
T_BEACON = 0x01
T_START = 0x02
T_RESET = 0x03
T_ASSIGN = 0x05
T_PASS = 0x08
BCAST = b'\xff' * 6

N = len(NODES)
M = N - 1
OTHERS = [[j for j in range(N) if j != i] for i in range(N)]
COLS = ['%s->%s' % (NODES[i], NODES[j]) for i in range(N) for j in OTHERS[i]]
RAW_NAMES = [c for c in NODES] + ['GS']
RAW_HEAD = ['time_ms', 'gw', 'gs_rssi', 'type', 'len', 'hex', 'seq', 'node_ms', 'node_gw']
RAW_COLS = [RAW_HEAD + COLS[i * M:(i + 1) * M] for i in range(N)] + [RAW_HEAD + ['rssi_%d' % (k + 1) for k in range(M)]]
EMPTY = [''] * (3 + M)
MAC_OF = [bytes([int(x, 16) for x in MACS[c].split(':')]) for c in NODES]
ID_OF = {mac: i for i, mac in enumerate(MAC_OF)}
ALERT_PAIRS = [sorted([NODES.index(c) for c in s.split('-')]) for s in ALERT_SECTIONS]

FMT_BEACON = '<BBBHI%dbB' % M
FMT_START = '<BBI'
FMT_RESET = '<BB'
FMT_ASSIGN = '<BBB'
FMT_PASS = '<BBBBHIBbbhh'
LEN_BEACON = struct.calcsize(FMT_BEACON)
LEN_START = struct.calcsize(FMT_START)
LEN_PASS = struct.calcsize(FMT_PASS)


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
    return ['GS_%03d.csv' % n] + ['GS_%03d_%s.csv' % (n, s) for s in RAW_NAMES]


def decode(msg):
    n = len(msg)
    if n == LEN_BEACON:
        v = struct.unpack(FMT_BEACON, msg)
        if v[0] == MAGIC and v[1] == T_BEACON and v[2] < N:
            return v[2], 'BEACON', v
    elif n == LEN_START:
        v = struct.unpack(FMT_START, msg)
        if v[0] == MAGIC and v[1] == T_START:
            return None, 'START', v
    return None, '?', None


def fields(kind, v):
    if kind == 'BEACON':
        return [str(v[3]), str(v[4]), NODES[v[5 + M]] if v[5 + M] < N else '-'] + [str(x) for x in v[5:5 + M]]
    if kind == 'START':
        return ['', str(v[2]), ''] + [''] * M
    return EMPTY


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
        self.seen = []
        self.f = None
        self.raw = []
        self.log_t0 = time.ticks_ms()
        self.last_flush = time.ticks_ms()
        self.sd = None
        self.sd_ok = False
        self.alert_at = [None] * len(ALERT_SECTIONS)
        self.pass_seen = []

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
                pkt = struct.pack(FMT_RESET, MAGIC, T_RESET)
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
            self.f.flush()
            for g in self.raw:
                g.flush()
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

    def close_log(self):
        for g in [self.f] + self.raw:
            if g is None:
                continue
            try:
                g.close()
            except OSError:
                pass
        self.f = None
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

    def is_dup(self, msg):
        now = time.ticks_ms()
        while self.seen and time.ticks_diff(now, self.seen[0][0]) >= DEDUP_MS:
            self.seen.pop(0)
        for s in self.seen:
            if s[1] == msg:
                return True
        self.seen.append((now, msg))
        return False

    def on_pass(self, msg):
        v = struct.unpack(FMT_PASS, msg)
        if v[0] != MAGIC or v[1] != T_PASS or v[2] >= N or v[3] >= N:
            return
        now = time.ticks_ms()
        while self.pass_seen and time.ticks_diff(now, self.pass_seen[0][0]) >= DEDUP_MS:
            self.pass_seen.pop(0)
        for s in self.pass_seen:
            if s[1] == msg:
                return
        self.pass_seen.append((now, msg))
        pair = sorted([v[2], v[3]])
        for i, p in enumerate(ALERT_PAIRS):
            if p == pair:
                self.alert_at[i] = now

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
        if len(msg) == LEN_PASS:
            self.on_pass(msg)
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
        if self.is_dup(msg):
            return
        if origin is not None and origin != sid:
            self.last_fwd = time.ticks_ms()
        p = self.e.peers_table.get(m)
        self.raw_row(sid if origin is None else origin, '' if p is None else str(p[0]), kind, msg, fields(kind, v))
        if kind == 'BEACON':
            b = origin * M
            for k in range(M):
                self.vals[b + k] = v[5 + k]
            self.log_row(sid, self.vals)
            if self.measuring or self.holding:
                return
            print(' '.join(['%s:%d' % (COLS[i], self.vals[i]) for i in range(N * M)]) + self.alert_text())

    def need_assign(self):
        if self.other_fwd or self.last_fwd is None:
            return True
        return time.ticks_diff(time.ticks_ms(), self.last_fwd) >= FWD_TIMEOUT_MS

    def update(self):
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
        pkt = struct.pack(FMT_ASSIGN, MAGIC, T_ASSIGN, self.gw)
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
