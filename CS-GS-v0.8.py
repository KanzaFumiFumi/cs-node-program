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
MIN_FREE_BYTES = 16 * 1024
BEAR_MERGE_MS = 1000
BEAR_SHOW_MS = 1000
BEAR_KEEP_MS = 60000

SD_MOUNT = '/sd'
SD_SLOT = 2
SD_SCK = 8
SD_MISO = 9
SD_MOSI = 10
SD_CS = 4
SD_FREQ = 1000000

MAGIC = 0x52
T_BEACON = 0x01
T_START = 0x02
T_RESET = 0x03
T_ASSIGN = 0x05
T_BEAR = 0x06
BCAST = b'\xff' * 6

N = len(NODES)
M = N - 1
OTHERS = [[j for j in range(N) if j != i] for i in range(N)]
COLS = ['%s->%s' % (NODES[i], NODES[j]) for i in range(N) for j in OTHERS[i]]
BEAR_COLS = ['bear', 'bear_start_s', 'bear_len_s', 'bear_drop_db']
RAW_NAMES = [c for c in NODES] + ['GS']
RAW_HEAD = ['time_ms', 'gw', 'gs_rssi', 'type', 'len', 'hex', 'seq', 'node_ms', 'node_gw']
RAW_TAIL = ['bear_rid', 'bear_partner', 'bear_age_ms', 'bear_len_ms', 'bear_drop_db']
RAW_COLS = [RAW_HEAD + COLS[i * M:(i + 1) * M] + RAW_TAIL for i in range(N)] + [RAW_HEAD + ['rssi_%d' % (k + 1) for k in range(M)] + RAW_TAIL]
EMPTY = [''] * (3 + M + len(RAW_TAIL))
MAC_OF = [bytes([int(x, 16) for x in MACS[c].split(':')]) for c in NODES]
ID_OF = {mac: i for i, mac in enumerate(MAC_OF)}

FMT_BEACON = '<BBBHI%dbB' % M
FMT_START = '<BBI'
FMT_RESET = '<BB'
FMT_ASSIGN = '<BBB'
FMT_BEAR = '<BBBBBHHB'
LEN_BEACON = struct.calcsize(FMT_BEACON)
LEN_START = struct.calcsize(FMT_START)
LEN_BEAR = struct.calcsize(FMT_BEAR)


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


def free_bytes():
    st = os.statvfs(SD_MOUNT)
    return st[0] * st[3]


def fmt_s(ms):
    d = (abs(ms) + 50) // 100
    return '%s%d.%d' % ('-' if ms < 0 and d else '', d // 10, d % 10)


def log_names(n):
    return ['GS_%03d.csv' % n] + ['GS_%03d_%s.csv' % (n, s) for s in RAW_NAMES]


def decode(msg):
    n = len(msg)
    if n == LEN_BEACON:
        v = struct.unpack(FMT_BEACON, msg)
        if v[0] == MAGIC and v[1] == T_BEACON and v[2] < N:
            return v[2], 'BEACON', v
    elif n == LEN_BEAR:
        v = struct.unpack(FMT_BEAR, msg)
        if v[0] == MAGIC and v[1] == T_BEAR and v[2] < N and v[4] < N and v[2] != v[4]:
            return v[2], 'BEAR', v
    elif n == LEN_START:
        v = struct.unpack(FMT_START, msg)
        if v[0] == MAGIC and v[1] == T_START:
            return None, 'START', v
    return None, '?', None


def fields(kind, v):
    if kind == 'BEACON':
        return [str(v[3]), str(v[4]), NODES[v[5 + M]] if v[5 + M] < N else '-'] + [str(x) for x in v[5:5 + M]] + [''] * len(RAW_TAIL)
    if kind == 'START':
        return ['', str(v[2]), ''] + [''] * (M + len(RAW_TAIL))
    if kind == 'BEAR':
        return [''] * (3 + M) + [str(v[3]), NODES[v[4]], str(v[5]), str(v[6]), str(v[7])]
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
        self.bear_recent = []
        self.bear_show = []
        self.bear_csv = []

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
                return True
            except OSError:
                self.unmount_sd()
        try:
            self.sd = machine.SDCard(slot=SD_SLOT, width=1, sck=machine.Pin(SD_SCK), miso=machine.Pin(SD_MISO), mosi=machine.Pin(SD_MOSI), cs=machine.Pin(SD_CS), freq=SD_FREQ)
            os.mount(self.sd, SD_MOUNT)
        except Exception:
            self.unmount_sd()
            return False
        self.sd_ok = True
        return True

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
        self.bear_csv = []
        if not hasattr(machine, 'SDCard'):
            print('LOG OFF: SDCard not supported')
            return
        if not self.mount_sd():
            print('LOG OFF: no SD card')
            return
        try:
            names = os.listdir(SD_MOUNT)
            n = 0
            while [s for s in log_names(n) if s in names]:
                n += 1
            if free_bytes() < MIN_FREE_BYTES:
                print('LOG OFF: low SD space')
                return
            files = log_names(n)
            self.f = open('%s/%s' % (SD_MOUNT, files[0]), 'w')
            self.f.write('time_s,gw,' + ','.join(COLS) + ',' + ','.join(BEAR_COLS) + '\n')
            for i in range(N + 1):
                self.raw.append(open('%s/%s' % (SD_MOUNT, files[i + 1]), 'w'))
                self.raw[i].write(','.join(RAW_COLS[i]) + '\n')
            self.f.flush()
            for g in self.raw:
                g.flush()
        except OSError:
            self.log_fail()
            return
        self.log_t0 = t0
        self.last_flush = time.ticks_ms()

    def log_fail(self):
        print('LOG OFF: write error')
        self.close_log()
        self.unmount_sd()

    def write(self, f, s):
        try:
            f.write(s)
        except OSError:
            self.log_fail()

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
            low = free_bytes() < MIN_FREE_BYTES
        except OSError:
            self.log_fail()
            return
        if low:
            print('LOG OFF: low SD space')
            self.close_log()

    def bear_fields(self):
        if not self.bear_csv:
            return ',,,,'
        name, start, length, drop = self.bear_csv.pop(0)
        return ',%s,%s,%s,%d' % (name, fmt_s(time.ticks_diff(start, self.log_t0)), fmt_s(length), drop)

    def log_row(self, sid, vals):
        if self.f is None:
            return
        d = (time.ticks_diff(time.ticks_ms(), self.log_t0) + 50) // 100
        self.write(self.f, '%d.%d,%s,%s%s\n' % (d // 10, d % 10, NODES[sid], ','.join([str(x) for x in vals]), self.bear_fields()))

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

    def on_bear(self, a, b, age, length, drop):
        if a >= N or b >= N or a == b:
            return
        now = time.ticks_ms()
        start = time.ticks_add(now, -age)
        lo = min(a, b)
        hi = max(a, b)
        self.bear_recent = [r for r in self.bear_recent if time.ticks_diff(now, r[2]) < BEAR_KEEP_MS]
        for r in self.bear_recent:
            if r[0] == lo and r[1] == hi and abs(time.ticks_diff(start, r[3])) <= BEAR_MERGE_MS:
                return
        self.bear_recent.append((lo, hi, now, start))
        name = '%s-%s' % (NODES[lo], NODES[hi])
        self.bear_show.append([name, None])
        if self.f is not None:
            self.bear_csv.append((name, start, length, drop))

    def bear_text(self):
        if not self.bear_show:
            return ''
        now = time.ticks_ms()
        names = []
        keep = []
        for it in self.bear_show:
            if it[1] is None:
                it[1] = time.ticks_add(now, BEAR_SHOW_MS)
            if time.ticks_diff(it[1], now) > 0:
                keep.append(it)
                if it[0] not in names:
                    names.append(it[0])
        self.bear_show = keep
        if not names:
            return ''
        return ' 【熊速報】' + ' '.join([s + '区間' for s in names])

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
            print(' '.join(['%s:%d' % (COLS[i], self.vals[i]) for i in range(N * M)]) + self.bear_text())
        elif kind == 'BEAR':
            self.on_bear(v[2], v[4], v[5], v[6], v[7])

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
