import network
import espnow
import struct
import sys
import select
import time
import os
import machine

MACS = {
    'A': '00:00:00:00:00:00',
    'B': '00:00:00:00:00:00',
    'C': '00:00:00:00:00:00',
    'D': '00:00:00:00:00:00',
}

NODES = 'ABCD'
CHANNEL = 6
RECV_TIMEOUT_MS = 50
MEASURE_MS = 10000
MEASURE_SHOW_MS = 100
RESULT_HOLD_MS = 5000
ASSIGN_INTERVAL_MS = 100
AGG_TIMEOUT_MS = 3000
MIN_FREE_BYTES = 16 * 1024
LOG_CHECK_ROWS = 10

SD_MOUNT = '/sd'
SD_SLOT = 2
SD_SCK = 8
SD_MISO = 9
SD_MOSI = 10
SD_CS = 4
SD_FREQ = 1000000

MAGIC = 0x52
T_BEACON = 0x01
T_RESET = 0x03
T_AGG = 0x04
T_ASSIGN = 0x05
BCAST = b'\xff' * 6

N = len(NODES)
M = N - 1
OTHERS = [[j for j in range(N) if j != i] for i in range(N)]
COLS = ['%s->%s' % (NODES[i], NODES[j]) for i in range(N) for j in OTHERS[i]]
MAC_OF = [bytes([int(x, 16) for x in MACS[c].split(':')]) for c in NODES]
ID_OF = {mac: i for i, mac in enumerate(MAC_OF)}

FMT_BEACON = '<BBBHI%db' % M
FMT_RESET = '<BB'
FMT_AGG = '<BBIH%db' % (N * M)
FMT_ASSIGN = '<BBB'
LEN_BEACON = struct.calcsize(FMT_BEACON)
LEN_AGG = struct.calcsize(FMT_AGG)


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
    st = os.statvfs(SD_MOUNT)
    return st[0] * st[3]


class Station:
    def __init__(self, e):
        self.e = e
        self.gw = None
        self.last_agg = None
        self.other_agg = False
        self.next_assign = time.ticks_ms()
        self.measuring = False
        self.meas_end = time.ticks_ms()
        self.next_show = time.ticks_ms()
        self.holding = False
        self.hold_end = time.ticks_ms()
        self.sums = [0] * N
        self.counts = [0] * N
        self.latest = [0] * N
        self.f = None
        self.log_t0 = time.ticks_ms()
        self.log_rows = 0
        self.sd = None
        self.sd_ok = False

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
                self.send(struct.pack(FMT_RESET, MAGIC, T_RESET))
                self.start_log(t)
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
        if not hasattr(machine, 'SDCard'):
            print('LOG OFF: SDCard not supported')
            return
        if not self.mount_sd():
            print('LOG OFF: no SD card')
            return
        try:
            names = os.listdir(SD_MOUNT)
            n = 0
            while 'GS_%03d.csv' % n in names:
                n += 1
            if free_bytes() < MIN_FREE_BYTES:
                print('LOG OFF: low SD space')
                return
            self.f = open('%s/GS_%03d.csv' % (SD_MOUNT, n), 'w')
            self.f.write('time_s,gw,' + ','.join(COLS) + '\n')
            self.f.flush()
        except OSError:
            print('LOG OFF: write error')
            self.close_log()
            self.unmount_sd()
            return
        self.log_t0 = t0
        self.log_rows = 0

    def log_row(self, sid, vals):
        if self.f is None:
            return
        d = (time.ticks_diff(time.ticks_ms(), self.log_t0) + 50) // 100
        try:
            self.f.write('%d.%d,%s,%s\n' % (d // 10, d % 10, NODES[sid], ','.join([str(x) for x in vals])))
            self.f.flush()
            self.log_rows += 1
            low = self.log_rows % LOG_CHECK_ROWS == 0 and free_bytes() < MIN_FREE_BYTES
        except OSError:
            print('LOG OFF: write error')
            self.close_log()
            self.unmount_sd()
            return
        if low:
            print('LOG OFF: low SD space')
            self.close_log()

    def close_log(self):
        if self.f is None:
            return
        try:
            self.f.close()
        except OSError:
            pass
        self.f = None

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
        self.last_agg = None
        self.other_agg = False
        self.next_assign = time.ticks_ms()

    def show_measure(self):
        if time.ticks_diff(time.ticks_ms(), self.next_show) < 0:
            return
        print(' '.join(['%s:%d' % (NODES[i], self.latest[i]) for i in range(N)]))
        self.next_show = time.ticks_add(self.next_show, MEASURE_SHOW_MS)
        if time.ticks_diff(time.ticks_ms(), self.next_show) > MEASURE_SHOW_MS:
            self.next_show = time.ticks_add(time.ticks_ms(), MEASURE_SHOW_MS)

    def on_recv(self, mac, msg):
        m = bytes(mac)
        sid = ID_OF.get(m)
        if sid is None:
            return
        n = len(msg)
        if n == LEN_BEACON:
            if not self.measuring:
                return
            v = struct.unpack(FMT_BEACON, msg)
            if v[0] != MAGIC or v[1] != T_BEACON or v[2] != sid:
                return
            p = self.e.peers_table.get(m)
            if p is None:
                return
            self.sums[sid] += p[0]
            self.counts[sid] += 1
            self.latest[sid] = p[0]
        elif n == LEN_AGG:
            v = struct.unpack(FMT_AGG, msg)
            if v[0] != MAGIC or v[1] != T_AGG:
                return
            if sid != self.gw:
                if self.gw is not None:
                    self.other_agg = True
                return
            self.last_agg = time.ticks_ms()
            vals = v[4:]
            self.log_row(sid, vals)
            if self.measuring or self.holding:
                return
            print(' '.join(['%s:%d' % (COLS[i], vals[i]) for i in range(N * M)]))

    def need_assign(self):
        if self.gw is None:
            return False
        if self.other_agg or self.last_agg is None:
            return True
        return time.ticks_diff(time.ticks_ms(), self.last_agg) >= AGG_TIMEOUT_MS

    def update(self):
        if self.measuring and time.ticks_diff(time.ticks_ms(), self.meas_end) >= 0:
            self.finish_measure()
        if self.measuring:
            self.show_measure()
        if self.holding and time.ticks_diff(time.ticks_ms(), self.hold_end) >= 0:
            self.holding = False
        if not self.need_assign():
            return
        if time.ticks_diff(time.ticks_ms(), self.next_assign) < 0:
            return
        self.send(struct.pack(FMT_ASSIGN, MAGIC, T_ASSIGN, self.gw))
        self.other_agg = False
        self.next_assign = time.ticks_add(time.ticks_ms(), ASSIGN_INTERVAL_MS)


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
