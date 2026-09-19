import network
import espnow
import struct
import sys
import select
import time

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

    def send(self, pkt):
        try:
            self.e.send(BCAST, pkt, False)
        except OSError:
            pass

    def on_command(self, line):
        cmd = line.strip().lower()
        if cmd == 'r':
            if self.gw is not None:
                self.send(struct.pack(FMT_RESET, MAGIC, T_RESET))
        elif cmd == 'g':
            if not self.measuring:
                self.start_measure()

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
            if self.measuring or self.holding:
                return
            print(' '.join(['%s:%d' % (COLS[i], v[4 + i]) for i in range(N * M)]))

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
    while True:
        if keys.poll(0):
            st.on_command(sys.stdin.readline())
        mac, msg = e.recv(RECV_TIMEOUT_MS)
        if msg:
            st.on_recv(mac, msg)
        st.update()


main()
