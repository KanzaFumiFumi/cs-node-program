import network
import espnow
import struct
import sys
import select

GW_MAC = '00:00:00:00:00:00'

NODES = 'ABCD'
CHANNEL = 6
RECV_TIMEOUT_MS = 50

MAGIC = 0x52
T_RESET = 0x03
T_AGG = 0x04
BCAST = b'\xff' * 6

N = len(NODES)
M = N - 1
OTHERS = [[j for j in range(N) if j != i] for i in range(N)]
COLS = ['%s->%s' % (NODES[i], NODES[j]) for i in range(N) for j in OTHERS[i]]
GW_MAC_B = bytes([int(x, 16) for x in GW_MAC.split(':')])

FMT_RESET = '<BB'
FMT_AGG = '<BBIH%db' % (N * M)
LEN_AGG = struct.calcsize(FMT_AGG)


def setup_espnow():
    sta = network.WLAN(network.STA_IF)
    sta.active(True)
    sta.disconnect()
    sta.config(channel=CHANNEL)
    sta.config(pm=sta.PM_NONE)
    e = espnow.ESPNow()
    e.active(True)
    try:
        e.add_peer(BCAST)
    except OSError:
        pass
    return e


def main():
    e = setup_espnow()
    keys = select.poll()
    keys.register(sys.stdin, select.POLLIN)
    pkt_reset = struct.pack(FMT_RESET, MAGIC, T_RESET)
    while True:
        if keys.poll(0):
            sys.stdin.readline()
            try:
                e.send(BCAST, pkt_reset, False)
            except OSError:
                pass
        mac, msg = e.recv(RECV_TIMEOUT_MS)
        if not msg or len(msg) != LEN_AGG or bytes(mac) != GW_MAC_B:
            continue
        v = struct.unpack(FMT_AGG, msg)
        if v[0] != MAGIC or v[1] != T_AGG:
            continue
        print(' '.join(['%s:%d' % (COLS[i], v[4 + i]) for i in range(N * M)]))


main()
