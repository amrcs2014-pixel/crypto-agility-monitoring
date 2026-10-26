"""Paper B testbed: run one experimental cell in a Mininet network and capture it.

cell = (stack, transport, kx, cert, ech): stack in {go, openssl}, transport in {tcp, quic} (quic: go only),
kx in {classical, hybrid}, cert in {ecdsa, mldsa}, ech in {off, on}.
Network: one server (10.0.0.1, Go net/http + quic-go, ECH keys always loaded) and 8 clients
(10.0.0.11-18), each on a 50 Mbit/s link with 20 ms one-way delay; capture on the server's interface
(vantage of a monitor in front of the server). Workload: 9 profiles x REPS repetitions, distributed
over the clients in rounds; seeds depend only on (profile, rep), so every cell replays the same
workload (common random numbers). Output: CAP/<cell>/capture.pcap + runs.json.

Every behaviour targets only the lab's own server inside this isolated emulated network.
Run as root in WSL: python3 b_twin.py CELL [CELL ...] | all
"""
import itertools, json, os, subprocess, sys, time
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

setLogLevel('warning')
B = os.environ.get('LAB', '/opt/p1920b')
TLSLAB = f'{B}/gotls/tlslab'
OSSLC = f'{B}/b_osslclient.py'
CAP = os.environ.get('CAP', f'{B}/caps')
SRV, CLIENTS = '10.0.0.1', [f'10.0.0.{11 + i}' for i in range(8)]
PROFILES = ['web_page', 'api_poll', 'download', 'upload', 'video', 'many_short', 'beacon', 'brute', 'scan']
MALICIOUS = {'beacon', 'brute', 'scan'}
REPS = int(os.environ.get('REPS', 10))
DUR = float(os.environ.get('DUR', 20))


def cells():
    out = []
    for stack, tr, kx, cert, ech in itertools.product(['go', 'openssl'], ['tcp', 'quic'], ['classical', 'hybrid'],
                                                      ['ecdsa', 'mldsa'], ['off', 'on']):
        if stack == 'openssl' and tr == 'quic':
            continue  # no OpenSSL HTTP/3 client in this lab (recorded as a missing cell)
        out.append(f'{stack}-{tr}-{kx}-{cert}-ech{ech}')
    return out


def client_cmd(stack, tr, kx, cert, ech, prof, seed):
    ca = f'{B}/pki/ca_{cert}.crt'
    if stack == 'go':
        a = f'{TLSLAB} client -profile {prof} -target {SRV} -kx {kx} -ca {ca} -dur {DUR} -seed {seed}'
        if ech == 'on':
            a += f' -ech {B}/pki/ech'
        if tr == 'quic':
            a += ' -quic'
        return a
    e = f'{B}/pki/ech/ech_configlist.b64' if ech == 'on' else '-'
    return f'python3 {OSSLC} {prof} {SRV} {kx} {ca} {e} {DUR} {seed}'


def run_cell(cell):
    stack, tr, kx, cert, ech = cell.split('-')
    ech = ech.replace('ech', '')
    out = os.path.join(CAP, cell)
    if os.path.exists(os.path.join(out, 'runs.json')):
        print(cell, 'exists, skipped', flush=True); return
    os.makedirs(out, exist_ok=True)
    hosts = open('/etc/hosts').read()
    if 'www.example.test' not in hosts:  # WSL regenerates /etc/hosts on restart
        open('/etc/hosts', 'a').write('\n' + SRV + ' www.example.test public.example.test\n')
    subprocess.run(['mn', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    net = Mininet(switch=OVSSwitch, link=TCLink, controller=None)
    s1 = net.addSwitch('s1', failMode='standalone')
    srv = net.addHost('srv', ip=SRV + '/24')
    net.addLink(srv, s1, bw=1000)
    cl = []
    for i, ip in enumerate(CLIENTS):
        h = net.addHost(f'c{i}', ip=ip + '/24'); cl.append(h)
        net.addLink(h, s1, bw=50, delay='20ms')
    net.start()
    try:
        for h in [srv] + cl:
            h.cmd(f'ethtool -K {h.defaultIntf().name} tso off gso off gro off tx off rx off 2>/dev/null')
        q = ' -quic' if tr == 'quic' else ''
        srv.cmd(f'nohup {TLSLAB} server -cert {B}/pki/srv_{cert}.crt -key {B}/pki/srv_{cert}_seed.key '
                f'-ech {B}/pki/ech -addr {SRV}:443{q} >{out}/server.log 2>&1 &')
        time.sleep(1.5)
        pcap = os.path.join(out, 'capture.pcap')
        srv.cmd(f"nohup tcpdump -i {srv.defaultIntf().name} -w '{pcap}' -U -s 0 'ip' >/dev/null 2>&1 & echo $! > /tmp/tcpd.pid")
        time.sleep(1.5)
        jobs = [(p, r) for r in range(REPS) for p in PROFILES]
        runs, t0 = [], time.time()
        for k in range(0, len(jobs), len(cl)):
            batch, procs = jobs[k:k + len(cl)], []
            for h, (p, r) in zip(cl, batch):
                seed = 1000 * PROFILES.index(p) + r
                cmd = client_cmd(stack, tr, kx, cert, ech, p, seed)
                procs.append((h, p, r, seed, time.time(), h.popen(cmd, shell=True, stdout=subprocess.PIPE,
                                                                       stderr=subprocess.STDOUT)))
            for h, p, r, seed, ts, pr in procs:
                try:
                    o, _ = pr.communicate(timeout=DUR + 60)
                except subprocess.TimeoutExpired:
                    pr.kill(); o = b'TIMEOUT'
                runs.append(dict(client=h.IP(), profile=p, rep=r, seed=seed, malicious=p in MALICIOUS,
                                 t_start=ts, t_end=time.time(), out=o.decode(errors='replace')[-200:]))
            time.sleep(1.0)
        srv.cmd('kill -INT $(cat /tmp/tcpd.pid); sleep 1')
        json.dump(dict(cell=cell, stack=stack, transport=tr, kx=kx, cert=cert, ech=ech, reps=REPS, dur=DUR,
                       wall=time.time() - t0, runs=runs), open(os.path.join(out, 'runs.json'), 'w'), indent=0)
        bad = sum(1 for x in runs if 'errors 0' not in x['out'])
        print(f'{cell}: {len(runs)} runs in {time.time() - t0:.0f}s, runs with errors {bad}', flush=True)
    finally:
        srv.cmd('pkill -f "tlslab server" 2>/dev/null')
        net.stop()


if __name__ == '__main__':
    want = cells() if sys.argv[1:] == ['all'] else sys.argv[1:]
    for c in want:
        run_cell(c)
    print('ALL DONE' if sys.argv[1:] == ['all'] else 'done', flush=True)
