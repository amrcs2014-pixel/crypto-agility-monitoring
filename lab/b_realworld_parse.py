"""Parse the public-server captures (b_realworld.sh): ClientHello size, key-share bytes and handshake
bytes per direction, using the same functions as the lab extractor."""
import csv, os, sys
import pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # b_extract.py
import b_extract as bx

rows = []
for site, kx, rep, grp, sig, pcap in csv.reader(open(os.environ.get('LAB', '/opt/p1920b') + '/realworld/results.tsv'), delimiter='\t'):
    import dpkt, socket
    srv = None
    with open(pcap, 'rb') as fh:
        for ts, raw in dpkt.pcap.Reader(fh):
            ip = dpkt.ethernet.Ethernet(raw).data
            if isinstance(ip, dpkt.ip.IP) and isinstance(ip.data, dpkt.tcp.TCP) and ip.data.dport == 443:
                srv = socket.inet_ntoa(ip.dst); break
    if not srv:
        continue
    bx.SRV = srv
    F = bx.flows_dpkt(pcap)
    for key, f in F.items():
        ch, nrec = bx.first_ch(f['c2s'])
        if not ch:
            continue
        he = f['hs_end']; hs = [p for p in f['pk'] if he is None or p[0] <= he]
        rows.append(dict(site=site, kx=kx, rep=rep, group=grp or 'X25519', sig=sig, ch_len=ch['ch_len'],
                         ks_bytes=ch['ks_bytes'], hs_c2s_bytes=sum(p[2] for p in hs if p[1] > 0),
                         hs_s2c_bytes=sum(p[2] for p in hs if p[1] < 0), hs_pkts=len(hs),
                         hs_dur_ms=round(1000 * (hs[-1][0] - hs[0][0]), 1) if hs else None))
        break
df = pd.DataFrame(rows)
df.to_csv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'b_realworld.csv'), index=False)
print(df.groupby(['site', 'kx'])[['ch_len', 'ks_bytes', 'hs_c2s_bytes', 'hs_s2c_bytes', 'hs_pkts', 'hs_dur_ms']].median().to_string())
