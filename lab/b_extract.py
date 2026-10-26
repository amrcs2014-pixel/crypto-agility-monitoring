"""Paper B: per-cell flow extraction (run in WSL). For every finished cell in CAP:
  1. NFStream flows (statistical features, first-10-packet sizes/IATs, nDPI JA4 client fingerprint,
     server fingerprint, SNI as seen on the wire);
  2. an own dpkt pass per flow: JA3 + ClientHello metadata (record length, TCP segments, groups,
     key-share groups and bytes, ECH extension), handshake phase boundary, and the same statistics
     computed (a) over the whole flow and (b) after the handshake only ("handshake-normalised");
     first 6 payload-bearing packets x 100 bytes for the byte-level model.
Labels: a flow belongs to the run whose client IP matches and whose time window contains the flow start.
Output: OUT/<cell>.csv.gz (one row per flow) and OUT/<cell>_bytes.npy (flows x 6 x 100, uint8).
"""
import gzip, hashlib, json, os, socket, struct, sys
import numpy as np
import pandas as pd
import dpkt
from nfstream import NFStreamer

CAP = os.environ.get('CAP', os.environ.get('LAB', '/opt/p1920b') + '/caps')
OUT = os.environ.get('OUT', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'b_flows'))
SRV = '10.0.0.1'
GREASE = {0x0a0a + 0x1010 * i for i in range(16)}
NB, NBYTES = 6, 100


def stats(pk, prefix):
    """pk: list of (ts, dir(+1 c2s / -1 s2c), ip_len). Returns NFStream-like aggregate statistics."""
    o = {}
    if not pk:
        return {f'{prefix}{k}': 0.0 for k in ['pkts', 'bytes', 'dur', 'fwd_pkts', 'bwd_pkts', 'fwd_bytes', 'bwd_bytes',
                                              'fwd_mean_ps', 'fwd_std_ps', 'fwd_max_ps', 'fwd_min_ps', 'bwd_mean_ps',
                                              'bwd_std_ps', 'bwd_max_ps', 'bwd_min_ps', 'mean_iat', 'std_iat', 'max_iat',
                                              'fwd_mean_iat', 'bwd_mean_iat', 'bytes_ratio', 'pps', 'bps']}
    ts = np.array([p[0] for p in pk]); d = np.array([p[1] for p in pk]); s = np.array([p[2] for p in pk], float)
    dur = ts[-1] - ts[0]
    o[f'{prefix}pkts'] = len(pk); o[f'{prefix}bytes'] = s.sum(); o[f'{prefix}dur'] = dur
    for nm, m in (('fwd', d > 0), ('bwd', d < 0)):
        x = s[m]
        o[f'{prefix}{nm}_pkts'] = m.sum(); o[f'{prefix}{nm}_bytes'] = x.sum()
        o[f'{prefix}{nm}_mean_ps'] = x.mean() if len(x) else 0; o[f'{prefix}{nm}_std_ps'] = x.std() if len(x) else 0
        o[f'{prefix}{nm}_max_ps'] = x.max() if len(x) else 0; o[f'{prefix}{nm}_min_ps'] = x.min() if len(x) else 0
        t = ts[m]
        o[f'{prefix}{nm}_mean_iat'] = np.diff(t).mean() if len(t) > 1 else 0
    iat = np.diff(ts)
    o[f'{prefix}mean_iat'] = iat.mean() if len(iat) else 0; o[f'{prefix}std_iat'] = iat.std() if len(iat) else 0
    o[f'{prefix}max_iat'] = iat.max() if len(iat) else 0
    o[f'{prefix}bytes_ratio'] = o[f'{prefix}fwd_bytes'] / max(o[f'{prefix}bwd_bytes'], 1)
    o[f'{prefix}pps'] = len(pk) / dur if dur > 0 else 0; o[f'{prefix}bps'] = s.sum() / dur if dur > 0 else 0
    return o


def parse_ch(buf):
    """Parse a TLS ClientHello handshake message body -> dict (JA3 fields + metadata) or None."""
    try:
        if buf[0] != 1:
            return None
        n = struct.unpack('!I', b'\x00' + buf[1:4])[0]
        b = buf[4:4 + n]
        ver = struct.unpack('!H', b[0:2])[0]; i = 34
        sid = b[i]; i += 1 + sid
        cl = struct.unpack('!H', b[i:i + 2])[0]; i += 2
        ciphers = [struct.unpack('!H', b[i + k:i + k + 2])[0] for k in range(0, cl, 2)]; i += cl
        i += 1 + b[i]
        el = struct.unpack('!H', b[i:i + 2])[0]; i += 2
        exts, groups, pf, ks_groups, ks_bytes, sni, ech, ext_bytes = [], [], [], [], 0, '', 0, {}
        end = i + el
        while i + 4 <= end:
            t, l = struct.unpack('!HH', b[i:i + 4]); d = b[i + 4:i + 4 + l]; i += 4 + l
            exts.append(t); ext_bytes[t] = l
            if t == 10:
                groups = [struct.unpack('!H', d[2 + k:4 + k])[0] for k in range(0, struct.unpack('!H', d[:2])[0], 2)]
            elif t == 11:
                pf = list(d[1:1 + d[0]])
            elif t == 51:
                j = 2
                while j + 4 <= len(d):
                    g, kl = struct.unpack('!HH', d[j:j + 4]); ks_groups.append(g); ks_bytes += kl; j += 4 + kl
            elif t == 0 and len(d) > 5:
                sni = d[5:5 + struct.unpack('!H', d[3:5])[0]].decode(errors='replace')
            elif t == 0xfe0d:
                ech = 1
        f = lambda xs: '-'.join(str(x) for x in xs if x not in GREASE)
        ja3s = f'{ver},{f(ciphers)},{f(exts)},{f(groups)},{f(pf)}'
        return dict(ja3=hashlib.md5(ja3s.encode()).hexdigest(), ch_len=4 + n, n_ext=len(exts),
                    groups=f(groups), ks_groups=f(ks_groups), ks_bytes=ks_bytes, sni_inner_or_outer=sni,
                    ech_ext=ech, ech_ext_len=ext_bytes.get(0xfe0d, 0), hybrid_offered=int(0x11ec in groups),
                    hybrid_share=int(0x11ec in ks_groups))
    except Exception:
        return None


def flows_dpkt(pcap):
    F = {}
    with open(pcap, 'rb') as fh:
        for ts, raw in dpkt.pcap.Reader(fh):
            try:
                eth = dpkt.ethernet.Ethernet(raw); ip = eth.data
                if not isinstance(ip, dpkt.ip.IP):
                    continue
                l4 = ip.data; proto = ip.p
                if proto not in (6, 17):
                    continue
                src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
                if dst == SRV:
                    key, d = (src, l4.sport, proto), 1
                elif src == SRV:
                    key, d = (dst, l4.dport, proto), -1
                else:
                    continue
                f = F.setdefault(key, dict(pk=[], c2s=b'', hs_end=None, nbytes=[], flags=0))
                pay = bytes(l4.data)
                # 4th field: QUIC long-header packet (Initial/Handshake phase); always 0 for TCP
                f['pk'].append((ts, d, ip.len, int(proto == 17 and bool(pay) and bool(pay[0] & 0x80))))
                if proto == 6:
                    f['flags'] |= l4.flags
                if pay and len(f['nbytes']) < NB:
                    f['nbytes'].append((d, pay[:NBYTES]))
                if proto == 6 and d == 1 and pay:
                    if len(f['c2s']) < 20000:
                        f['c2s'] += pay
                    # handshake ends with the client's first encrypted record (its Finished) after the ClientHello
                    if f['hs_end'] is None and len(f['c2s']) > len(pay):
                        if _has_appdata_record(f['c2s']):
                            f['hs_end'] = ts
                if proto == 17 and pay and f['hs_end'] is None and not (pay[0] & 0x80):
                    f['hs_end'] = ts  # first QUIC short-header (1-RTT) packet
            except Exception:
                continue
    return F


def _has_appdata_record(c2s):
    i = 0
    while i + 5 <= len(c2s):
        t, l = c2s[i], struct.unpack('!H', c2s[i + 3:i + 5])[0]
        if t == 23:
            return True
        i += 5 + l
    return False


def first_ch(c2s):
    """Reassemble the first handshake record(s) from the client byte stream and parse the ClientHello."""
    if len(c2s) < 6 or c2s[0] != 22:
        return None, 0
    body, i, nrec = b'', 0, 0
    while i + 5 <= len(c2s) and c2s[i] == 22:
        l = struct.unpack('!H', c2s[i + 3:i + 5])[0]
        body += c2s[i + 5:i + 5 + l]; i += 5 + l; nrec += 1
        if len(body) >= 4 and len(body) >= 4 + struct.unpack('!I', b'\x00' + body[1:4])[0]:
            break
    return parse_ch(body), nrec


def label(df, runs):
    lab = []
    for ip, t in zip(df.client_ip, df.t0):
        r = next((x for x in runs if x['client'] == ip and x['t_start'] - 0.5 <= t <= x['t_end'] + 0.5), None)
        lab.append((r['profile'], r['rep'], r['malicious']) if r else ('unknown', -1, False))
    df['profile'] = [l[0] for l in lab]; df['rep'] = [l[1] for l in lab]; df['malicious'] = [l[2] for l in lab]
    return df


def extract(cell):
    d = os.path.join(CAP, cell)
    meta = json.load(open(os.path.join(d, 'runs.json')))
    pcap = os.path.join(d, 'capture.pcap')
    nf = NFStreamer(source=pcap, statistical_analysis=True, splt_analysis=10, n_dissections=20,
                    idle_timeout=30, active_timeout=600).to_pandas()
    nf = nf[(nf.dst_ip == SRV) & nf.src_ip.str.startswith('10.0.0.')].copy()
    F = flows_dpkt(pcap)
    rows, mats = [], []
    for _, r in nf.iterrows():
        key = (r.src_ip, int(r.src_port), int(r.protocol))
        f = F.get(key)
        row = r.drop(labels=['splt_direction', 'splt_ps', 'splt_piat_ms']).to_dict()
        L = lambda v: json.loads(v) if isinstance(v, str) else list(v)
        sps, sdir, siat = L(r.splt_ps), L(r.splt_direction), L(r.splt_piat_ms)
        for k in range(10):
            ps = sps[k] if k < len(sps) else 0
            dr = sdir[k] if k < len(sdir) else -1
            row[f'splt_{k}'] = (ps if dr == 0 else -ps) if dr != -1 else 0
            row[f'splt_iat_{k}'] = siat[k] if k < len(siat) and siat[k] >= 0 else 0
        m = np.zeros((NB, NBYTES), np.uint8)
        if f:
            pk = f['pk']
            row.update(stats(pk, 'full_'))
            he = f['hs_end']
            if key[2] == 17:  # QUIC: handshake packets are the long-header ones, wherever they fall in time
                post = [p for p in pk if he is not None and not p[3]]
                hs = [p for p in pk if p[3]]
            else:
                post = [p for p in pk if he is not None and p[0] > he]
                hs = [p for p in pk if he is None or p[0] <= he]
            row.update(stats(post, 'post_'))
            row['hs_pkts'] = len(hs); row['hs_bytes'] = sum(p[2] for p in hs)
            row['hs_c2s_bytes'] = sum(p[2] for p in hs if p[1] > 0); row['hs_s2c_bytes'] = sum(p[2] for p in hs if p[1] < 0)
            row['hs_dur'] = (hs[-1][0] - hs[0][0]) if hs else 0
            row['hs_complete'] = int(he is not None)
            ch, nrec = first_ch(f['c2s']) if key[2] == 6 else (None, 0)
            if ch:
                row.update(ch); row['ch_records'] = nrec
            for k, (dr, b) in enumerate(f['nbytes']):
                m[k, :len(b)] = np.frombuffer(b, np.uint8)
        row['client_ip'] = r.src_ip; row['t0'] = r.bidirectional_first_seen_ms / 1000
        rows.append(row); mats.append(m)
    df = label(pd.DataFrame(rows), meta['runs'])
    for k in ('stack', 'transport', 'kx', 'cert', 'ech'):
        df[k] = meta[k]
    df['cell'] = cell
    os.makedirs(OUT, exist_ok=True)
    df.to_csv(os.path.join(OUT, f'{cell}.csv.gz'), index=False, compression='gzip')
    np.save(os.path.join(OUT, f'{cell}_bytes.npy'), np.stack(mats) if mats else np.zeros((0, NB, NBYTES), np.uint8))
    print(cell, len(df), 'flows;', df.profile.value_counts().to_dict(), flush=True)


if __name__ == '__main__':
    cells = sys.argv[1:] or sorted(c for c in os.listdir(CAP) if os.path.exists(os.path.join(CAP, c, 'runs.json')))
    for c in cells:
        if os.path.exists(os.path.join(OUT, f'{c}.csv.gz')) and not os.environ.get('FORCE'):
            continue
        extract(c)
