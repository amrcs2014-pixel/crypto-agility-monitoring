"""Paper B: how post-quantum TLS and ECH shift network monitoring, and what repairs cost.

Data: data/b_flows/<cell>.csv.gz (+ _bytes.npy) from lab/b_extract.py; TCP and UDP flows only.
Protocol (seeds and run schedule are identical across cells):
  baseline cells = classical key exchange, ECDSA certificate, ECH off, one per (stack, transport);
  fold 0 (main): train = baseline reps 0-3, calibration = baseline reps 4-5, test = reps 6-9 of every cell;
  folds 1-2 rotate the repetitions (variability); few-shot pools = non-test reps of migrated cells.
Thresholds at 1 % and 5 % FPR on the baseline's benign calibration flows (R0/recalibrated variants: on
the migrated cell's own benign calibration flows, no malicious labels).
Detectors: LightGBM, random forest, MLP (supervised), Isolation Forest (benign-only) on NFStream features;
byte-level CNN (first 6 payloads x 100 bytes); JA3/JA4 coverage.
Repairs: R0 threshold recalibration; R1 post-handshake statistics (+ handshake-completed flag; ablation
without it); R1b no first-packet features; R2 few-shot (1/5/10 %), R2b balanced, R2r few-shot + recalibrated
threshold; R3 retraining on all labelled migrated flows. Control: own full-flow statistics.
Usage: python b_detect.py [fold]   -> results/b_eval.json (fold 0) or results/b_eval_f<k>.json
"""
import json, glob, os, sys, warnings
from pathlib import Path
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, FunctionTransformer
from sklearn.pipeline import make_pipeline
from sklearn.metrics import roc_auc_score
from scipy.stats import ks_2samp

warnings.filterwarnings('ignore')
W = Path(__file__).resolve().parents[1]
FL, R = W / 'data' / 'b_flows', W / 'results'
FACTORS = ['stack', 'transport', 'kx', 'cert', 'ech']
FOLDS = [({0, 1, 2, 3}, {4, 5}, {6, 7, 8, 9}),
         ({6, 7, 8, 9}, {4, 5}, {0, 1, 2, 3}),
         ({2, 3, 4, 5}, {0, 1}, {6, 7, 8, 9})]
FOLD = int(sys.argv[1]) if len(sys.argv) > 1 else 0
TRAIN, CAL, TEST = FOLDS[FOLD]
POOL = set(range(10)) - TEST
SEED = 19 + FOLD
BENIGN = ['web_page', 'api_poll', 'download', 'upload', 'video', 'many_short']
ID_COLS = {'id', 'expiration_id', 'src_ip', 'src_mac', 'src_oui', 'src_port', 'dst_ip', 'dst_mac', 'dst_oui', 'dst_port',
           'protocol', 'ip_version', 'vlan_id', 'tunnel_id', 'bidirectional_first_seen_ms', 'bidirectional_last_seen_ms',
           'src2dst_first_seen_ms', 'src2dst_last_seen_ms', 'dst2src_first_seen_ms', 'dst2src_last_seen_ms',
           'application_name', 'application_category_name', 'application_is_guessed', 'application_confidence',
           'requested_server_name', 'client_fingerprint', 'server_fingerprint', 'user_agent', 'content_type',
           'client_ip', 't0', 'profile', 'rep', 'malicious', 'cell'} | set(FACTORS)


def load():
    dfs, mats = [], []
    for f in sorted(glob.glob(str(FL / '*.csv.gz'))):
        cell = os.path.basename(f)[:-7]
        d = pd.read_csv(f, low_memory=False)
        m = np.load(str(FL / f'{cell}_bytes.npy'))
        keep = ((d.profile != 'unknown') & d.protocol.isin([6, 17])).values   # drop ICMP etc.
        dfs.append(d[keep].reset_index(drop=True)); mats.append(m[keep])
    df = pd.concat(dfs, ignore_index=True)
    X8 = np.concatenate(mats)
    df['baseline'] = (df.kx == 'classical') & (df.cert == 'ecdsa') & (df.ech == 'off')
    df['group'] = df['stack'] + '-' + df['transport']
    df['y'] = df.malicious.astype(int)
    df['hs_complete'] = df.hs_complete.fillna(0)
    return df, X8


def feature_sets(df):
    nfs = [c for c in df.columns if c.startswith(('bidirectional_', 'src2dst_', 'dst2src_', 'splt_')) and c not in ID_COLS]
    full = [c for c in df.columns if c.startswith('full_')]
    post_only = [c for c in df.columns if c.startswith('post_')]
    return dict(nfs=nfs, full=full, post=post_only + ['hs_complete'], post_nohs=post_only,
                nosplt=[c for c in nfs if not c.startswith('splt_')])


def slog(x):
    """signed log1p: byte and packet counts span six orders of magnitude"""
    return np.sign(x) * np.log1p(np.abs(x))


def models():
    return {
        'lgbm': lambda: lgb.LGBMClassifier(n_estimators=300, learning_rate=0.05, num_leaves=31, subsample=0.8,
                                           colsample_bytree=0.8, random_state=SEED, verbose=-1),
        'rf': lambda: RandomForestClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=-1, random_state=SEED),
        'mlp': lambda: make_pipeline(FunctionTransformer(slog), StandardScaler(),
                                     MLPClassifier((128, 64), max_iter=300, early_stopping=False, random_state=SEED)),
    }


def thr_at(scores_benign, fpr):
    return float(np.quantile(scores_benign, 1 - fpr)) if len(scores_benign) else 0.5


PRED = []  # per-flow test alerts (fold 0) for paired statistics (b_stats.py)


def per_cell(gd, score, thr1, thr5, tag=None):
    """thr1/thr5: dict cell -> threshold at 1 % / 5 % FPR. Metrics on test reps only."""
    out = {}
    te = gd[gd.rep.isin(TEST)]
    if tag and FOLD == 0:
        PRED.append(pd.DataFrame(dict(tag=tag, cell=te.cell.values, group=te.group.values, profile=te.profile.values,
                                      rep=te.rep.values, y=te.y.values,
                                      alert=(score[te.index].values > te.cell.map(thr1).values).astype(np.int8))))
    for cell, g in te.groupby('cell'):
        s = score[g.index].values; y = g.y.values; t1, t5 = thr1[cell], thr5[cell]
        r = dict(n=len(g), n_benign=int((y == 0).sum()),
                 fpr=float((s[y == 0] > t1).mean()) if (y == 0).any() else None,
                 recall=float((s[y == 1] > t1).mean()) if (y == 1).any() else None,
                 fpr5=float((s[y == 0] > t5).mean()) if (y == 0).any() else None,
                 recall5=float((s[y == 1] > t5).mean()) if (y == 1).any() else None,
                 auroc=float(roc_auc_score(y, s)) if len(set(y)) > 1 else None)
        rec = []
        for p in ('beacon', 'brute', 'scan'):
            m = (g.profile == p).values
            r[f'recall_{p}'] = float((s[m] > t1).mean()) if m.any() else None
            if m.any():
                rec.append(r[f'recall_{p}'])
        r['recall_macro'] = float(np.mean(rec)) if rec else None
        m = (y == 1) & (g.hs_complete.values == 1)
        r['recall_tls'] = float((s[m] > t1).mean()) if m.any() else None
        for p in BENIGN:
            m = (g.profile == p).values
            r[f'fpr_{p}'] = float((s[m] > t1).mean()) if m.any() else None
        out[cell] = r
    return out


def thresholds(gd, s, recal):
    base_cal = gd[gd.baseline & gd.rep.isin(CAL) & (gd.y == 0)]
    b1, b5 = thr_at(s[base_cal.index].values, 0.01), thr_at(s[base_cal.index].values, 0.05)
    t1, t5 = {}, {}
    for cell, g in gd.groupby('cell'):
        if recal:
            c = g[g.rep.isin(CAL) & (g.y == 0)]
            t1[cell], t5[cell] = thr_at(s[c.index].values, 0.01), thr_at(s[c.index].values, 0.05)
        else:
            t1[cell], t5[cell] = b1, b5
    return t1, t5


def supervised(df, cols, name, extra_train=None, recal=False, models_=None):
    res = {}
    for grp, gd in df.groupby('group'):
        base = gd[gd.baseline]
        tr = base[base.rep.isin(TRAIN)]
        if extra_train is not None:
            tr = pd.concat([tr, extra_train(gd)])
        X = gd[cols].fillna(0).values
        for mn, mk in models().items():
            if models_ and mn not in models_:
                continue
            clf = mk().fit(tr[cols].fillna(0).values, tr.y.values)
            s = pd.Series(clf.predict_proba(X)[:, 1], index=gd.index)
            t1, t5 = thresholds(gd, s, recal)
            res[f'{mn}|{grp}'] = per_cell(gd, s, t1, t5, tag=f'{name}|{mn}')
            res[f'{mn}|{grp}']['_n_train'] = int(len(tr))
    return res


def anomaly(df, cols, name):
    res = {}
    for grp, gd in df.groupby('group'):
        base = gd[gd.baseline]
        tr = base[base.rep.isin(TRAIN) & (base.y == 0)]
        pipe = make_pipeline(FunctionTransformer(slog), StandardScaler()).fit(tr[cols].fillna(0).values)
        iso = IsolationForest(n_estimators=300, random_state=SEED).fit(pipe.transform(tr[cols].fillna(0).values))
        s = pd.Series(-iso.score_samples(pipe.transform(gd[cols].fillna(0).values)), index=gd.index)
        t1, t5 = thresholds(gd, s, False)
        res[f'iforest|{grp}'] = per_cell(gd, s, t1, t5, tag=name)
    return res


def byte_cnn(df, X8, epochs=15):
    import torch, torch.nn as nn
    dev = 'cuda' if torch.cuda.is_available() else 'cpu'
    torch.manual_seed(SEED)
    res = {}
    for grp, gd in df.groupby('group'):
        base = gd[gd.baseline]
        tr = base[base.rep.isin(TRAIN)]

        class Net(nn.Module):
            def __init__(s):
                super().__init__()
                s.emb = nn.Embedding(256, 16)
                s.conv = nn.Sequential(nn.Conv1d(16, 64, 5, padding=2), nn.ReLU(), nn.MaxPool1d(4),
                                       nn.Conv1d(64, 64, 5, padding=2), nn.ReLU(), nn.AdaptiveMaxPool1d(1))
                s.fc = nn.Linear(64, 1)

            def forward(s, x):  # x: (B, 600)
                return s.fc(s.conv(s.emb(x).transpose(1, 2)).squeeze(-1)).squeeze(-1)
        net = Net().to(dev)
        idx = gd.index.get_indexer(tr.index)
        sub = X8[gd.index.values]
        xt = torch.tensor(sub[idx].reshape(len(tr), -1), dtype=torch.long)
        yt = torch.tensor(tr.y.values, dtype=torch.float32)
        opt = torch.optim.Adam(net.parameters(), 1e-3)
        lossf = nn.BCEWithLogitsLoss()
        for ep in range(epochs):
            perm = torch.randperm(len(xt))
            for k in range(0, len(xt), 256):
                i = perm[k:k + 256]
                opt.zero_grad(); l = lossf(net(xt[i].to(dev)), yt[i].to(dev)); l.backward(); opt.step()
        net.eval()
        with torch.no_grad():
            xa = torch.tensor(sub.reshape(len(gd), -1), dtype=torch.long)
            s = torch.cat([torch.sigmoid(net(xa[k:k + 1024].to(dev))).cpu() for k in range(0, len(xa), 1024)]).numpy()
        s = pd.Series(s, index=gd.index)
        t1, t5 = thresholds(gd, s, False)
        res[f'bytecnn|{grp}'] = per_cell(gd, s, t1, t5, tag='bytecnn')
    return res


def fingerprints(df):
    out = {}
    for grp, gd in df.groupby('group'):
        base = gd[gd.baseline]
        for fp in ('ja3', 'client_fingerprint'):
            if fp not in gd or gd[fp].isna().all():
                continue
            known = set(base[fp].dropna())
            for cell, g in gd.groupby('cell'):
                v = g[fp].dropna()
                out[f'{fp}|{cell}'] = dict(n=int(len(v)), coverage=float(v.isin(known).mean()) if len(v) else None,
                                           distinct=int(v.nunique()), value=v.mode().iloc[0] if len(v) else None)
        for cell, g in gd.groupby('cell'):
            out[f'sni|{cell}'] = dict(sni=g.requested_server_name.dropna().mode().iloc[0]
                                      if g.requested_server_name.notna().any() else None)
    return out


def psi(a, b, bins=10, eps=1e-3):
    """Population stability index. Low-cardinality features (<= 12 distinct values in the union) are treated
    as categorical; otherwise baseline-quantile bins with open outer edges."""
    vals = np.union1d(np.unique(a), np.unique(b))
    if len(vals) <= 12:
        ea = np.array([(a == v).mean() for v in vals]) + eps
        eb = np.array([(b == v).mean() for v in vals]) + eps
    else:
        q = np.unique(np.quantile(a, np.linspace(0, 1, bins + 1))[1:-1])
        edges = np.concatenate([[-np.inf], q, [np.inf]])
        ea = np.histogram(a, edges)[0] / len(a) + eps
        eb = np.histogram(b, edges)[0] / len(b) + eps
    ea, eb = ea / ea.sum(), eb / eb.sum()
    return float(((eb - ea) * np.log(eb / ea)).sum())


def shift(df, cols):
    """PSI/KS per feature between each group's baseline and each single-factor migration (benign flows)."""
    out = {}
    for grp, gd in df.groupby('group'):
        b = gd[gd.baseline & (gd.y == 0)]
        for fac, val in (('kx', 'hybrid'), ('cert', 'mldsa'), ('ech', 'on')):
            m = gd[(gd[fac] == val) & (gd.y == 0)]
            for f2, v2 in (('kx', 'classical'), ('cert', 'ecdsa'), ('ech', 'off')):
                if f2 != fac:
                    m = m[m[f2] == v2]
            if not len(m):
                continue
            rows = {}
            for c in cols:
                a, z = b[c].fillna(0).values.astype(float), m[c].fillna(0).values.astype(float)
                rows[c] = dict(psi=psi(a, z), ks=float(ks_2samp(a, z).statistic))
            out[f'{grp}|{fac}'] = rows
    return out


def main():
    df, X8 = load()
    fs = feature_sets(df)
    print('fold', FOLD, 'flows', len(df), 'cells', df.cell.nunique(), 'features', {k: len(v) for k, v in fs.items()}, flush=True)
    comp = df[df.hs_complete == 1]
    ev = dict(fold=FOLD, n_flows=len(df), cells=sorted(df.cell.unique()), features={k: len(v) for k, v in fs.items()},
              flows_per_cell=df.groupby('cell').size().to_dict(),
              flows_profile=df.groupby(['cell', 'profile']).size().unstack(fill_value=0).to_dict(orient='index'),
              hs=comp.groupby('cell')[['ch_len', 'ks_bytes', 'hs_c2s_bytes', 'hs_s2c_bytes', 'hs_pkts', 'hs_dur']]
                  .median().to_dict(orient='index'))
    ev['sup_nfs'] = supervised(df, fs['nfs'], 'nfs')
    ev['recal_nfs'] = supervised(df, fs['nfs'], 'recal', recal=True)                    # R0
    ev['sup_post'] = supervised(df, fs['post'], 'post')                                 # R1
    ev['sup_post_nohs'] = supervised(df, fs['post_nohs'], 'post_nohs')                  # R1 ablation
    ev['sup_full'] = supervised(df, fs['full'], 'full')                                 # control: own extractor, whole flow
    ev['sup_nosplt'] = supervised(df, fs['nosplt'], 'nosplt')                           # R1b
    for k in (0.01, 0.05, 0.10):
        def extra(gd, k=k):
            pool = gd[~gd.baseline & gd.rep.isin(POOL)]
            return pool.sample(frac=k, random_state=SEED) if len(pool) else pool

        def extra_bal(gd, k=k):
            pool = gd[~gd.baseline & gd.rep.isin(POOL)]
            ben = pool[pool.y == 0].sample(frac=k, random_state=SEED)
            mal = pool[pool.y == 1]
            return pd.concat([ben, mal.sample(n=min(len(ben), len(mal)), random_state=SEED)])
        ev[f'fewshot_{int(k * 100)}'] = supervised(df, fs['nfs'], f'fewshot{int(k * 100)}', extra)           # R2
        ev[f'fewshotbal_{int(k * 100)}'] = supervised(df, fs['nfs'], f'fewshotbal{int(k * 100)}', extra_bal)  # R2b
        ev[f'fewshotrecal_{int(k * 100)}'] = supervised(df, fs['nfs'], f'fewshotrecal{int(k * 100)}', extra,  # R2r
                                                        recal=True)
    ev['retrain_all'] = supervised(df, fs['nfs'], 'retrain', lambda gd: gd[~gd.baseline & gd.rep.isin(POOL)])  # R3
    ev['iforest_nfs'] = anomaly(df, fs['nfs'], 'iforest|nfs')
    ev['bytecnn'] = byte_cnn(df, X8)
    if FOLD == 0:
        ev['fingerprints'] = fingerprints(df)
        ev['shift'] = shift(df, fs['nfs'])
        pd.concat(PRED, ignore_index=True).to_csv(R / 'b_pred.csv.gz', index=False, compression='gzip')
    out = R / ('b_eval.json' if FOLD == 0 else f'b_eval_f{FOLD}.json')
    json.dump(ev, open(out, 'w'), indent=1, default=float)
    print('saved', out.name)


if __name__ == '__main__':
    main()
