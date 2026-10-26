"""Paper B, reviewer M3a: is the R1 repair robust when the malicious application data is padded or benign-sized?

New captures (lab/b_twin.py with ONLY=beacon_rand,brute_rand,beacon_mimic; same cells, seeds, schedule and server):
  beacon_rand   beacon with random request padding (0-1,024 B) and random response size (64-16,384 B)
  brute_rand    credential guessing with a randomly padded form (0-4,096 B); the victim's reply is unchanged
  beacon_mimic  beacon timing with the request and response sizes of the benign many_short profile
Flows: data/b_flows_pad/<cell>.csv.gz (lab/b_extract.py). Benign flows and scans come from the original captures of
the same cell; flows are per-connection, so composing them across captures does not change any flow's features.

Worlds: rand = {beacon_rand, brute_rand, scan}; mimic = {beacon_mimic, brute_rand, scan}; orig = published behaviours.
Regimes (same folds, feature sets, models and thresholds as b_detect.py):
  matched  train on the baseline cell of the same world, test on every cell of that world
           (does R1 still repair the migration when malicious sizes vary or look benign?)
  evasion  train on the original baseline (published behaviours), test on the padded worlds
           (an attacker who pads after the detector was trained, with and without a migration)
Pipelines: none (NFStream features), R0 (threshold on the cell's own benign calibration flows), R1 (post-handshake).
Usage: python b_padding.py [fold] -> results/b_padding.json (fold 0) or results/b_padding_f<k>.json
"""
import json, sys, warnings
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

warnings.filterwarnings('ignore')
FOLD = int(sys.argv[1]) if len(sys.argv) > 1 else 0
sys.argv = [sys.argv[0], str(FOLD)]
import b_detect as bd  # noqa: E402

W = Path(__file__).resolve().parents[1]
FP, R = W / 'data' / 'b_flows_pad', W / 'results'
WORLDS = {'orig': ('beacon', 'brute', 'scan'), 'rand': ('beacon_rand', 'brute_rand', 'scan'),
          'mimic': ('beacon_mimic', 'brute_rand', 'scan')}
BEH = {'beacon': 'beacon', 'brute': 'brute', 'scan': 'scan', 'beacon_rand': 'beacon', 'brute_rand': 'brute',
       'beacon_mimic': 'beacon'}


def load_pad(cols):
    dfs = []
    for f in sorted(FP.glob('*.csv.gz')):
        d = pd.read_csv(f, low_memory=False)
        d = d[(d.profile != 'unknown') & d.protocol.isin([6, 17])].reset_index(drop=True)
        dfs.append(d)
    d = pd.concat(dfs, ignore_index=True)
    d['baseline'] = (d.kx == 'classical') & (d.cert == 'ecdsa') & (d.ech == 'off')
    d['group'] = d['stack'] + '-' + d['transport']
    d['y'] = d.malicious.astype(int)
    d['hs_complete'] = d.hs_complete.fillna(0)
    return d[[c for c in d.columns if c in cols or c in ('cell', 'group', 'baseline', 'y', 'rep', 'profile')]]


def world(df, pad, w):
    """benign flows of the original captures + the malicious behaviours of world w"""
    keep = ['cell', 'group', 'baseline', 'y', 'rep', 'profile'] + FEATS
    if w == 'orig':  # original row order, so that this world reproduces b_detect.py exactly (sanity check)
        return df[keep].reset_index(drop=True)
    ben = df[df.y == 0][keep]
    mal = [df[(df.y == 1) & (df.profile == p)][keep] if p in ('beacon', 'brute', 'scan') else
           pad[(pad.y == 1) & (pad.profile == p)][keep] for p in WORLDS[w]]
    return pd.concat([ben] + mal, ignore_index=True)


def evaluate(train_w, test_w, cols):
    out = {}
    for grp in sorted(test_w.group.unique()):
        tr_g, te_g = train_w[train_w.group == grp], test_w[test_w.group == grp]
        tr = tr_g[tr_g.baseline & tr_g.rep.isin(bd.TRAIN)]
        base_cal = tr_g[tr_g.baseline & tr_g.rep.isin(bd.CAL) & (tr_g.y == 0)]
        for mn, mk in bd.models().items():
            clf = mk().fit(tr[cols].fillna(0).values, tr.y.values)
            s_cal = clf.predict_proba(base_cal[cols].fillna(0).values)[:, 1]
            b1 = bd.thr_at(s_cal, 0.01)
            te = te_g[te_g.rep.isin(bd.TEST)]
            s = clf.predict_proba(te[cols].fillna(0).values)[:, 1]
            own_cal = te_g[te_g.rep.isin(bd.CAL) & (te_g.y == 0)]
            s_own = clf.predict_proba(own_cal[cols].fillna(0).values)[:, 1] if len(own_cal) else None
            te = te.assign(score=s)
            for cell, g in te.groupby('cell'):
                y, sc = g.y.values, g.score.values
                r = {}
                for pipe, thr in (('fixed', b1),
                                  ('recal', bd.thr_at(s_own[own_cal.cell.values == cell], 0.01) if s_own is not None else b1)):
                    r[f'{pipe}_recall'] = float((sc[y == 1] > thr).mean())
                    r[f'{pipe}_fpr'] = float((sc[y == 0] > thr).mean())
                    for b in ('beacon', 'brute', 'scan'):
                        m = (g.y.values == 1) & g.profile.map(BEH).eq(b).values
                        r[f'{pipe}_recall_{b}'] = float((sc[m] > thr).mean()) if m.any() else None
                r['auroc'] = float(roc_auc_score(y, sc)) if len(set(y)) > 1 else None
                r['n_mal'] = int((y == 1).sum()); r['n_benign'] = int((y == 0).sum())
                out[f'{mn}|{cell}'] = r
    return out


def main():
    global FEATS
    df, _ = bd.load()
    fs = bd.feature_sets(df)
    FEATS = sorted(set(fs['nfs']) | set(fs['post']))
    pad = load_pad(set(FEATS))
    print('fold', FOLD, 'padded flows', len(pad), pad.profile.value_counts().to_dict(), flush=True)
    worlds = {w: world(df, pad, w) for w in WORLDS}
    res = dict(fold=FOLD, n_pad=pad.profile.value_counts().to_dict(), n_cells=int(pad.cell.nunique()))
    for feat, fk in (('nfs', 'none'), ('post', 'R1')):
        cols = fs[feat]
        for w in ('orig', 'rand', 'mimic'):
            res[f'matched|{fk}|{w}'] = evaluate(worlds[w], worlds[w], cols)          # train and test in world w
            print('matched', fk, w, flush=True)
        for w in ('rand', 'mimic'):
            res[f'evasion|{fk}|{w}'] = evaluate(worlds['orig'], worlds[w], cols)     # trained on the published behaviours
            print('evasion', fk, w, flush=True)
    out = R / ('b_padding.json' if FOLD == 0 else f'b_padding_f{FOLD}.json')
    json.dump(res, open(out, 'w'), indent=1)
    print('saved', out.name)


if __name__ == '__main__':
    main()
