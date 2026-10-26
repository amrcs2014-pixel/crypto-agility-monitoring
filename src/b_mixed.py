"""Paper B, reviewer M1: uneven (mixed and staggered) migration of the CLIENT-side factors.

The certificate is a property of the server: every client of the monitored server sees the same certificate, so it
cannot migrate unevenly between benign clients and attackers. Key exchange and ECH are client-side choices, and
real deployments migrate them unevenly: browsers and libraries of benign clients update first while malware and
attack tools may keep an older TLS stack, or the reverse. With the server unchanged (ECDSA), the testbed captured
every behaviour under every client configuration with the same seeded runs, so such deployments are composed
from the existing captures, for each client-side migrated cell c (KX, ECH, KX+ECH; ECDSA server):

  full            benign @ c          + malicious @ c          (everyone migrated; reference)
  benign_first    benign @ c          + malicious @ baseline   (attackers keep the old stack)
  attacker_first  benign @ baseline   + malicious @ c          (benign clients lag)

Pipelines (same splits, features, models and thresholds as b_detect.py):
  none   NFStream features, trained on the baseline, baseline threshold
  R0     as 'none', threshold re-set on the deployment's own clean benign calibration flows
  R1     post-handshake statistics + handshake flag, trained on the baseline, baseline threshold
  stag_nfs / stag_post   STAGGERED: retrained on the baseline training flows plus the migrated benign flows of the
         training repetitions (benign-first deployment; its malicious flows are the baseline's, already included),
         threshold re-set on the migrated benign flows of the calibration repetitions (disjoint from training);
         tested on benign_first and on full (the attackers have migrated too).
Fingerprints: block-list = values seen only for malicious flows of the baseline's TRAINING repetitions; scored on
the TEST repetitions of each world (out of sample).

Note: for per-flow scores with a fixed threshold, the mixed worlds only recombine per-cell results (recall from
the cell of the malicious flows, FPR from the cell of the benign flows); the composition is informative for R0,
for retraining and for fingerprints.
Usage: python b_mixed.py [fold]  -> results/b_mixed.json (fold 0) or results/b_mixed_f<k>.json
"""
import json, sys
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

FOLD = int(sys.argv[1]) if len(sys.argv) > 1 else 0
sys.argv = [sys.argv[0], str(FOLD)]           # b_detect reads the fold from argv at import
import b_detect as bd                          # noqa: E402

WORLDS = ('full', 'benign_first', 'attacker_first')


def compose(gd, base_cell, cell, world, reps, cls=None):
    """Flows of one deployment world restricted to the given repetitions (and optionally one class)."""
    b_cell = cell if world in ('full', 'benign_first') else base_cell
    m_cell = cell if world in ('full', 'attacker_first') else base_cell
    ben = gd[(gd.cell == b_cell) & (gd.y == 0) & gd.rep.isin(reps)]
    mal = gd[(gd.cell == m_cell) & (gd.y == 1) & gd.rep.isin(reps)]
    return ben if cls == 0 else mal if cls == 1 else pd.concat([ben, mal])


def metrics(w, s, t1, t5):
    y = w.y.values; sc = s[w.index].values
    r = dict(n_benign=int((y == 0).sum()), n_mal=int((y == 1).sum()),
             recall=float((sc[y == 1] > t1).mean()), fpr=float((sc[y == 0] > t1).mean()),
             recall5=float((sc[y == 1] > t5).mean()), fpr5=float((sc[y == 0] > t5).mean()),
             auroc=float(roc_auc_score(y, sc)) if len(set(y)) > 1 else None)
    for p in ('beacon', 'brute', 'scan'):
        m = (w.profile == p).values
        r[f'recall_{p}'] = float((sc[m] > t1).mean()) if m.any() else None
    return r


def thr(s, ben):
    v = s[ben.index].values
    return bd.thr_at(v, 0.01), bd.thr_at(v, 0.05)


def fit_score(tr, gd, cols, mk):
    clf = mk().fit(tr[cols].fillna(0).values, tr.y.values)
    return pd.Series(clf.predict_proba(gd[cols].fillna(0).values)[:, 1], index=gd.index)


def fingerprints(gd, base_cell, cell):
    out = {}
    base_tr = gd[(gd.cell == base_cell) & gd.rep.isin(bd.TRAIN)]
    for fp in ('ja3', 'client_fingerprint'):
        if fp not in gd.columns or gd[fp].isna().all():
            continue
        known_ben = set(base_tr[base_tr.y == 0][fp].dropna())
        block = set(base_tr[base_tr.y == 1][fp].dropna()) - known_ben
        for world in WORLDS:
            ben = compose(gd, base_cell, cell, world, bd.TEST, 0)[fp].dropna()
            mal = compose(gd, base_cell, cell, world, bd.TEST, 1)[fp].dropna()
            out[f'{fp}|{world}'] = dict(blocklist_hit=float(mal.isin(block).mean()) if len(mal) else None,
                                        allowlist_miss_benign=float((~ben.isin(known_ben)).mean()) if len(ben) else None,
                                        n_block=len(block))
    return out


def main():
    df, _ = bd.load()
    fs = bd.feature_sets(df)
    TR, CAL, TE = bd.TRAIN, bd.CAL, bd.TEST
    res = dict(fold=FOLD, design='client-side factors only (ECDSA server)', cells={}, fingerprints={})
    for grp, gd in df.groupby('group'):
        base_cell = gd[gd.baseline].cell.iloc[0]
        base_tr = gd[(gd.cell == base_cell) & gd.rep.isin(TR)]
        base_cal_ben = gd[(gd.cell == base_cell) & gd.rep.isin(CAL) & (gd.y == 0)]
        cells = sorted(c for c in gd[(gd.cert == 'ecdsa')].cell.unique() if c != base_cell)   # KX, ECH, KX+ECH
        for mn, mk in bd.models().items():
            s_nfs = fit_score(base_tr, gd, fs['nfs'], mk)
            s_post = fit_score(base_tr, gd, fs['post'], mk)
            t_nfs, t_post = thr(s_nfs, base_cal_ben), thr(s_post, base_cal_ben)
            for cell in cells:
                r = {}
                for world in WORLDS:
                    w = compose(gd, base_cell, cell, world, TE)
                    cal_ben = compose(gd, base_cell, cell, world, CAL, 0)
                    r[f'none|{world}'] = metrics(w, s_nfs, *t_nfs)
                    r[f'R0|{world}'] = metrics(w, s_nfs, *thr(s_nfs, cal_ben))
                    r[f'R1|{world}'] = metrics(w, s_post, *t_post)
                # staggered: retrain while only the benign clients have migrated (training reps only; the
                # benign-first deployment's malicious flows are the baseline's, already in base_tr)
                stag_tr = pd.concat([base_tr, compose(gd, base_cell, cell, 'benign_first', TR, 0)])
                stag_cal = compose(gd, base_cell, cell, 'benign_first', CAL, 0)        # disjoint from training
                for feat, cols in (('stag_nfs', fs['nfs']), ('stag_post', fs['post'])):
                    s = fit_score(stag_tr, gd, cols, mk)
                    t = thr(s, stag_cal)
                    for world in ('benign_first', 'full'):
                        r[f'{feat}|{world}'] = metrics(compose(gd, base_cell, cell, world, TE), s, *t)
                res['cells'][f'{mn}|{grp}|{cell}'] = r
            print(grp, mn, 'done', flush=True)
        for cell in cells:
            res['fingerprints'][f'{grp}|{cell}'] = fingerprints(gd, base_cell, cell)
    out = bd.R / ('b_mixed.json' if FOLD == 0 else f'b_mixed_f{FOLD}.json')
    json.dump(res, open(out, 'w'), indent=1, default=float)
    print('saved', out.name)


if __name__ == '__main__':
    main()
