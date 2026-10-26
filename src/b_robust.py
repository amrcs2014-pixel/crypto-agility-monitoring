"""Paper B, referee round 2 (M2a, M6, M7a): robustness analyses on the existing flow tables and predictions.

1. Base rates (M2a). The testbed's test sets are 76-84 % malicious. Precision at a realistic prevalence pi follows from
   recall R and false-positive rate F: precision = pi R / (pi R + (1 - pi) F). Computed for pi = 1 % and 5 %, pooled over
   the 21 migrated cells (and over the 3 baseline cells), at the 1 % FPR threshold with a run-level bootstrap
   (results/b_pred.csv.gz, main fold) and at the 5 % FPR threshold from the per-cell counts of every fold.
   Also reported: false alerts per 10,000 benign flows.
2. Per-cell intervals (M6b). Run-level bootstrap (2,000 resamples of the (profile, repetition) runs of a cell) for recall
   and FPR at the 1 % threshold, no repair vs R1, every model and cell (main fold).
3. Seed variability (M6c). Five model seeds per fold (results/b_eval_f<k>_s<r>.json, from `b_detect.py <fold> <rep>`;
   rep 0 is the published run): range over seeds of the mean recall and FPR over the migrated cells and of the lowest
   per-cell recall, for no repair, R0, R1, R2r (5 %) and R3.
4. Shift alarm (M7a). How many unlabelled flows after a migration a monitor needs before a two-sample test fires.
   Reference: all baseline flows of the training repetitions. A window is n flows drawn at random from the test
   repetitions of a cell (class mix as captured). Alarm: a two-sample Kolmogorov-Smirnov test on any of the 77 NFStream
   features at Bonferroni-corrected alpha = 0.01 (critical value from the KS distribution at the effective sample size),
   the same test on the size and count features only (no durations or inter-arrival times), or PSI > 0.25 on any feature. Power = share of
   300 windows that alarm on a migrated cell; false-alarm rate = the same on windows of the baseline's own test flows.
Output: results/b_robust.json
"""
import json, sys, warnings
from pathlib import Path
import numpy as np
import pandas as pd
from scipy.stats import kstwo

warnings.filterwarnings('ignore')
sys.argv = [sys.argv[0], '0']
import b_detect as bd  # noqa: E402

R = Path(__file__).resolve().parents[1] / 'results'
RNG = np.random.default_rng(19)
MODELS = ('lgbm', 'rf', 'mlp')
PIPES = {'none': ('nfs', 'sup_nfs'), 'R0': ('recal', 'recal_nfs'), 'R1': ('post', 'sup_post'),
         'R2r5': ('fewshotrecal5', 'fewshotrecal_5'), 'R3': ('retrain', 'retrain_all')}
PIS = (0.01, 0.05)
NBOOT = 2000


def is_base(cell):
    return '-classical-ecdsa-echoff' in cell


def prec(r, f, pi):
    den = pi * r + (1 - pi) * f
    return float(pi * r / den) if den > 0 else None


# ------------------------------------------------------------------ 1 + 2: bootstrap from per-flow alerts
def run_table(pred):
    """Per (tag, cell, profile, rep): alerts and flows by class -> run-level units for the bootstrap."""
    g = pred.groupby(['tag', 'cell', 'profile', 'rep', 'y']).alert.agg(['sum', 'count']).reset_index()
    return g


def boot_pool(units):
    """units: rows of one tag over a set of cells. Resample runs within (cell, class); return dict of metrics + CIs."""
    mal, ben = units[units.y == 1], units[units.y == 0]
    def stat(m, b):  # pooled recall and FPR
        r = m['sum'].sum() / m['count'].sum(); f = b['sum'].sum() / b['count'].sum()
        return r, f
    r0, f0 = stat(mal, ben)

    def resample(part):
        """sum of alerts and of flows per bootstrap replicate, runs resampled within each cell"""
        s_tot, c_tot = np.zeros(NBOOT), np.zeros(NBOOT)
        for _, d in part.groupby('cell'):
            i = RNG.integers(0, len(d), (NBOOT, len(d)))
            s_tot += d['sum'].values[i].sum(1); c_tot += d['count'].values[i].sum(1)
        return s_tot / c_tot
    reps = np.column_stack([resample(mal), resample(ben)])
    out = dict(recall=r0, fpr=f0, n_benign=int(ben['count'].sum()), n_mal=int(mal['count'].sum()),
               recall_ci=list(np.percentile(reps[:, 0], [2.5, 97.5])), fpr_ci=list(np.percentile(reps[:, 1], [2.5, 97.5])),
               false_per_10k=1e4 * f0, false_per_10k_ci=list(1e4 * np.percentile(reps[:, 1], [2.5, 97.5])))
    for pi in PIS:
        ps = [prec(r, f, pi) for r, f in reps]
        ps = [p for p in ps if p is not None]
        out[f'prec_{int(pi * 100)}'] = prec(r0, f0, pi)
        out[f'prec_{int(pi * 100)}_ci'] = list(np.percentile(ps, [2.5, 97.5])) if ps else None
    # when no benign flow alerted: rule-of-three upper bound on FPR -> lower bound on precision
    if f0 == 0:
        fu = 3 / out['n_benign']
        out['fpr_upper_rule3'] = fu
        for pi in PIS:
            out[f'prec_{int(pi * 100)}_lower_rule3'] = prec(r0, fu, pi)
    return out


def base_rates(units):
    res = {}
    for pipe, (tag, _) in PIPES.items():
        for mn in MODELS:
            u = units[units.tag == f'{tag}|{mn}']
            res[f'{pipe}|{mn}|migrated'] = boot_pool(u[~u.cell.map(is_base)])
            res[f'{pipe}|{mn}|baseline'] = boot_pool(u[u.cell.map(is_base)])
    return res


def base_rates_5(folds):
    """5 % FPR threshold, pooled over migrated cells, per fold (point estimates from per-cell counts)."""
    res = {}
    for k, ev in folds.items():
        for pipe, (_, key) in PIPES.items():
            for mn in MODELS:
                rows = [v for gk, d in ev[key].items() if gk.startswith(mn + '|') for c, v in d.items()
                        if not c.startswith('_') and not is_base(c)]
                nb = sum(v['n_benign'] for v in rows); nm = sum(v['n'] - v['n_benign'] for v in rows)
                r = sum(v['recall5'] * (v['n'] - v['n_benign']) for v in rows) / nm
                f = sum(v['fpr5'] * v['n_benign'] for v in rows) / nb
                r1 = sum(v['recall'] * (v['n'] - v['n_benign']) for v in rows) / nm
                f1 = sum(v['fpr'] * v['n_benign'] for v in rows) / nb
                res[f'{k}|{pipe}|{mn}'] = dict(recall5=r, fpr5=f, prec5_1=prec(r, f, 0.01), prec5_5=prec(r, f, 0.05),
                                               recall1=r1, fpr1=f1, prec1_1=prec(r1, f1, 0.01), prec1_5=prec(r1, f1, 0.05),
                                               min_cell_recall5=min(v['recall5'] for v in rows),
                                               min_cell_recall1=min(v['recall'] for v in rows))
    return res


def per_cell_ci(units):
    res = {}
    for pipe in ('none', 'R1'):
        tag = PIPES[pipe][0]
        for mn in MODELS:
            u = units[units.tag == f'{tag}|{mn}']
            for cell, d in u.groupby('cell'):
                m, b = d[d.y == 1], d[d.y == 0]
                r0 = m['sum'].sum() / m['count'].sum(); f0 = b['sum'].sum() / b['count'].sum()
                ri = RNG.integers(0, len(m), (NBOOT, len(m))); bi = RNG.integers(0, len(b), (NBOOT, len(b)))
                ms, mc, bs, bc = m['sum'].values, m['count'].values, b['sum'].values, b['count'].values
                rr = ms[ri].sum(1) / mc[ri].sum(1); ff = bs[bi].sum(1) / bc[bi].sum(1)
                res[f'{pipe}|{mn}|{cell}'] = dict(recall=r0, recall_ci=list(np.percentile(rr, [2.5, 97.5])),
                                                  fpr=f0, fpr_ci=list(np.percentile(ff, [2.5, 97.5])),
                                                  n_mal=int(mc.sum()), n_benign=int(bc.sum()),
                                                  n_mal_runs=len(m), n_benign_runs=len(b))
    return res


# ------------------------------------------------------------------ 3: seeds
def seeds():
    res = {}
    for k in (0, 1, 2):
        evs = {0: json.load(open(R / ('b_eval.json' if k == 0 else f'b_eval_f{k}.json')))}
        for s in (1, 2, 3, 4):
            p = R / f'b_eval_f{k}_s{s}.json'
            if p.exists():
                evs[s] = json.load(open(p))
        for pipe, (_, key) in PIPES.items():
            for mn in MODELS:
                per = {}
                for s, ev in evs.items():
                    rows = [v for gk, d in ev[key].items() if gk.startswith(mn + '|') for c, v in d.items()
                            if not c.startswith('_') and not is_base(c)]
                    base = [v for gk, d in ev[key].items() if gk.startswith(mn + '|') for c, v in d.items()
                            if not c.startswith('_') and is_base(c)]
                    per[s] = dict(recall=float(np.mean([v['recall'] for v in rows])), fpr=float(np.mean([v['fpr'] for v in rows])),
                                  recall5=float(np.mean([v['recall5'] for v in rows])), fpr5=float(np.mean([v['fpr5'] for v in rows])),
                                  min_cell_recall=float(min(v['recall'] for v in rows)),
                                  max_cell_fpr=float(max(v['fpr'] for v in rows)),
                                  base_min_recall=float(min(v['recall'] for v in base)))
                res[f'{k}|{pipe}|{mn}'] = dict(n_seeds=len(per), per_seed=per,
                                               **{f'{m}_range': [min(p[m] for p in per.values()), max(p[m] for p in per.values())]
                                                  for m in ('recall', 'fpr', 'recall5', 'fpr5', 'min_cell_recall',
                                                            'max_cell_fpr', 'base_min_recall')})
    return res


# ------------------------------------------------------------------ 4: shift alarm
NS = (5, 10, 20, 50, 100, 200)
NWIN = 300


def ks_stat(ref_sorted, win):
    """two-sample KS statistic between a sorted reference (1-D) and each row of win (K x n)."""
    m, (K, n) = len(ref_sorted), win.shape
    ws = np.sort(win, axis=1)
    pts = np.concatenate([np.broadcast_to(ref_sorted, (K, m)), ws], axis=1)       # evaluate both ECDFs at all points
    fr = np.searchsorted(ref_sorted, pts, side='right') / m
    fw = np.stack([np.searchsorted(ws[i], pts[i], side='right') for i in range(K)]) / n
    return np.abs(fr - fw).max(1)


def psi_win(ref, win, bins=10):
    edges = np.unique(np.quantile(ref, np.linspace(0, 1, bins + 1))[1:-1])
    if len(np.unique(ref)) <= 12:
        vals = np.unique(ref)
        idx_r = np.searchsorted(vals, ref); idx_w = np.searchsorted(vals, win)
        nb = len(vals) + 1
    else:
        idx_r = np.searchsorted(edges, ref, side='right'); idx_w = np.searchsorted(edges, win, side='right')
        nb = len(edges) + 1
    pr = np.bincount(idx_r, minlength=nb) / len(ref)
    pw = np.stack([np.bincount(r, minlength=nb) for r in idx_w]) / win.shape[1]
    pr, pw = np.clip(pr, 1e-4, None), np.clip(pw, 1e-4, None)
    return ((pw - pr) * np.log(pw / pr)).sum(1)


def shift_alarm():
    df, _ = bd.load()
    cols = bd.feature_sets(df)['nfs']
    alpha = 0.01 / len(cols)
    size_cols = [j for j, c in enumerate(cols) if not any(s in c for s in ('iat', 'duration', '_ms'))]
    alpha_s = 0.01 / len(size_cols)
    out = {}
    for grp, gd in df.groupby('group'):
        ref = gd[gd.baseline & gd.rep.isin(bd.TRAIN)][cols].fillna(0).values.astype(float)
        refs = [np.sort(ref[:, j]) for j in range(len(cols))]
        m = len(ref)
        for cell, g in gd[gd.rep.isin(bd.TEST)].groupby('cell'):
            X = g[cols].fillna(0).values.astype(float)
            for n in NS:
                if n > len(X):
                    continue
                idx = np.stack([RNG.choice(len(X), n, replace=False) for _ in range(NWIN)])
                ks_alarm = np.zeros(NWIN, bool); psi_alarm = np.zeros(NWIN, bool); kss_alarm = np.zeros(NWIN, bool)
                crit = kstwo.isf(alpha, round(m * n / (m + n)))                    # KS critical D at the effective n
                crit_s = kstwo.isf(alpha_s, round(m * n / (m + n)))
                for j in range(len(cols)):
                    W = X[idx, j]
                    d = ks_stat(refs[j], W)
                    ks_alarm |= d > crit
                    if j in size_cols:
                        kss_alarm |= d > crit_s
                    psi_alarm |= psi_win(ref[:, j], W) > 0.25
                out[f'{grp}|{cell}|{n}'] = dict(ks=float(ks_alarm.mean()), ks_size=float(kss_alarm.mean()),
                                                  psi=float(psi_alarm.mean()), n_size_features=len(size_cols))
        print('shift alarm', grp, flush=True)
    return out


def main():
    pred = pd.read_csv(R / 'b_pred.csv.gz')
    units = run_table(pred)
    folds = {0: json.load(open(R / 'b_eval.json')), 1: json.load(open(R / 'b_eval_f1.json')),
             2: json.load(open(R / 'b_eval_f2.json'))}
    res = dict(base_rates=base_rates(units)); print('base rates', flush=True)
    res['base_rates_5'] = base_rates_5(folds)
    res['per_cell_ci'] = per_cell_ci(units); print('per-cell CIs', flush=True)
    res['seeds'] = seeds()
    res['shift_alarm'] = shift_alarm()
    json.dump(res, open(R / 'b_robust.json', 'w'), indent=1, default=float)
    print('saved b_robust.json')


if __name__ == '__main__':
    main()
