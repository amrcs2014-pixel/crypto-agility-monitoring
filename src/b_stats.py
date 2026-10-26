"""Paper B: paired statistics on per-flow test predictions (results/b_pred.csv.gz).

1. Paired run-level bootstrap: every cell replays the same (profile, repetition) runs, so the change from the
   stack-transport baseline is computed run by run (recall on malicious runs, FPR on benign runs) and resampled
   over runs (2,000 resamples) -> difference and 95 % CI per migrated cell and detector.
2. Factor model: linear probability model of the alert indicator on the three migrations (and their two-way
   interactions) with stack-transport fixed effects and standard errors clustered by run; fitted separately for
   malicious flows (effect on recall) and benign flows (effect on FPR). Coefficients are percentage-point effects.
Output: results/b_stats.json
"""
import json
from pathlib import Path
import numpy as np
import pandas as pd
import statsmodels.formula.api as smf

W = Path(__file__).resolve().parents[1]
R = W / 'results'
TAGS = ['nfs|lgbm', 'nfs|rf', 'nfs|mlp', 'post|lgbm', 'post|rf', 'post|mlp', 'recal|lgbm', 'recal|rf', 'recal|mlp',
        'bytecnn', 'iforest|nfs', 'nosplt|lgbm', 'full|lgbm', 'post_nohs|lgbm']
RNG = np.random.default_rng(19)


def parse(cell):
    st, tr, kx, cert, ech = cell.split('-')
    return st, tr, kx, cert, ech.replace('ech', '')


def paired(df, nboot=2000):
    out = {}
    for tag, d in df.groupby('tag'):
        if tag not in TAGS:
            continue
        run = d.groupby(['group', 'cell', 'profile', 'rep', 'y']).alert.mean().reset_index()
        for g, rg in run.groupby('group'):
            base_cell = [c for c in rg.cell.unique() if c.endswith('classical-ecdsa-echoff')]
            if not base_cell:
                continue
            base = rg[rg.cell == base_cell[0]].set_index(['profile', 'rep'])
            for c in sorted(rg.cell.unique()):
                if c == base_cell[0]:
                    continue
                cur = rg[rg.cell == c].set_index(['profile', 'rep'])
                j = base.join(cur, lsuffix='_b', rsuffix='_c', how='inner')
                for y, met in ((1, 'recall'), (0, 'fpr')):
                    jj = j[j.y_b == y]
                    if not len(jj):
                        continue
                    diff = (jj.alert_c - jj.alert_b).values
                    bs = [diff[RNG.integers(0, len(diff), len(diff))].mean() for _ in range(nboot)]
                    out[f'{tag}|{c}|{met}'] = dict(base=float(jj.alert_b.mean()), value=float(jj.alert_c.mean()),
                                                   diff=float(diff.mean()), lo=float(np.quantile(bs, 0.025)),
                                                   hi=float(np.quantile(bs, 0.975)), n_runs=int(len(jj)))
    return out


def factor_model(df):
    out = {}
    df = df.copy()
    parts = df.cell.map(parse)
    df['kx'] = [p[2] == 'hybrid' for p in parts]
    df['cert'] = [p[3] == 'mldsa' for p in parts]
    df['ech'] = [p[4] == 'on' for p in parts]
    df['run'] = df.group + '|' + df.profile + '|' + df.rep.astype(str)
    for col in ('kx', 'cert', 'ech'):
        df[col] = df[col].astype(int)
    for tag, d in df.groupby('tag'):
        if tag not in TAGS:
            continue
        for y, met in ((1, 'recall'), (0, 'fpr')):
            dd = d[d.y == y]
            if dd.alert.nunique() < 2:
                continue
            fits = [(dd, 'alert ~ kx + cert + ech + C(group)', 'main'),
                    (dd, 'alert ~ (kx + cert + ech)**2 + C(group)', 'inter')]
            fits += [(dd[dd.group == g], 'alert ~ kx + cert + ech', f'main_{g}') for g in sorted(dd.group.unique())]
            for dd_, form, nm in fits:
                if dd_.alert.nunique() < 2:
                    out[f'{tag}|{met}|{nm}'] = {'constant': float(dd_.alert.mean())}
                    continue
                try:
                    m = smf.ols(form, dd_).fit(cov_type='cluster', cov_kwds={'groups': pd.factorize(dd_.run)[0]})
                    out[f'{tag}|{met}|{nm}'] = {k: dict(coef=float(m.params[k]), lo=float(m.conf_int().loc[k, 0]),
                                                        hi=float(m.conf_int().loc[k, 1]), p=float(m.pvalues[k]))
                                                for k in m.params.index if not k.startswith('C(group)')}
                except Exception as e:
                    out[f'{tag}|{met}|{nm}'] = {'error': repr(e)}
    return out


def main():
    df = pd.read_csv(R / 'b_pred.csv.gz')
    res = dict(paired=paired(df), factors=factor_model(df))
    json.dump(res, open(R / 'b_stats.json', 'w'), indent=1)
    for k, v in res['factors'].items():
        if k.endswith('|main') and 'error' not in v and 'constant' not in v:
            print(k, {t: f"{x['coef']:+.3f} [{x['lo']:+.3f},{x['hi']:+.3f}]" for t, x in v.items()})


if __name__ == '__main__':
    main()
