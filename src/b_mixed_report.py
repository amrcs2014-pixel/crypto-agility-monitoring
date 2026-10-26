"""Summarise results/b_mixed*.json (uneven migration of the client-side factors) -> results/b_mixed_summary.json.

Cell sets (ECDSA server throughout): 'kx' = cells with hybrid key exchange (KX, KX+ECH; 2 per group, 6 in all),
'ech' = ECH-only cells (1 per group, 3 in all). Every aggregate states its cell set; fold ranges use the same set.
"""
import json
from pathlib import Path
import numpy as np

R = Path(__file__).resolve().parents[1] / 'results'
MODELS = ('lgbm', 'rf', 'mlp')
ROWS = [('none', 'full'), ('none', 'benign_first'), ('none', 'attacker_first'),
        ('R0', 'full'), ('R0', 'benign_first'), ('R0', 'attacker_first'),
        ('R1', 'full'), ('R1', 'benign_first'), ('R1', 'attacker_first'),
        ('stag_nfs', 'benign_first'), ('stag_nfs', 'full'), ('stag_post', 'benign_first'), ('stag_post', 'full')]
SETS = {'kx': lambda c: 'hybrid' in c, 'ech': lambda c: 'classical' in c and c.endswith('echon')}
METS = ('recall', 'fpr', 'recall5', 'fpr5', 'auroc')


def agg(res, subset):
    out = {}
    for mn in MODELS:
        for pipe, world in ROWS:
            vals = [v[f'{pipe}|{world}'] for k, v in res['cells'].items()
                    if k.startswith(mn + '|') and subset(k.split('|')[2])]
            d = {m: float(np.mean([x[m] for x in vals if x[m] is not None])) for m in METS}
            d['n_cells'] = len(vals)
            d['min_cell_recall'] = float(min(x['recall'] for x in vals))
            for p in ('beacon', 'brute', 'scan'):
                xs = [x[f'recall_{p}'] for x in vals if x.get(f'recall_{p}') is not None]
                d[f'recall_{p}'] = float(np.mean(xs)) if xs else None
            out[f'{mn}|{pipe}|{world}'] = d
    return out


def main():
    folds = {f: json.load(open(R / ('b_mixed.json' if f == 0 else f'b_mixed_f{f}.json')))
             for f in (0, 1, 2) if (R / ('b_mixed.json' if f == 0 else f'b_mixed_f{f}.json')).exists()}
    S = dict(folds=sorted(folds), design=folds[0].get('design'), sets={})
    for sname, sub in SETS.items():
        per = {f: agg(res, sub) for f, res in folds.items()}
        rng = {}
        for k in per[0]:
            rng[k] = {m: [min(per[f][k][m] for f in per), max(per[f][k][m] for f in per)] for m in ('recall', 'fpr')}
            rng[k]['min_cell_recall'] = min(per[f][k]['min_cell_recall'] for f in per)
        S['sets'][sname] = dict(main=per[0], fold_range=rng, n_cells=per[0][next(iter(per[0]))]['n_cells'])
    # fingerprints (main fold, out of sample), per cell set; JA3 exists for TCP cells only
    fp = folds[0]['fingerprints']
    S['fingerprints'] = {}
    # TCP cells only (the QUIC block-lists are empty: no malicious-only value); KX alone vs KX+ECH
    FPSETS = {'kxonly': lambda c: '-tcp-' in c and 'hybrid' in c and c.endswith('echoff'),
              'kxech': lambda c: '-tcp-' in c and 'hybrid' in c and c.endswith('echon')}
    for sname, sub in FPSETS.items():
        for name in ('ja3', 'client_fingerprint'):
            for world in ('full', 'benign_first', 'attacker_first'):
                vals = [v[f'{name}|{world}'] for k, v in fp.items() if sub(k.split('|')[1]) and f'{name}|{world}' in v
                        and v[f'{name}|{world}']['n_block'] > 0]
                hits = [x['blocklist_hit'] for x in vals if x['blocklist_hit'] is not None]
                S['fingerprints'][f'{sname}|{name}|{world}'] = dict(
                    blocklist_hit=float(np.mean(hits)) if hits else None, n_cells=len(hits))
    json.dump(S, open(R / 'b_mixed_summary.json', 'w'), indent=1)
    for sname in SETS:
        A, FR = S['sets'][sname]['main'], S['sets'][sname]['fold_range']
        print(f"\n== cell set '{sname}' ({S['sets'][sname]['n_cells']} cells), main fold recall / FPR | fold range of recall | min cell recall over folds")
        for pipe, world in ROWS:
            print(f'{pipe + "|" + world:24s}' + ''.join(
                f"{A[f'{m}|{pipe}|{world}']['recall']:5.2f}/{A[f'{m}|{pipe}|{world}']['fpr']:4.2f} "
                f"[{FR[f'{m}|{pipe}|{world}']['recall'][0]:.2f}-{FR[f'{m}|{pipe}|{world}']['recall'][1]:.2f}] "
                f"min {FR[f'{m}|{pipe}|{world}']['min_cell_recall']:.2f} | " for m in MODELS))
    print('\nfingerprint block-lists (out of sample, main fold):')
    for k, v in S['fingerprints'].items():
        print(f'  {k:40s} hit {v["blocklist_hit"]}  cells {v["n_cells"]}')


if __name__ == '__main__':
    main()
