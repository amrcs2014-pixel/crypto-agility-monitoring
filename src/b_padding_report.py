"""Paper B, reviewer M3a: macros and Supplementary Table S18 from results/b_padding*.json (b_padding.py)."""
import json
from pathlib import Path
import numpy as np

R = Path(__file__).resolve().parents[1] / 'results'
MK = {'lgbm': 'Lgbm', 'rf': 'Rf', 'mlp': 'Mlp'}
MN = {'lgbm': 'LightGBM', 'rf': 'Random forest', 'mlp': 'MLP'}
WK = {'orig': 'Orig', 'rand': 'Rand', 'mimic': 'Mimic'}
NL = '\n'


def mac(n, v):
    return f'\\newcommand{{\\{n}}}{{{v}}}\n'


def f2(x):
    return '--' if x is None or (isinstance(x, float) and np.isnan(x)) else f'{x:.2f}'


def fl(x):
    return f'{np.floor(100 * x + 1e-9) / 100:.2f}'


def rng(lo, hi):
    return f2(lo) if f2(lo) == f2(hi) else f'{f2(lo)}--{f2(hi)}'


def is_base(cell):
    return cell.endswith('classical-ecdsa-echoff')


def load():
    folds = {}
    for k in (0, 1, 2):
        p = R / ('b_padding.json' if k == 0 else f'b_padding_f{k}.json')
        if p.exists():
            folds[k] = json.load(open(p))
    return folds


def agg(res, model, part, thr='fixed'):
    """mean over the baseline (part='base') or migrated (part='mig') cells of one model"""
    rows = [v for k, v in res.items() if k.startswith(model + '|') and (is_base(k.split('|')[1]) == (part == 'base'))]
    def m(key):
        xs = [r[key] for r in rows if r.get(key) is not None]
        return float(np.mean(xs)) if xs else None
    return dict(recall=m(f'{thr}_recall'), fpr=m(f'{thr}_fpr'), beacon=m(f'{thr}_recall_beacon'),
                brute=m(f'{thr}_recall_brute'), scan=m(f'{thr}_recall_scan'), auroc=m('auroc'),
                min_cell=min(r[f'{thr}_recall'] for r in rows), n=len(rows))


def summary():
    F = load()
    if not F:
        return None
    S = {}
    for k, res in F.items():
        for key, d in res.items():
            if not isinstance(d, dict) or not key.startswith(('matched', 'evasion')):
                continue
            for m in MK:
                for part in ('base', 'mig'):
                    S[f'{k}|{key}|{m}|{part}'] = agg(d, m, part)
                    if key.split('|')[1] == 'none':
                        S[f'{k}|{key}|{m}|{part}|R0'] = agg(d, m, part, 'recal')
    return S, sorted(F)


def macros():
    s = summary()
    if s is None:
        return []
    S, folds = s
    out = [mac('PdNfolds', len(folds))]
    # R1 trained on randomly padded attacks: per-cell FPR in the Go/QUIC ML-DSA cells vs every other migrated cell
    F = load()
    for m, mk in MK.items():
        q, o = [], []
        for k in folds:
            d = F[k]['matched|R1|rand']
            q.append([v['fixed_fpr'] for c, v in d.items() if c.startswith(f'{m}|go-quic') and 'mldsa' in c])
            o.append([v['fixed_fpr'] for c, v in d.items() if c.startswith(m + '|') and not is_base(c.split('|')[1])
                      and not (c.split('|')[1].startswith('go-quic') and 'mldsa' in c)])
        out += [mac(f'PdRandQuicCertFpr{mk}', rng(min(min(x) for x in q), max(max(x) for x in q))),
                mac(f'PdRandOtherMaxFpr{mk}', f2(max(max(x) for x in o)))]
        out.append(mac(f'PdRandQuicCertFlood{mk}', sum(1 for x in q if max(x) > 0.25)))
    for reg in ('matched', 'evasion'):
        for pipe, pk in (('none', 'None'), ('R1', 'Rone')):
            for w in (('orig', 'rand', 'mimic') if reg == 'matched' else ('rand', 'mimic')):
                for m, mk in MK.items():
                    for part, ptk in (('base', 'Base'), ('mig', 'Mig')):
                        vs = [S[f'{k}|{reg}|{pipe}|{w}|{m}|{part}'] for k in folds]
                        base = f'Pd{reg.capitalize()}{pk}{WK[w]}{mk}{ptk}'
                        for met, mt in (('recall', 'Rec'), ('fpr', 'Fpr'), ('beacon', 'Beacon'), ('brute', 'Brute')):
                            xs = [v[met] for v in vs if v[met] is not None]
                            out.append(mac(base + mt, rng(min(xs), max(xs)) if xs else '--'))
                        out.append(mac(base + 'MinCell', fl(min(v['min_cell'] for v in vs))))
    return out


def si_section(t, longtab):
    s = summary()
    if s is None:
        return ''
    S, folds = s
    rows = []
    for reg, rn in (('matched', 'trained on the same behaviours'), ('evasion', 'trained on the published behaviours')):
        for w in (('orig', 'rand', 'mimic') if reg == 'matched' else ('rand', 'mimic')):
            for pipe, pn in (('none', 'none'), ('R1', 'R1')):
                for m in MK:
                    cells = []
                    for part in ('base', 'mig'):
                        vs = [S[f'{k}|{reg}|{pipe}|{w}|{m}|{part}'] for k in folds]
                        def r(met):
                            xs = [v[met] for v in vs if v[met] is not None]
                            return rng(min(xs), max(xs)) if xs else '--'
                        cells.append(f"{r('recall')} / {r('fpr')} / {r('beacon')} / {r('brute')}")
                    rows.append(f"{rn} & {w} & {pn} & {MN[m]} & {cells[0]} & {cells[1]}\\\\")
    return ('\\section*{S11 Padded and benign-sized attacks}' + longtab(
        'llll' + 'rr', 'Training & Attacks & Pipeline & Model & Baseline cells & Migrated cells', rows,
        'Padded and benign-sized attacks: mean over cells of recall / FPR / beacon recall / guessing recall (thresholds at 1\\,\\% FPR), range over '
        f'{len(folds)} folds. Attacks: orig = published behaviours; rand = beacon with random request padding (0--1,024 B) and '
        'response size (64--16,384 B), credential guessing with a randomly padded form (0--4,096 B); mimic = beacon with the request '
        'and response sizes of the benign short-connection profile, with the same padded guessing. Scans are unchanged. Benign '
        'flows are the published ones.'))
