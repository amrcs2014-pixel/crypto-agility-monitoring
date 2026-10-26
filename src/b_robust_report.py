"""Paper B, referee round 2: macros (appended to numbers_B.tex by b_report.py) and Supplementary Section S10 tables
from results/b_robust.json (written by b_robust.py)."""
import json
from pathlib import Path
import numpy as np

R = Path(__file__).resolve().parents[1] / 'results'
NL = '\n'
MK = {'lgbm': 'Lgbm', 'rf': 'Rf', 'mlp': 'Mlp'}
MN = {'lgbm': 'LightGBM', 'rf': 'Random forest', 'mlp': 'MLP'}
PK = {'none': 'None', 'R0': 'Rzero', 'R1': 'Rone', 'R2r5': 'Rtworb', 'R3': 'Rthree'}
PN = {'none': 'No repair', 'R0': 'R0', 'R1': 'R1', 'R2r5': 'R2r 5\\,\\%', 'R3': 'R3'}
GROUPS = ('go-tcp', 'openssl-tcp', 'go-quic')
SINGLE = {'KX': 'hybrid-ecdsa-echoff', 'CERT': 'classical-mldsa-echoff', 'ECH': 'classical-ecdsa-echon'}
NS = (5, 10, 20, 50, 100, 200)


def mac(n, v):
    return f'\\newcommand{{\\{n}}}{{{v}}}\n'


def f2(x):
    return '--' if x is None else f'{x:.2f}'


def fl(x):
    return f'{np.floor(100 * x + 1e-9) / 100:.2f}'


def ci(c):
    return '--' if c is None else f'[{c[0]:.2f}, {c[1]:.2f}]'


def rng(lo, hi):
    return f2(lo) if f2(lo) == f2(hi) else f'{f2(lo)}--{f2(hi)}'


def load():
    p = R / 'b_robust.json'
    return json.load(open(p)) if p.exists() else None


def kind(cell):
    tail = cell.split('-', 2)[2]
    for k, v in SINGLE.items():
        if tail == v:
            return k
    return 'base' if tail == 'classical-ecdsa-echoff' else 'combo'


def shift_summary(S):
    """power per (single migration, transport, n) = mean over the groups of that transport; null = baseline cells."""
    out = {}
    for test in ('ks', 'ks_size', 'psi'):
        for tr, groups in (('tcp', ('go-tcp', 'openssl-tcp')), ('quic', ('go-quic',))):
            for k in ('base', 'KX', 'CERT', 'ECH', 'combo'):
                for n in NS:
                    xs = [v[test] for key, v in S.items() for g in groups
                          if key.startswith(g + '|') and key.endswith(f'|{n}') and kind(key.split('|')[1]) == k]
                    out[f'{test}|{tr}|{k}|{n}'] = (float(np.mean(xs)), float(min(xs)), float(max(xs))) if xs else None
    return out


def stability():
    """How often each main effect appears over the 15 runs (3 folds x 5 model seeds; seed 0 = published), per model
    and group, on the single-migration cells, no repair, 1 % threshold. A run counts only if the model trained (recall
    >= 0.5 on the group's baseline cell). miss: recall < 0.7 (>= 30 points below the baseline's 1.00); flood: FPR > 0.25."""
    runs = []
    for k in (0, 1, 2):
        for s in range(5):
            f = ('b_eval.json' if k == 0 else f'b_eval_f{k}.json') if s == 0 else f'b_eval_f{k}_s{s}.json'
            if (R / f).exists():
                runs.append(json.load(open(R / f))['sup_nfs'])
    res = {}
    for m in MK:
        for g in GROUPS:
            d = [ev[f'{m}|{g}'] for ev in runs]
            ok = [x for x in d if x[f'{g}-classical-ecdsa-echoff']['recall'] >= 0.5]
            r = dict(runs=len(d), trained=len(ok))
            for mig, tail in (('KX', 'hybrid-ecdsa-echoff'), ('CERT', 'classical-mldsa-echoff')):
                r[f'{mig}_miss'] = sum(1 for x in ok if x[f'{g}-{tail}']['recall'] < 0.7)
                r[f'{mig}_flood'] = sum(1 for x in ok if x[f'{g}-{tail}']['fpr'] > 0.25)
            res[f'{m}|{g}'] = r
    return res


def macros():
    B = load()
    if B is None:
        return []
    out = []
    GK = {'go-tcp': 'Go', 'openssl-tcp': 'Ossl', 'go-quic': 'Quic'}
    for key, r in stability().items():
        m, g = key.split('|')
        base = f'St{MK[m]}{GK[g]}'
        out += [mac(base + 'Runs', r['runs']), mac(base + 'Trained', r['trained'])]
        for e, ek in (('KX_miss', 'KxMiss'), ('KX_flood', 'KxFlood'), ('CERT_miss', 'CertMiss'), ('CERT_flood', 'CertFlood')):
            out.append(mac(base + ek, r[e]))
    br = B['base_rates']
    for p, pk in PK.items():
        for m, mk in MK.items():
            v = br[f'{p}|{m}|migrated']
            out += [mac(f'Rb{pk}{mk}PrecOne', f2(v['prec_1'])), mac(f'Rb{pk}{mk}PrecOneCi', ci(v['prec_1_ci'])),
                    mac(f'Rb{pk}{mk}PrecFive', f2(v['prec_5'])), mac(f'Rb{pk}{mk}PrecFiveCi', ci(v['prec_5_ci'])),
                    mac(f'Rb{pk}{mk}Fpk', f"{v['false_per_10k']:.0f}"), mac(f'Rb{pk}{mk}Fpr', f2(v['fpr']))]
    for m, mk in MK.items():
        v = br[f'none|{m}|baseline']
        out.append(mac(f'RbBase{mk}PrecOne', f2(v['prec_1'])))
        out.append(mac(f'RbBase{mk}PrecOneLow', f2(v.get('prec_1_lower_rule3', v['prec_1_ci'][0]))))
        out.append(mac(f'RbBase{mk}Fpk', f"{v['false_per_10k']:.0f}"))
    nb = br['none|lgbm|baseline']['n_benign']
    out.append(mac('RbBaseNbenign', f'{nb:,}'))
    out.append(mac('RbMigNbenign', f"{br['none|lgbm|migrated']['n_benign']:,}"))
    # ranges of precision over models for R1
    pr = [br[f'R1|{m}|migrated']['prec_1'] for m in MK]
    out.append(mac('RbRonePrecOneRange', rng(min(pr), max(pr))))
    pr5 = [br[f'R1|{m}|migrated']['prec_5'] for m in MK]
    out.append(mac('RbRonePrecFiveRange', rng(min(pr5), max(pr5))))
    # 5 % FPR operating point, fold ranges
    b5 = B['base_rates_5']
    for p, pk in PK.items():
        for m, mk in MK.items():
            vs = [b5[f'{k}|{p}|{m}'] for k in (0, 1, 2)]
            out += [mac(f'Rbf{pk}{mk}Rec', rng(min(v['recall5'] for v in vs), max(v['recall5'] for v in vs))),
                    mac(f'Rbf{pk}{mk}Fpr', rng(min(v['fpr5'] for v in vs), max(v['fpr5'] for v in vs))),
                    mac(f'Rbf{pk}{mk}MinCell', fl(min(v['min_cell_recall5'] for v in vs)))]
    # seeds
    sd = B['seeds']
    nruns = sum(sd[f'{k}|none|lgbm']['n_seeds'] for k in (0, 1, 2))
    out.append(mac('RbSeedNruns', nruns))
    out.append(mac('RbSeedNseeds', min(sd[f'{k}|none|lgbm']['n_seeds'] for k in (0, 1, 2))))
    for p, pk in PK.items():
        for m, mk in MK.items():
            vs = [sd[f'{k}|{p}|{m}'] for k in (0, 1, 2)]
            lo = min(v['recall_range'][0] for v in vs); hi = max(v['recall_range'][1] for v in vs)
            flo = min(v['fpr_range'][0] for v in vs); fhi = max(v['fpr_range'][1] for v in vs)
            out += [mac(f'Rbs{pk}{mk}Rec', rng(lo, hi)), mac(f'Rbs{pk}{mk}Fpr', rng(flo, fhi)),
                    mac(f'Rbs{pk}{mk}MinCell', fl(min(v['min_cell_recall_range'][0] for v in vs)))]
            coll = sum(1 for v in vs for s in v['per_seed'].values() if s['base_min_recall'] < 0.5)
            out.append(mac(f'RbsCollapse{pk}{mk}', coll))
            ok = [s for v in vs for s in v['per_seed'].values() if s['base_min_recall'] >= 0.5]  # runs that trained
            out += [mac(f'Rbs{pk}{mk}RecOk', rng(min(s['recall'] for s in ok), max(s['recall'] for s in ok))),
                    mac(f'Rbs{pk}{mk}MinCellOk', fl(min(s['min_cell_recall'] for s in ok)))]
    # R1 per-cell interval: lowest lower bound over migrated cells (main fold)
    pc = B['per_cell_ci']
    for m, mk in MK.items():
        lows = [v['recall_ci'][0] for k, v in pc.items() if k.startswith(f'R1|{m}|') and kind(k.split('|')[2]) != 'base']
        out.append(mac(f'RbCiRoneLow{mk}', fl(min(lows))))
    nbr = [v['n_benign_runs'] for v in pc.values()]
    out.append(mac('RbCiBenignRuns', rng(min(nbr), max(nbr)).replace('.00', '')))
    # shift alarm
    sh = shift_summary(B['shift_alarm'])
    for test, tk in (('ks', 'Ks'), ('ks_size', 'Kss'), ('psi', 'Psi')):
        for tr, trk in (('tcp', 'Tcp'), ('quic', 'Quic')):
            for k in ('base', 'KX', 'CERT', 'ECH', 'combo'):
                for n in NS:
                    v = sh[f'{test}|{tr}|{k}|{n}']
                    if v:
                        out.append(mac(f'Sh{tk}{trk}{k.capitalize()}N{["a","b","c","d","e","f"][NS.index(n)]}', fl(v[1]) if k != 'base' else f2(v[2])))  # migrated: floored minimum
    return out


def si_section(t, longtab):
    """Supplementary Section S10 (tables S9-S13)."""
    B = load()
    if B is None:
        return ''
    o = ['\\section*{S10 Robustness: base rates, operating point, seeds, per-cell intervals and shift alarms}']
    br = B['base_rates']
    rows = []
    for p in PK:
        for m in MK:
            for part in ('migrated', 'baseline'):
                v = br[f'{p}|{m}|{part}']
                low = f" ($\\geq${v['prec_1_lower_rule3']:.2f})" if 'prec_1_lower_rule3' in v else ''
                rows.append(f"{PN[p]} & {MN[m]} & {part} & {v['recall']:.3f} & {v['fpr']:.3f} {ci(v['fpr_ci'])} & "
                            f"{v['false_per_10k']:.0f} & {f2(v['prec_1'])}{low} {ci(v['prec_1_ci'])} & {f2(v['prec_5'])} {ci(v['prec_5_ci'])}\\\\")
    o.append(longtab('llllllll', 'Pipeline & Model & Cells & Recall & FPR [95\\,\\% CI] & False / 10k & Precision at 1\\,\\% & Precision at 5\\,\\%', rows,
                     'Realistic base rates (main fold, thresholds at 1\\,\\% FPR). Recall and FPR are pooled over the 21 migrated cells '
                     'or the 3 baseline cells; precision at prevalence $\\pi$ is $\\pi R/(\\pi R+(1-\\pi)F)$. Intervals: run-level bootstrap '
                     '(2,000 resamples of the profile runs within each cell). Where no benign flow alerted, the value in parentheses is the '
                     'precision at the rule-of-three upper bound on FPR ($3/n_\\mathrm{benign}$).'))
    b5 = B['base_rates_5']
    rows = []
    for p in PK:
        for m in MK:
            vs = [b5[f'{k}|{p}|{m}'] for k in (0, 1, 2)]
            rows.append(f"{PN[p]} & {MN[m]} & " + ' & '.join(
                f"{v['recall1']:.2f} / {v['fpr1']:.2f} / {fl(v['min_cell_recall1'])} & {v['recall5']:.2f} / {v['fpr5']:.2f} / {fl(v['min_cell_recall5'])}"
                for v in vs) + '\\\\')
    o.append(longtab('llrrrrrr', 'Pipeline & Model & F0 1\\,\\% & F0 5\\,\\% & F1 1\\,\\% & F1 5\\,\\% & F2 1\\,\\% & F2 5\\,\\%', rows,
                     'Both operating points in every fold: recall / FPR pooled over the flows of the 21 migrated cells / lowest per-cell recall, '
                     'thresholds at 1\\,\\% and 5\\,\\% FPR on the baseline (R0 and R2r: on the cell\'s own) benign calibration flows.'))
    sd = B['seeds']
    rows = []
    for p in PK:
        for m in MK:
            cells = []
            for k in (0, 1, 2):
                v = sd[f'{k}|{p}|{m}']
                cells.append(f"{rng(*v['recall_range'])} / {rng(*v['fpr_range'])} / {fl(v['min_cell_recall_range'][0])}")
            rows.append(f"{PN[p]} & {MN[m]} & " + ' & '.join(cells) + '\\\\')
    ns = min(sd[f'{k}|none|lgbm']['n_seeds'] for k in (0, 1, 2))
    o.append(longtab('llrrr', 'Pipeline & Model & Fold 0 & Fold 1 & Fold 2', rows,
                     f'Model-seed variability: range over {ns} seeds per fold of the unweighted mean over the 21 migrated cells of the per-cell recall / FPR, '
                     'and the lowest per-cell recall over all seeds (thresholds at 1\\,\\% FPR). Seed 0 is the published run.'))
    rows = []
    for k in sorted(sd):
        f, p, m = k.split('|')
        for s, v in sorted(sd[k]['per_seed'].items(), key=lambda x: int(x[0])):
            if v['base_min_recall'] < 0.5:
                rows.append(f"{f} & {s} & {PN[p]} & {MN[m]} & {v['base_min_recall']:.2f} & {v['recall']:.2f}\\\\")
    if rows:
        o.append(longtab('rrllrr', 'Fold & Seed & Pipeline & Model & Lowest baseline-cell recall & Mean per-cell recall, migrated cells', rows,
                         'Runs in which a model failed already on a baseline cell (recall below 0.5 before any migration), i.e. a '
                         'training failure rather than a migration effect.'))
    pc = B['per_cell_ci']
    for m in MK:
        rows = []
        cells = sorted({k.split('|')[2] for k in pc if k.startswith(f'none|{m}|')})
        for c in cells:
            a, b = pc[f'none|{m}|{c}'], pc[f'R1|{m}|{c}']
            rows.append(f"{t(c)} & {a['recall']:.2f} {ci(a['recall_ci'])} & {a['fpr']:.2f} {ci(a['fpr_ci'])} & "
                        f"{b['recall']:.2f} {ci(b['recall_ci'])} & {b['fpr']:.2f} {ci(b['fpr_ci'])}\\\\")
        o.append(longtab('lllll', 'Cell & No repair: recall & No repair: FPR & R1: recall & R1: FPR', rows,
                         f'{MN[m]}, main fold, thresholds at 1\\,\\% FPR: per-cell recall and FPR with 95\\,\\% run-level bootstrap '
                         'intervals (2,000 resamples of the profile runs of the cell).'))
    sh = shift_summary(B['shift_alarm'])
    rows = []
    for test, tn in (('ks', 'KS, all 77 features'), ('ks_size', 'KS, size and count features'), ('psi', 'PSI $>$ 0.25, any feature')):
        for tr in ('tcp', 'quic'):
            for k, kn in (('base', 'none (false alarms)'), ('KX', 'hybrid KX'), ('CERT', 'ML-DSA cert.'), ('ECH', 'ECH'), ('combo', 'combinations')):
                vals = [sh[f'{test}|{tr}|{k}|{n}'] for n in NS]
                rows.append(f"{tn} & {tr.upper()} & {kn} & " + ' & '.join(
                    '--' if v is None else (f'{v[2]:.2f}' if k == 'base' else fl(v[1])) for v in vals) + '\\\\')
    o.append(longtab('lll' + 'r' * len(NS), 'Test & Transport & Migration & ' + ' & '.join(f'$n={n}$' for n in NS), rows,
                     'Shift alarms on unlabelled traffic: share of 300 random windows of $n$ test flows that raise an alarm against the '
                     'baseline\'s training flows (two-sample KS test per feature, Bonferroni $\\alpha=0.01$; or PSI $>0.25$). Migrated '
                     'rows: lowest share over the cells of that type; baseline rows: highest share (false alarms).'))
    rows = []
    for key, r in stability().items():
        m, g = key.split('|')
        rows.append(f"{MN[m]} & {t(g)} & {r['trained']} / {r['runs']} & {r['KX_miss']} & {r['KX_flood']} & {r['CERT_miss']} & {r['CERT_flood']}\\\\")
    o.append(longtab('llrrrrr', 'Model & Group & Trained runs & KX: miss & KX: flood & Cert.: miss & Cert.: flood', rows,
                     'Stability of the main effects over 15 runs (3 folds $\\times$ 5 model seeds; seed 0 is the published run), no repair, '
                     'thresholds at 1\\,\\% FPR, single-migration cells. Counts are runs in which the effect occurred, among the runs in '
                     "which the model trained (recall $\\geq 0.5$ on the group's baseline cell). Miss: recall below 0.7; flood: FPR above 0.25."))
    return NL.join(o)
