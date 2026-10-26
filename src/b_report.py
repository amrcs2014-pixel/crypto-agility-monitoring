"""Paper B: numbers, tables and figures from results/b_eval*.json, b_stats.json and data/b_realworld.csv.
Writes outputs/numbers_B.tex, outputs/tab_*.tex, outputs/b_fig_*.pdf.
"""
import json, re
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
matplotlib.rcParams['pdf.fonttype'] = 42  # embed TrueType, not Type 3, fonts in PDF figures
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

W = Path(__file__).resolve().parents[1]
R, P, D = W / 'results', W / 'outputs', W / 'data'  # generated tables, macros and figures
P.mkdir(exist_ok=True)
GROUPS = ['go-tcp', 'openssl-tcp', 'go-quic']
GNAME = {'go-tcp': 'Go / TCP', 'openssl-tcp': 'OpenSSL / TCP', 'go-quic': 'Go / QUIC'}
COMBOS = [('classical', 'ecdsa', 'off'), ('hybrid', 'ecdsa', 'off'), ('classical', 'mldsa', 'off'),
          ('classical', 'ecdsa', 'on'), ('hybrid', 'mldsa', 'off'), ('hybrid', 'ecdsa', 'on'),
          ('classical', 'mldsa', 'on'), ('hybrid', 'mldsa', 'on')]
DET = [('sup_nfs', 'lgbm', 'LightGBM'), ('sup_nfs', 'rf', 'Random forest'), ('sup_nfs', 'mlp', 'MLP'),
       ('iforest_nfs', 'iforest', 'Isolation Forest'), ('bytecnn', 'bytecnn', 'Byte CNN')]
MODELS = [('lgbm', 'LightGBM'), ('rf', 'Random forest'), ('mlp', 'MLP')]
REPAIRS = [('sup_nfs', 'none', 'No repair (baseline-trained model)'), ('recal_nfs', 'Rzero', 'R0 recalibrated threshold'),
           ('sup_post', 'Rone', 'R1 handshake-normalised features'), ('sup_post_nohs', 'Ronem', 'R1$^-$ without handshake flag'),
           ('sup_nosplt', 'Ronebe', 'R1b no first-packet features'), ('sup_full', 'Ctrl', 'Control: own whole-flow statistics'),
           ('fewshot_1', 'Rtwoa', 'R2 few-shot 1\\,\\%'), ('fewshot_5', 'Rtwob', 'R2 few-shot 5\\,\\%'),
           ('fewshot_10', 'Rtwoc', 'R2 few-shot 10\\,\\%'), ('fewshotbal_1', 'Rtwobala', 'R2b balanced 1\\,\\%'),
           ('fewshotbal_5', 'Rtwobalb', 'R2b balanced 5\\,\\%'), ('fewshotbal_10', 'Rtwobalc', 'R2b balanced 10\\,\\%'),
           ('fewshotrecal_1', 'Rtwora', 'R2r few-shot 1\\,\\% + R0'), ('fewshotrecal_5', 'Rtworb', 'R2r few-shot 5\\,\\% + R0'),
           ('fewshotrecal_10', 'Rtworc', 'R2r few-shot 10\\,\\% + R0'), ('retrain_all', 'Rthree', 'R3 retrain on all migrated')]
plt.rcParams.update({'font.size': 8, 'font.family': 'DejaVu Sans', 'axes.spines.top': False, 'axes.spines.right': False})


def cname(c):
    kx, cert, ech = c
    parts = [p for p, on in (('KX', kx == 'hybrid'), ('CERT', cert == 'mldsa'), ('ECH', ech == 'on')) if on]
    return '+'.join(parts) if parts else 'baseline'


CN = [cname(c) for c in COMBOS]


def mac(n, v):
    return f'\\newcommand{{\\{n}}}{{{v}}}\n'


def f2(x, d=2):
    return '--' if x is None or (isinstance(x, float) and np.isnan(x)) else f'{x:.{d}f}'


def pp(x):
    return '--' if x is None else f'{100 * x:+.0f}'.replace('-', '$-$')


def cell_of(g, c):
    st, tr = g.split('-')
    return f'{st}-{tr}-{c[0]}-{c[1]}-ech{c[2]}'


def grid(ev, key, model, metric):
    M = np.full((len(GROUPS), len(COMBOS)), np.nan)
    for i, g in enumerate(GROUPS):
        cells = ev.get(key, {}).get(f'{model}|{g}', {})
        for j, c in enumerate(COMBOS):
            v = cells.get(cell_of(g, c), {}).get(metric) if isinstance(cells.get(cell_of(g, c)), dict) else None
            if v is not None:
                M[i, j] = v
    return M


def migrated_mean(ev, key, model, metric):
    vals = [ev.get(key, {}).get(f'{model}|{g}', {}).get(cell_of(g, c), {}).get(metric)
            for g in GROUPS for c in COMBOS[1:]]
    vals = [v for v in vals if v is not None]
    return float(np.mean(vals)) if vals else None


def baseline_mean(ev, key, model, metric):
    vals = [ev.get(key, {}).get(f'{model}|{g}', {}).get(cell_of(g, COMBOS[0]), {}).get(metric) for g in GROUPS]
    vals = [v for v in vals if v is not None]
    return float(np.mean(vals)) if vals else None


def main():
    ev = json.load(open(R / 'b_eval.json'))
    folds = [ev] + [json.load(open(p)) for p in sorted(R.glob('b_eval_f[0-9].json'))]
    st = json.load(open(R / 'b_stats.json'))
    hs = ev['hs']
    out = [mac('NCells', len(ev['cells'])), mac('NFlows', f"{ev['n_flows']:,}"),
           mac('NFeatNFS', ev['features']['nfs']), mac('NFeatPost', ev['features']['full']), mac('NFolds', len(folds))]
    rows = []
    for g in GROUPS:
        for c in COMBOS:
            h = hs.get(cell_of(g, c))
            if h:
                rows.append(dict(group=g, combo=cname(c), **{k: h.get(k) for k in ('ch_len', 'ks_bytes', 'hs_c2s_bytes',
                                                                                    'hs_s2c_bytes', 'hs_pkts', 'hs_dur')}))
    H = pd.DataFrame(rows)
    H.to_csv(R / 'b_handshake.csv', index=False)

    def hv(g, combo, k):
        x = H[(H.group == g) & (H.combo == combo)][k]
        return float(x.iloc[0]) if len(x) and pd.notna(x.iloc[0]) else None
    for g, gk in (('go-tcp', 'Go'), ('openssl-tcp', 'Ossl'), ('go-quic', 'Quic')):
        for combo, ck in (('baseline', 'Base'), ('KX', 'Kx'), ('CERT', 'Cert'), ('ECH', 'Ech'), ('KX+CERT+ECH', 'All')):
            for k, kk in (('ch_len', 'Ch'), ('hs_s2c_bytes', 'Srv'), ('hs_c2s_bytes', 'Cli'), ('hs_pkts', 'Pkts')):
                v = hv(g, combo, k)
                out.append(mac(f'Hs{gk}{ck}{kk}', '--' if v is None else f'{v:,.0f}'))
            v = hv(g, combo, 'hs_dur')
            out.append(mac(f'Hs{gk}{ck}Ms', '--' if v is None else f'{1000 * v:.0f}'))
    # repair macros (fold 0) + fold ranges
    rep = {}
    for key, lab, _ in REPAIRS:
        for model, _n in MODELS:
            mm = model.capitalize()
            vals = {met: migrated_mean(ev, key, model, met) for met in ('recall', 'fpr', 'auroc', 'recall_tls', 'recall_macro',
                                                                        'recall5', 'fpr5')}
            vals['base_recall'] = baseline_mean(ev, key, model, 'recall')
            vals['base_fpr'] = baseline_mean(ev, key, model, 'fpr')
            fr = [migrated_mean(f, key, model, 'recall') for f in folds]
            ff = [migrated_mean(f, key, model, 'fpr') for f in folds]
            fr = [x for x in fr if x is not None]; ff = [x for x in ff if x is not None]
            vals['rec_lo'], vals['rec_hi'] = (min(fr), max(fr)) if fr else (None, None)
            vals['fpr_lo'], vals['fpr_hi'] = (min(ff), max(ff)) if ff else (None, None)
            rep[(lab, model)] = vals
            for met, mk in (('recall', 'Rec'), ('fpr', 'Fpr'), ('auroc', 'Auc'), ('recall_tls', 'Tls'), ('recall_macro', 'Macro'),
                            ('base_recall', 'BaseRec'), ('base_fpr', 'BaseFpr'), ('rec_lo', 'RecLo'), ('rec_hi', 'RecHi'),
                            ('fpr_lo', 'FprLo'), ('fpr_hi', 'FprHi'), ('recall5', 'Recfive'), ('fpr5', 'Fprfive')):
                out.append(mac(f'Rep{lab}{mm}{mk}', f2(vals[met])))
    # detection per combo per group (recall/fpr/auroc) for supervised + others
    for key, model, name in DET:
        nk = re.sub(r'[^A-Za-z]', '', name)
        for met, mk in (('recall', 'Rec'), ('fpr', 'Fpr'), ('auroc', 'Auc')):
            M = grid(ev, key, model, met)
            for i, g in enumerate(GROUPS):
                gk = {'go-tcp': 'Go', 'openssl-tcp': 'Ossl', 'go-quic': 'Quic'}[g]
                for j, cn in enumerate(CN):
                    out.append(mac(f'D{nk}{gk}{re.sub(r"[^A-Za-z]", "", cn).capitalize()}{mk}', f2(M[i, j])))
    # factor-model macros
    for tag, tk in (('nfs|lgbm', 'Lgbm'), ('nfs|rf', 'Rf'), ('nfs|mlp', 'Mlp'), ('bytecnn', 'Cnn'), ('post|lgbm', 'PostLgbm'),
                    ('post|rf', 'PostRf'), ('post|mlp', 'PostMlp'), ('nosplt|lgbm', 'NospltLgbm'), ('iforest|nfs', 'Iforest'),
                    ('recal|lgbm', 'RecalLgbm'), ('recal|mlp', 'RecalMlp'), ('recal|rf', 'RecalRf'), ('full|lgbm', 'FullLgbm')):
        for met, mk in (('recall', 'Rec'), ('fpr', 'Fpr')):
            for form, fk in (('main', 'Main'), ('inter', 'Int')) + tuple((f'main_{g}', {'go-tcp': 'Go', 'openssl-tcp': 'Ossl',
                                                                                          'go-quic': 'Quic'}[g]) for g in GROUPS):
                v = st['factors'].get(f'{tag}|{met}|{form}', {})
                for term, trm in (('kx', 'Kx'), ('cert', 'Cert'), ('ech', 'Ech'), ('kx:cert', 'KxCert')):
                    x = v.get(term)
                    if isinstance(x, dict):
                        out.append(mac(f'F{tk}{mk}{fk}{trm}', f"{100 * x['coef']:.0f}".replace('-', '$-$')))
                        out.append(mac(f'F{tk}{mk}{fk}{trm}Ci', f"[{100 * x['lo']:.0f}, {100 * x['hi']:.0f}]".replace('-', '$-$')))
    fp = ev['fingerprints']
    for g, gk in (('go-tcp', 'Go'), ('openssl-tcp', 'Ossl'), ('go-quic', 'Quic')):
        for c in COMBOS:
            for f, fk in (('ja3', 'Jathree'), ('client_fingerprint', 'Jafour')):
                v = fp.get(f'{f}|{cell_of(g, c)}', {}).get('coverage')
                out.append(mac(f'Fp{gk}{fk}{re.sub(r"[^A-Za-z]", "", cname(c)).capitalize()}', f2(v)))
    out += mixed_section()
    from b_robust_report import macros as robust_macros
    out += robust_macros()
    from b_padding_report import macros as padding_macros
    out += padding_macros()
    (P / 'numbers_B.tex').write_text(''.join(out), encoding='utf-8')
    tables(ev, H, rep, st)
    figs(ev, H, rep)
    print('report B done;', len(out), 'macros;', len(folds), 'folds')


def mixed_section():
    """Uneven migration of the client-side factors (KX, ECH; ECDSA server): macros + tab_mixed.tex from
    results/b_mixed_summary.json. All values are means over the cell set 'kx' (cells with hybrid key exchange) unless
    a macro says otherwise; fold ranges and per-cell minima use the same set."""
    p = R / 'b_mixed_summary.json'
    if not p.exists():
        return []
    S = json.load(open(p))
    K = S['sets']['kx']; A, FR = K['main'], K['fold_range']
    E = S['sets']['ech']
    PK = {'none': 'None', 'R0': 'Rzero', 'R1': 'Rone', 'stag_nfs': 'StagNfs', 'stag_post': 'StagPost'}
    WK = {'full': 'Full', 'benign_first': 'Bf', 'attacker_first': 'Af'}
    MK = {'lgbm': 'Lgbm', 'rf': 'Rf', 'mlp': 'Mlp'}
    out = [mac('MxNcells', K['n_cells']), mac('MxNcellsEch', E['n_cells']), mac('MxNfolds', len(S['folds']))]

    def rr(lo, hi):
        return f2(lo) if f2(lo) == f2(hi) else f'{f2(lo)}--{f2(hi)}'

    def fl(x):  # floor to two decimals, so 'no cell below x' is true at the printed precision
        return f'{np.floor(100 * x + 1e-9) / 100:.2f}'
    for k, v in A.items():
        m, pipe, world = k.split('|')
        base = f'Mx{PK[pipe]}{WK[world]}{MK[m]}'
        out += [mac(base + 'Rec', f2(v['recall'])), mac(base + 'Fpr', f2(v['fpr'])),
                mac(base + 'RecRange', rr(*FR[k]['recall'])), mac(base + 'MinCell', fl(FR[k]['min_cell_recall']))]
    # ranges over the three models (main fold)
    def over_models(pipe, worlds, met):
        xs = [A[f'{m}|{pipe}|{w}'][met] for m in MK for w in worlds]
        return min(xs), max(xs)
    for name, pipe, worlds, met in (('NoneAfFpr', 'none', ('attacker_first',), 'fpr'),
                                    ('StagNfsBfRec', 'stag_nfs', ('benign_first',), 'recall'),
                                    ('StagNfsBfFpr', 'stag_nfs', ('benign_first',), 'fpr'),
                                    ('StagPostFullRec', 'stag_post', ('full',), 'recall'),
                                    ('StagPostFullFpr', 'stag_post', ('full',), 'fpr'),
                                    ('RoneRec', 'R1', ('benign_first', 'attacker_first'), 'recall'),
                                    ('RoneFpr', 'R1', ('benign_first', 'attacker_first'), 'fpr')):
        out.append(mac(f'Mx{name}Rng', rr(*over_models(pipe, worlds, met))))
    # R1 without retraining: minimum per-cell recall over folds, models, both cell sets and all three worlds
    r1min = min(S['sets'][s]['fold_range'][f'{m}|R1|{w}']['min_cell_recall'] for s in ('kx', 'ech') for m in MK
                for w in WK)
    out.append(mac('MxRoneMinCellAll', fl(r1min)))
    # staggered R1 features, ECH-only cells: worst cell over folds (MLP)
    out.append(mac('MxStagPostEchMinCell', fl(min(E['fold_range'][f'{m}|stag_post|full']['min_cell_recall'] for m in MK))))
    out.append(mac('MxStagPostMinCellAll', fl(min(S['sets'][s]['fold_range'][f'{m}|stag_post|{w}']['min_cell_recall']
                                                 for s in ('kx', 'ech') for m in MK for w in ('benign_first', 'full')))))
    out.append(mac('MxNoneEchAfMinRec', f2(min(E['main'][f'{m}|none|attacker_first']['recall'] for m in MK))))
    out.append(mac('MxStagNfsEchFullMinRec', f2(min(E['main'][f'{m}|stag_nfs|full']['recall'] for m in MK))))
    for sk, sn in (('kxonly', 'Kx'), ('kxech', 'Kxech')):
        for fp, fk in (('ja3', 'Jathree'), ('client_fingerprint', 'Jafour')):
            for world in WK:
                v = S['fingerprints'].get(f'{sk}|{fp}|{world}', {})
                out.append(mac(f'MxFp{fk}{sn}{WK[world]}Block', f2(v.get('blocklist_hit'))))
            out.append(mac(f'MxFp{fk}{sn}Ncells', S['fingerprints'].get(f'{sk}|{fp}|full', {}).get('n_cells', 0)))
    rows, spec = [], [
        ('Everyone migrated (same cells, for reference)', [('none', 'full', 'No repair'), ('R1', 'full', 'R1 handshake-normalised')]),
        ('Benign clients migrated, attackers keep the old stack', [('none', 'benign_first', 'No repair'),
                                                                   ('R0', 'benign_first', 'R0 recalibrated threshold'),
                                                                   ('R1', 'benign_first', 'R1 handshake-normalised')]),
        ('Attackers migrated, benign clients keep the old stack', [('none', 'attacker_first', 'No repair'),
                                                                   ('R1', 'attacker_first', 'R1 handshake-normalised')]),
        ('Staggered: retrained while only benign clients had migrated', [
            ('stag_nfs', 'benign_first', 'NFStream features, before attackers migrate'),
            ('stag_nfs', 'full', 'NFStream features, after attackers migrate'),
            ('stag_post', 'benign_first', 'R1 features, before attackers migrate'),
            ('stag_post', 'full', 'R1 features, after attackers migrate')])]
    for title, items in spec:
        rows.append(f'\\multicolumn{{7}}{{l}}{{\\emph{{{title}}}}}\\\\')
        for pipe, world, lab in items:
            cs = []
            for m in MK:
                v = A[f'{m}|{pipe}|{world}']
                cs += [f2(v['recall']), f2(v['fpr'])]
            rows.append(f'\\quad {lab} & ' + ' & '.join(cs) + '\\\\')
        rows.append('\\midrule')
    (P / 'tab_mixed.tex').write_text(
        '\\begin{table}[t]\\centering\\caption{Uneven migration of the client-side configuration: mean recall and FPR over the '
        + str(K['n_cells']) + ' cells with hybrid key exchange (KX and KX+ECH, ECDSA server; main fold, test repetitions, '
        'thresholds at 1\\,\\% FPR). Mixed deployments combine the benign flows of one cell with the malicious flows of another, '
        'captured with the same seeded runs; for the no-repair and R1 rows they recombine per-cell results by construction. '
        'Staggered: retrained on the baseline plus the migrated benign flows of the training repetitions, threshold re-set on '
        'the calibration repetitions, then tested before and after the attackers migrate as well. Per cell and fold: '
        'Supplementary Table S8; full-migration rows per cell: Supplementary Table S2.}\\label{tab:b_mixed}\n'
        '\\footnotesize\\setlength{\\tabcolsep}{3pt}\\begin{tabular}{lrrrrrr}\\toprule & \\multicolumn{2}{c}{LightGBM} & '
        '\\multicolumn{2}{c}{Random forest} & \\multicolumn{2}{c}{MLP}\\\\\\cmidrule(lr){2-3}\\cmidrule(lr){4-5}\\cmidrule(lr){6-7}'
        ' Scenario and pipeline & Rec. & FPR & Rec. & FPR & Rec. & FPR\\\\\\midrule\n' + '\n'.join(rows[:-1]) +
        '\n\\bottomrule\\end{tabular}\\end{table}\n', encoding='utf-8')
    return out


def tables(ev, H, rep, st):
    rows = []
    for g in GROUPS:
        for i, c in enumerate(COMBOS):
            r = H[(H.group == g) & (H.combo == cname(c))]
            if not len(r):
                continue
            r = r.iloc[0]
            rows.append(f"{GNAME[g] if i == 0 else ''} & {cname(c)} & {f2(r.ch_len, 0)} & {f2(r.ks_bytes, 0)} & "
                        f"{f2(r.hs_c2s_bytes, 0)} & {f2(r.hs_s2c_bytes, 0)} & {f2(r.hs_pkts, 0)} & {f2(1000 * r.hs_dur, 0)}\\\\")
        rows.append('\\midrule')
    (P / 'tab_handshake.tex').write_text(
        '\\begin{table}[t]\\centering\\caption{Handshake size per cell (medians over flows with a completed handshake). CH: '
        'ClientHello message bytes; key share: bytes of all key shares offered; client/server bytes and packets: IP bytes and '
        "packets of the handshake phase (TCP: until the client's first encrypted record; QUIC: long-header packets); time in "
        'ms. Our parser does not decrypt QUIC Initial packets, so CH fields are given for TCP only.}\\label{tab:b_handshake}\n'
        '\\small\\begin{tabular}{llrrrrrr}\\toprule Stack & Migration & CH & Key share & Client B & Server B & Pkts & ms\\\\\\midrule\n'
        + '\n'.join(rows[:-1]) + '\n\\bottomrule\\end{tabular}\\end{table}\n', encoding='utf-8')
    # effects table: single-migration cell minus baseline, per group (flow level, percentage points)
    lines = []
    single = {'kx': ('hybrid', 'ecdsa', 'off'), 'cert': ('classical', 'mldsa', 'off'), 'ech': ('classical', 'ecdsa', 'on')}
    for (key, model, tag, name) in (('sup_nfs', 'lgbm', 'nfs|lgbm', 'LightGBM'), ('sup_nfs', 'rf', 'nfs|rf', 'Random forest'),
                                    ('sup_nfs', 'mlp', 'nfs|mlp', 'MLP'), ('bytecnn', 'bytecnn', 'bytecnn', 'Byte CNN'),
                                    ('sup_post', 'lgbm', 'post|lgbm', 'LightGBM, R1'), ('sup_post', 'mlp', 'post|mlp', 'MLP, R1')):
        for i, g in enumerate(GROUPS):
            cells_ = ev[key][f'{model}|{g}']
            b = cells_[cell_of(g, COMBOS[0])]
            out_c = []
            for met in ('recall', 'fpr'):
                for fac in ('kx', 'cert', 'ech'):
                    c = cell_of(g, single[fac])
                    d = cells_[c][met] - b[met]
                    pr = st['paired'].get(f'{tag}|{c}|{met}')
                    sig = '$^{*}$' if pr and not (pr['lo'] <= 0 <= pr['hi']) else ''
                    out_c.append(f'{pp(d)}{sig}')
            auc = [cells_[cell_of(g, single[f])]['auroc'] for f in ('kx', 'cert', 'ech')]
            lines.append(f"{name if i == 0 else ''} & {GNAME[g]} & " + ' & '.join(out_c) + ' & ' +
                         ' / '.join(f2(a) for a in auc) + '\\\\')
        lines.append('\\midrule')
    (P / 'tab_effects.tex').write_text(
        '\\begin{table}[t]\\centering\\caption{Effect of each single migration per stack and transport: change in recall and '
        'false-positive rate from the baseline cell to the cell that changes only that factor, in percentage points (test '
        'repetitions; thresholds at 1\\,\\% FPR on the baseline); $^{*}$: 95\\,\\% paired run-level bootstrap interval excludes '
        'zero. Last column: AUROC after KX / CERT / ECH (all baselines 0.99--1.00 for the supervised detectors). R1: '
        'handshake-normalised features.}\\label{tab:b_effects}\n\\footnotesize\\setlength{\\tabcolsep}{3.5pt}'
        '\\begin{tabular}{llrrrrrrc}\\toprule '
        '& & \\multicolumn{3}{c}{Recall} & \\multicolumn{3}{c}{False-positive rate}\\\\\\cmidrule(lr){3-5}\\cmidrule(lr){6-8}'
        'Pipeline & Stack & KX & CERT & ECH & KX & CERT & ECH & AUROC\\\\\\midrule\n' + '\n'.join(lines[:-1]) +
        '\n\\bottomrule\\end{tabular}\\end{table}\n', encoding='utf-8')
    # repair table
    rows = []
    for key, lab, name in REPAIRS:
        cs = []
        for m, _ in MODELS:
            v = rep[(lab, m)]
            cs += [f"{f2(v['recall'])}", f"{f2(v['fpr'])}", f"{f2(v['auroc'])}"]
        short = lambda x: '1' if x >= 0.995 else f'{x:.2f}'[1:]
        rngs = '/'.join(f"{short(rep[(lab, m)]['rec_lo'])}--{short(rep[(lab, m)]['rec_hi'])}" for m, _ in MODELS)
        rows.append(f"{name} & " + ' & '.join(cs) + f" & {rngs}\\\\")
        if lab in ('Rzero', 'Ctrl', 'Rtwoc', 'Rtwobalc', 'Rtworc'):
            rows.append('\\midrule')
    (P / 'tab_repair.tex').write_text(
        '\\begin{table}[t]\\centering\\caption{Repairs: mean recall, FPR and AUROC over the 21 migrated cells (main fold, test '
        'repetitions). Unless marked R0, thresholds stay at 1\\,\\% FPR on the pre-migration baseline. R0 needs only known-clean '
        'post-migration traffic, R1 none; R2, R2b, R2r and R3 need labelled post-migration flows. Last column: range of the mean '
        'recall over the three folds for LightGBM / random forest / MLP.}\\label{tab:b_repair}\n\\footnotesize\\setlength{\\tabcolsep}{2.5pt}'
        '\\begin{tabular}{lrrrrrrrrrr}\\toprule & \\multicolumn{3}{c}{LightGBM} & \\multicolumn{3}{c}{Random forest} & '
        '\\multicolumn{3}{c}{MLP} & Folds\\\\\\cmidrule(lr){2-4}\\cmidrule(lr){5-7}\\cmidrule(lr){8-10} Repair & Rec. & FPR & AUC & '
        'Rec. & FPR & AUC & Rec. & FPR & AUC & recall\\\\\\midrule\n' + '\n'.join(rows) +
        '\n\\bottomrule\\end{tabular}\\end{table}\n', encoding='utf-8')


def figs(ev, H, rep):
    fig, axs = plt.subplots(3, len(DET), figsize=(7.2, 5.0), sharey=True)
    for k, (key, model, name) in enumerate(DET):
        for r, (met, cmap, vmax) in enumerate((('recall', 'RdYlGn', 1), ('fpr', 'RdYlGn_r', 0.3), ('auroc', 'RdYlGn', 1))):
            M = grid(ev, key, model, met)
            ax = axs[r, k]
            ax.imshow(M, cmap=cmap, vmin=0.5 if met == 'auroc' else 0, vmax=vmax, aspect='auto')
            for i in range(M.shape[0]):
                for j in range(M.shape[1]):
                    if not np.isnan(M[i, j]):
                        ax.text(j, i, f'{M[i, j]:.2f}'[1:] if M[i, j] < 1 else '1', ha='center', va='center', fontsize=5.5)
            ax.set_xticks(range(len(CN))); ax.set_xticklabels(CN if r == 2 else [], rotation=90, fontsize=6)
            ax.set_yticks(range(3)); ax.set_yticklabels([GNAME[g] for g in GROUPS], fontsize=6.5)
            if r == 0:
                ax.set_title(name, fontsize=7.5)
        for r, lab in enumerate(('recall', 'FPR (scale 0-0.3)', 'AUROC (scale 0.5-1)')):
            axs[r, 0].set_ylabel(lab, fontsize=7)
    fig.tight_layout(); fig.savefig(P / 'b_fig_detect.pdf'); plt.close(fig)
    fig, axs = plt.subplots(1, 2, figsize=(7.2, 2.7))
    for ax, k, t in ((axs[0], 'ch_len', 'ClientHello bytes (TCP)'), (axs[1], 'hs_s2c_bytes', 'Server handshake bytes')):
        x = np.arange(len(COMBOS)); w = 0.27
        for i, g in enumerate(GROUPS):
            ys = [H[(H.group == g) & (H.combo == cname(c))][k].astype(float).mean() for c in COMBOS]
            ax.bar(x + (i - 1) * w, ys, w, label=GNAME[g], color=['#3182bd', '#e6550d', '#31a354'][i])
        ax.set_xticks(x); ax.set_xticklabels(CN, rotation=45, ha='right', fontsize=6.5); ax.set_title(t, fontsize=8)
    try:
        rw = pd.read_csv(D / 'b_realworld.csv')
        m = rw.groupby('kx')[['ch_len']].median()
        axs[0].axhline(m.loc['classical', 'ch_len'], color='k', ls=':', lw=0.7)
        axs[0].axhline(m.loc['hybrid', 'ch_len'], color='k', ls='--', lw=0.7)
    except Exception:
        pass
    axs[1].set_ylim(0, axs[1].get_ylim()[1] * 1.3)  # headroom so the legend does not cover the bars
    axs[1].legend(fontsize=6.5, frameon=False, loc='upper left', ncol=3)
    fig.tight_layout(); fig.savefig(P / 'b_fig_handshake.pdf'); plt.close(fig)
    fig, ax = plt.subplots(figsize=(7.2, 2.7))
    labs = [(lab, re.sub(r'\$\^\{?-\}?\$', '-', n.split(' ')[0])) for _, lab, n in REPAIRS]
    labs = [(l, n if n != 'No' else 'none') for l, n in labs]
    names = ['none', 'R0', 'R1', 'R1-', 'R1b', 'ctrl', 'R2 1%', 'R2 5%', 'R2 10%', 'R2b 1%', 'R2b 5%', 'R2b 10%',
             'R2r 1%', 'R2r 5%', 'R2r 10%', 'R3']
    x = np.arange(len(REPAIRS))
    for m, nm, cl in (('lgbm', 'LightGBM', '#3182bd'), ('rf', 'Random forest', '#31a354'), ('mlp', 'MLP', '#e6550d')):
        ax.plot(x, [rep[(l, m)]['recall'] for _, l, _ in REPAIRS], marker='o', ms=3, color=cl, label=f'{nm} recall')
        ax.plot(x, [rep[(l, m)]['fpr'] for _, l, _ in REPAIRS], marker='x', ms=3, ls='--', color=cl, label=f'{nm} FPR')
    ax.set_xticks(x); ax.set_xticklabels(names, rotation=45, ha='right', fontsize=6.5); ax.set_ylim(0, 1.02)
    ax.legend(fontsize=6, frameon=False, ncol=3, loc='center right', bbox_to_anchor=(1.0, 0.62))
    ax.set_ylabel('mean over migrated cells')
    fig.tight_layout(); fig.savefig(P / 'b_fig_repair.pdf'); plt.close(fig)
    sh = ev.get('shift', {})
    fig, axs = plt.subplots(1, 3, figsize=(7.2, 2.6))
    for ax, fac, t in zip(axs, ('kx', 'cert', 'ech'), ('hybrid key exchange', 'ML-DSA certificate', 'ECH')):
        acc = {}
        for k, rows in sh.items():
            if k.endswith('|' + fac):
                for feat, v in rows.items():
                    acc.setdefault(feat, []).append(v['psi'])
        top = sorted(((np.mean(v), f) for f, v in acc.items()), reverse=True)[:10]
        ax.barh(range(len(top))[::-1], [a for a, _ in top], color='#756bb1')
        ax.set_yticks(range(len(top))[::-1]); ax.set_yticklabels([f.replace('bidirectional_', 'bi_').replace('src2dst_', 'c2s_')
                                                                   .replace('dst2src_', 's2c_') for _, f in top], fontsize=5.5)
        ax.axvline(0.25, color='k', ls=':', lw=0.6); ax.set_title(t, fontsize=8); ax.set_xlabel('PSI', fontsize=7)
    fig.tight_layout(); fig.savefig(P / 'b_fig_shift.pdf'); plt.close(fig)
    method_fig()


def method_fig():
    fig, ax = plt.subplots(figsize=(7.2, 2.3)); ax.axis('off'); ax.set_xlim(0, 100); ax.set_ylim(0, 30)

    def box(x, y, w, h, t, c):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0.3', fc=c, ec='#555555', lw=0.6))
        ax.text(x + w / 2, y + h / 2, t, ha='center', va='center', fontsize=6.3)

    def arr(x1, y1, x2, y2):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle='->', lw=0.7, color='#333333'))
    box(1, 16, 19, 12, '8 clients (Mininet)\nGo 1.27 / OpenSSL 4.0.3\n50 Mbit/s, 20 ms\n6 benign + 3 malicious\nprofiles, seeded', '#f0f0f0')
    box(26, 16, 19, 12, 'Server (Go, quic-go)\nECDSA | ML-DSA-65 leaf\nECH key, TCP | QUIC\n1 Gbit/s link', '#f0f0f0')
    box(51, 16, 20, 12, '24 cells:\nKX x CERT x ECH x\nstack/transport\ncapture at server', '#deebf7')
    box(77, 16, 21, 12, 'Features: NFStream (77),\nJA3/JA4, ClientHello,\nfull vs post-handshake\nstats, first 6x100 bytes', '#deebf7')
    box(1, 1, 30, 11, 'Train on baseline (classical,\nECDSA, no ECH); thresholds at\n1% / 5% FPR on baseline benign', '#e5f5e0')
    box(37, 1, 28, 11, 'Test every cell (3 folds):\nLightGBM, RF, MLP, IForest,\nbyte CNN, JA3/JA4 coverage', '#e5f5e0')
    box(71, 1, 27, 11, 'Shift accounting (PSI, KS)\nRepairs: R0 threshold, R1 post-\nhandshake, R2 few-shot, R3', '#fde0dd')
    arr(20, 22, 26, 22); arr(45, 22, 51, 22); arr(71, 22, 77, 22); arr(80, 16, 18, 12); arr(87, 16, 55, 12)
    arr(31, 6.5, 37, 6.5); arr(65, 6.5, 71, 6.5)
    fig.savefig(P / 'b_fig_method.pdf', bbox_inches='tight'); plt.close(fig)


if __name__ == '__main__':
    main()
