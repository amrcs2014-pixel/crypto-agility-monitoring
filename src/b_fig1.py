"""Paper B Figure 1 (four-stage layout supplied by the authors, redrawn as a vector figure with corrected details).
Drawn at 12 x 6.75 in so that, printed at full text width (about 17.4 cm), the smallest lettering is about 7 pt.
Writes paperB/b_fig_method.pdf (vector, used in the manuscript) and paperB/b_fig_method.png (300 dpi)."""
import re
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
matplotlib.rcParams['pdf.fonttype'] = 42  # embed TrueType, not Type 3, fonts
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle, Polygon, Circle

W = Path(__file__).resolve().parents[1]
P = W / 'outputs'  # generated figures
plt.rcParams.update({'font.family': 'DejaVu Sans'})
INK = '#1a1a1a'
ST = {1: ('#e8f0fa', '#bcd2ec', '#3d6aa3'), 2: ('#eaf5e6', '#c5e3bb', '#4a8a3c'),
      3: ('#fdf0e3', '#f7d3ae', '#c27a2c'), 4: ('#f1ecf7', '#d8cbe9', '#7a5aa6')}
FT, FH, FB = 14.5, 12.5, 11.5   # stage titles, box headings, body text (points at 12 in width)


def nflows():
    t = (P / 'numbers_B.tex').read_text(encoding='utf-8')
    m = re.search(r'\\newcommand\{\\NFlows\}\{([^}]*)\}', t)
    return m.group(1) if m else '44,386'


def draw(out=P):
    fig = plt.figure(figsize=(12, 6.75))
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 160); ax.set_ylim(0, 90); ax.axis('off')

    def rbox(x, y, w, h, fc, ec, lw=1.3, r=1.4, z=1):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f'round,pad=0,rounding_size={r}', fc=fc, ec=ec, lw=lw, zorder=z))

    def panel(x, y, w, h, k, title):
        bg, hd, ed = ST[k]
        rbox(x, y, w, h, bg, ed, lw=1.1, r=2.0)
        rbox(x, y + h - 6.2, w, 6.2, hd, ed, lw=1.1, r=2.0, z=2)
        ax.add_patch(Rectangle((x + 0.15, y + h - 6.2), w - 0.3, 2.0, fc=hd, ec='none', zorder=2))
        ax.text(x + w / 2, y + h - 3.1, title, ha='center', va='center', fontsize=FT, weight='bold', color=INK, zorder=3)

    def arrow(p, q, col='#5b6f8c', lw=2.6, ms=20, z=6, cs='arc3'):
        ax.add_patch(FancyArrowPatch(p, q, arrowstyle='-|>', mutation_scale=ms, color=col, lw=lw, zorder=z,
                                     connectionstyle=cs))

    def line(p, q, col='#6f6f6f', lw=1.1, ls=(0, (2, 2)), z=2):
        ax.plot([p[0], q[0]], [p[1], q[1]], color=col, lw=lw, ls=ls, zorder=z)

    def monitor(cx, cy, s=1.0):
        ax.add_patch(Rectangle((cx - 2.3 * s, cy - 1.2 * s), 4.6 * s, 3.0 * s, fc='#dfe6ee', ec='#3a3a3a', lw=1.1, zorder=4))
        ax.add_patch(Rectangle((cx - 0.4 * s, cy - 2.0 * s), 0.8 * s, 0.8 * s, fc='#3a3a3a', ec='none', zorder=4))
        ax.add_patch(Rectangle((cx - 1.4 * s, cy - 2.3 * s), 2.8 * s, 0.4 * s, fc='#3a3a3a', ec='none', zorder=4))

    # ------------------------------------------------------------------ Stage 1
    panel(2, 47, 76, 41, 1, 'Stage 1: Emulated testbed and workloads')
    clients = [(8, 77), (8, 71.5), (8, 66), (17, 77), (17, 66), (26, 77), (26, 71.5), (26, 66)]
    sw = (40, 71.5)
    for c in clients:
        line(c, sw)
    for c in clients:
        monitor(*c, s=0.9)
    rbox(sw[0] - 4.0, sw[1] - 2.5, 8.0, 5.0, '#7fa6d6', '#2f5684', lw=1.4, r=1.0, z=5)
    arrow((sw[0] - 2.4, sw[1] + 0.9), (sw[0] + 2.4, sw[1] + 0.9), col='white', lw=1.4, ms=9, z=7)
    arrow((sw[0] + 2.4, sw[1] - 0.9), (sw[0] - 2.4, sw[1] - 0.9), col='white', lw=1.4, ms=9, z=7)
    ax.text(sw[0], sw[1] - 3.4, 'Open vSwitch', ha='center', va='top', fontsize=FB, color=INK)
    sx, sy = 63, 64.5
    line((sw[0] + 4.0, sw[1]), (sx, sw[1]), ls='-', lw=1.8, col='#3a3a3a')
    rbox(sx, sy, 7, 14, '#5f6670', '#2b2b2b', lw=1.4, r=0.8, z=4)
    for i in range(3):
        ax.add_patch(Rectangle((sx + 1.0, sy + 10.2 - 2.4 * i), 5.0, 1.3, fc='#9fb6cf', ec='none', zorder=5))
    ax.add_patch(Circle((sx + 3.5, sy + 2.6), 0.7, fc='#7cc36b', ec='none', zorder=5))
    ax.add_patch(Polygon([(sx - 3.6, sw[1] + 2.6), (sx - 1.4, sw[1] + 2.6), (sx - 2.5, sw[1] + 0.6)], closed=True,
                         fc='#c8102e', ec='none', zorder=6))
    ax.text(sx - 4.2, sw[1] + 1.8, 'capture', ha='right', va='center', fontsize=FB, color='#c8102e')
    ax.text(18, 60.0, '8 clients (Mininet)', ha='center', va='top', fontsize=FH, weight='bold', color=INK)
    ax.text(18, 57.2, 'Go 1.27, OpenSSL 4.0.3\n50 Mbit/s, 20 ms delay\n9 profiles (3 malicious)',
            ha='center', va='top', fontsize=FB, color=INK, linespacing=1.25)
    ax.text(57, 60.0, 'Server (Go, quic-go)', ha='center', va='top', fontsize=FH, weight='bold', color=INK)
    ax.text(57, 57.2, '1 Gbit/s link; TCP and QUIC\nECH key always loaded\nECDSA or ML-DSA-65 leaf',
            ha='center', va='top', fontsize=FB, color=INK, linespacing=1.25)

    # ------------------------------------------------------------------ Stage 2
    panel(82, 47, 76, 41, 2, 'Stage 2: Factorial design and features')
    ox, oy, a, dx, dy = 86.0, 67.0, 4.0, 2.5, 1.8
    E = '#3b6e31'
    for i in range(2):
        for j in range(2):
            ax.add_patch(Polygon([(ox + a * i, oy + a * j), (ox + a * (i + 1), oy + a * j), (ox + a * (i + 1), oy + a * (j + 1)),
                                  (ox + a * i, oy + a * (j + 1))], fc='#a8d39a', ec=E, lw=1.1, zorder=4))
            ax.add_patch(Polygon([(ox + a * i + dx * j, oy + 2 * a + dy * j), (ox + a * (i + 1) + dx * j, oy + 2 * a + dy * j),
                                  (ox + a * (i + 1) + dx * (j + 1), oy + 2 * a + dy * (j + 1)),
                                  (ox + a * i + dx * (j + 1), oy + 2 * a + dy * (j + 1))], fc='#c9e6bf', ec=E, lw=1.1, zorder=4))
            ax.add_patch(Polygon([(ox + 2 * a + dx * i, oy + a * j + dy * i), (ox + 2 * a + dx * (i + 1), oy + a * j + dy * (i + 1)),
                                  (ox + 2 * a + dx * (i + 1), oy + a * (j + 1) + dy * (i + 1)),
                                  (ox + 2 * a + dx * i, oy + a * (j + 1) + dy * i)], fc='#8cc27c', ec=E, lw=1.1, zorder=4))
    ax.text(101, 78.6, f'24 configurations ({nflows()} flows)', ha='left', va='center', fontsize=FH, weight='bold', color=INK)
    ax.text(101, 76.4, 'KX: classical | hybrid X25519MLKEM768\n× CERT: ECDSA | ML-DSA-65\n× ECH: off | on\n'
            '× Go/TCP, OpenSSL/TCP, Go/QUIC', ha='left', va='top', fontsize=FB, color=INK, linespacing=1.25)
    feats = [(84, 55.4, 'NFStream: 77 features'), (120, 55.4, 'ClientHello, JA3 / JA4'),
             (84, 48.6, 'Whole-flow vs post-\nhandshake stats (R1)'), (120, 48.6, 'First 6 × 100\npayload bytes')]
    ax.text(120, 63.6, 'Per-flow features', ha='center', va='center', fontsize=FH, weight='bold', color=INK, zorder=3)
    for k, (x, y, t) in enumerate(feats, 1):
        rbox(x, y, 34, 6.2, 'white', ST[2][2], lw=1.0, r=0.8, z=3)
        ax.text(x + 17, y + 3.1, f'{k}) {t}', ha='center', va='center', fontsize=FB, color=INK, zorder=4, linespacing=1.1)

    # ------------------------------------------------------------------ Stage 3
    panel(2, 2, 76, 41, 3, 'Stage 3: Baseline-trained monitoring')
    for x, head, body in ((5, 'Training', 'pre-migration baseline\nonly (classical KX,\nECDSA, no ECH)\n\nthresholds at 1 % and\n'
                                          '5 % FPR on baseline\nbenign flows'),
                          (43, 'Testing', 'all 24 configurations\n(3 folds × 5 seeds)\n\nLightGBM, random forest,\n'
                                          'MLP, Isolation Forest,\nbyte CNN; JA3/JA4\ninventories')):
        rbox(x, 5, 32, 30, 'white', ST[3][2], lw=1.3, r=1.2, z=2)
        ax.text(x + 16, 31.8, head, ha='center', va='center', fontsize=FH, weight='bold', color=INK, zorder=3)
        ax.text(x + 16, 28.8, body, ha='center', va='top', fontsize=FB, color=INK, linespacing=1.25, zorder=3)
    arrow((37.4, 20), (42.6, 20), col=ST[3][2], lw=2.2, ms=16)

    # ------------------------------------------------------------------ Stage 4
    panel(82, 2, 76, 41, 4, 'Stage 4: Shift, uneven migration, repairs')
    boxes = [(27.8, 6.6, 'Shift accounting', 'PSI, KS; label-free shift alarm'),
             (20.6, 6.6, 'Uneven client migration', 'benign-first, attacker-first, staggered'),
             (10.6, 9.4, 'Repairs', 'R0 threshold reset   R1 post-handshake\nR2 few-shot retraining   R3 full retraining'),
             (3.4, 6.6, 'Robustness', 'base rates, seeds, padded attacks')]
    for y, h, t_, s in boxes:
        rbox(90, y, 66, h, 'white', ST[4][2], lw=1.2, r=1.0, z=2)
        ax.text(92, y + h - 2.0, t_, ha='left', va='center', fontsize=FH, weight='bold', color=INK, zorder=3)
        ax.text(92, y + h - 3.9, s, ha='left', va='top', fontsize=FB, color=INK, zorder=3, linespacing=1.25)
    ax.plot([86.5, 86.5], [6.7, 31.1], color=ST[4][2], lw=1.8, zorder=2)
    for y, h, _, _ in boxes:
        arrow((86.5, y + h / 2), (89.8, y + h / 2), col=ST[4][2], lw=1.6, ms=12)

    # ------------------------------------------------------------------ flow between stages
    arrow((78.4, 76), (81.6, 76)); arrow((78.4, 58), (81.6, 58))
    arrow((120, 46.6), (40, 43.4), cs='angle,angleA=-90,angleB=0,rad=0')
    arrow((78.4, 22), (81.6, 22))
    fig.savefig(out / 'b_fig_method.pdf'); fig.savefig(out / 'b_fig_method.png', dpi=300); plt.close(fig)


if __name__ == '__main__':
    draw()
