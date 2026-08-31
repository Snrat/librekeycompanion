# -*- coding: utf-8 -*-
"""Generate mds_icon_preview.html - visual preview of MDS icons grouped by heuristics."""
import json, base64, io, hashlib, collections, warnings, html, os, sys
warnings.filterwarnings('ignore')
from PIL import Image

BLOB = os.path.join(os.environ['TEMP'], 'opencode', 'mds_blob.txt')
OUT = r'C:\Users\Expertbook\Documents\OpenCode\Librekey\mds_icon_preview.html'

jwt = open(BLOB, encoding='utf-8').read().strip()
blob = json.loads(base64.urlsafe_b64decode(jwt.split('.')[1] + '=' * (-len(jwt.split('.')[1]) % 4)))

groups, svgs = {}, {}
for e in blob.get('entries', []):
    ms = e.get('metadataStatement') or {}
    aaguid = e.get('aaguid') or ms.get('aaguid')
    if not aaguid:
        continue
    uri = ms.get('icon')
    if not uri:
        continue
    name = ms.get('description', '?')
    if uri.startswith('data:image/svg'):
        svgs.setdefault(hashlib.md5(uri.encode()).hexdigest()[:8],
                        {'uri': uri, 'names': []})['names'].append(name)
        continue
    try:
        payload = uri.split(',', 1)[1]
        raw = base64.b64decode(payload + '=' * (-len(payload) % 4))
        img = Image.open(io.BytesIO(raw))
        w, h = img.size
        rgba = img.convert('RGBA')
        px = list(rgba.getdata())
        transparent = sum(1 for p in px if p[3] < 250) / len(px)
        colors = len(set(px))
        ar = w / h
        # "Real product image" heuristics: elongated key silhouette OR rich colors
        # (photos/renders have gradients -> thousands of colors; logos are flat).
        is_photo = (ar >= 3) or (colors >= 1000)
        ih = hashlib.md5(uri.encode()).hexdigest()[:8]
        g = groups.setdefault(ih, {'uri': uri, 'names': [], 'ar': ar, 'tr': transparent,
                                   'c': colors, 'kb': len(raw) // 1024, 'photo': is_photo, 'wh': (w, h)})
        g['names'].append(name)
    except Exception:
        pass


def card(ih, g, cls, badge):
    names = sorted(set(g['names']))
    if len(names) <= 6:
        items = ''.join('<li>%s</li>' % html.escape(n) for n in names)
    else:
        items = ''.join('<li>%s</li>' % html.escape(n) for n in names[:4])
        items += '<li>... 共 %d 条</li>' % len(names)
    meta = 'SVG' if 'ar' not in g else '%dx%d · 比例%.1f · 透明%.0f%% · 色%d · %dKB' % (
        g['wh'][0], g['wh'][1], g['ar'], g['tr'] * 100, g['c'], g['kb'])
    return ('<label class="card %s"><input type="checkbox" class="sel" value="%s">'
            '<div class="imgbox"><img src="%s"></div>'
            '<div class="info"><b>%s</b><span class="meta">%s · %d条</span>'
            '<details><summary>条目(%d)</summary><ul>%s</ul></details></div></label>') % (
        cls, ih, g['uri'], badge, meta, len(g['names']), len(names), items)


def section(items, cls, badge):
    return ''.join(card(ih, g, cls, badge) for ih, g in
                   sorted(items.items(), key=lambda kv: -kv[1].get('ar', 0)))


grpProduct = {ih: g for ih, g in groups.items() if g['photo']}
grpLogo = {ih: g for ih, g in groups.items() if not g['photo']}

doc = '''<!DOCTYPE html><html><head><meta charset="utf-8"><title>MDS 图标分类预览</title><style>
body{font-family:'Segoe UI',sans-serif;background:#1b1b1f;color:#eee;margin:20px}
h2{margin:24px 0 8px;color:#ff7fa4}.meta{color:#9aa;font-size:11px;margin:2px 0;display:block}
.grid{display:flex;flex-wrap:wrap;gap:8px}
.card{display:flex;gap:8px;background:#26262c;border:1px solid #3a3a42;border-radius:8px;padding:8px;width:340px;cursor:pointer}
.card:has(input:checked){border-color:#ff4d7e;background:#33202a}
.card img{max-height:56px;max-width:110px;object-fit:contain;background:#fff;border-radius:4px;padding:2px}
.imgbox{width:116px;display:flex;align-items:center;justify-content:center}
.info{font-size:12px;overflow:hidden}details{font-size:11px;color:#bbc}ul{margin:2px 0;padding-left:16px}
button{background:#ff4d7e;color:#fff;border:none;padding:10px 22px;border-radius:6px;font-size:15px;cursor:pointer;position:fixed;top:12px;right:16px;z-index:9}
</style></head><body>
<button onclick="navigator.clipboard.writeText([...document.querySelectorAll('.sel:checked')].map(c=>c.value).join(','))">复制所选组ID</button>
<h1>MDS 图标分类预览（实物图片枚举）</h1>
<p><b>请勾选确认为「实物图片」的组</b>（这些条目各自保留自己的 icon，不参与 CA 共用压缩）→ 复制组ID发回。<br>
未勾选的将归入「厂商共用 icon」集合。误判没关系，勾选就是最终裁决。</p>
<h2>疑似实物图片 (%d组) — 细长剪影 或 高色数照片/渲染</h2><div class="grid">%s</div>
<h2>Logo/图形 (%d组) — 平面色少，疑似可共用</h2><div class="grid">%s</div>
<h2>SVG 矢量 (%d组)</h2><div class="grid">%s</div>
</body></html>''' % (len(grpProduct), section(grpProduct, 'grpA', '实物候选'),
                     len(grpLogo), section(grpLogo, 'grpC', 'Logo/图形'),
                     len(svgs), section(svgs, 'grpD', 'SVG'))

open(OUT, 'w', encoding='utf-8').write(doc)
print('OK: 实物候选 %d 组 / Logo %d 组 / SVG %d 组 -> %s (%d KB)' % (
    len(grpProduct), len(grpLogo), len(svgs), OUT, os.path.getsize(OUT) // 1024))
print()
print('=== 实物候选枚举（组ID | 特征 | 涉及产品）===')
for ih, g in sorted(grpProduct.items(), key=lambda kv: -kv[1].get('ar', 0)):
    u = sorted(set(g['names']))
    meta = 'SVG' if 'ar' not in g else ('比例%-5.2f 色%-5d %3dKB' % (g['ar'], g['c'], g['kb']))
    print('  [%s] %-28s %s' % (ih, meta, ', '.join(u[:2]) + (' 等%d条' % len(g['names']) if len(g['names']) > 2 else '')))
