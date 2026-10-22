#!/usr/bin/env python3
"""sw_stamp.py — the service worker's LIJ_EXPECTED map: one sha256 per PRECACHE entry, from the files on disk.

Phase B.2 (docs/design/routes/phase-b2-r1.md §3): a file the worker fetches from Cloudflare's copy instead of the origin
is kept only when its sha256 equals the stamp the worker carries. The stamps are written from the FINAL bytes — by the
page cut (build_vSNNx.py) after every edit to the page, by CI's engine flip after it moves the busters, and checked by
lij-build and gate-v1057 before anything ships.

  python3 ops/frontend/sw_stamp.py --write    rewrite the map between the markers from the files
  python3 ops/frontend/sw_stamp.py --check    exit 1 (and say which) when a stamp differs from its file

The map sits in sw.js between `/* LIJ_EXPECTED_BEGIN */` and `/* LIJ_EXPECTED_END */` on ONE line (the banner law:
tests read sw.js line by line). A PRECACHE entry's file is its path under lij-pwa/frontend with the ?v= query dropped;
'/wallet/' is wallet/index.html.
"""
import hashlib, os, re, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'lij-pwa', 'frontend')
SW = os.path.join(ROOT, 'wallet', 'sw.js')
BEGIN, END = '/* LIJ_EXPECTED_BEGIN */', '/* LIJ_EXPECTED_END */'


def precache(sw):
    m = re.search(r"const PRECACHE = \[(.*?)\];", sw, re.S)
    if not m:
        raise SystemExit('sw_stamp: PRECACHE not found')
    return re.findall(r"'(/[^']*)'", m.group(1))


def file_of(u):
    p = u.split('?', 1)[0]
    if p.endswith('/'):
        p += 'index.html'
    return os.path.join(ROOT, p.lstrip('/'))


def sha(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def expected(sw):
    out = []
    for u in precache(sw):
        f = file_of(u)
        if not os.path.isfile(f):
            raise SystemExit('sw_stamp: PRECACHE names %s but %s is not a file' % (u, f))
        out.append((u, sha(f)))
    return out


def render(pairs):
    body = ', '.join("'%s': '%s'" % (u, h) for u, h in pairs)
    return BEGIN + ' const LIJ_EXPECTED = { ' + body + ' }; ' + END


def current_map(sw):
    i, j = sw.find(BEGIN), sw.find(END)
    if i < 0 or j < 0 or j < i:
        raise SystemExit('sw_stamp: the LIJ_EXPECTED markers are not in sw.js')
    seg = sw[i:j + len(END)]
    if '\n' in seg:
        raise SystemExit('sw_stamp: the LIJ_EXPECTED map spans more than one line')
    return i, j + len(END), dict(re.findall(r"'(/[^']*)': '([0-9a-f]{64})'", seg))


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else '--check'
    sw = open(SW, encoding='utf-8').read()
    pairs = expected(sw)
    i, j, have = current_map(sw)
    if mode == '--write':
        sw2 = sw[:i] + render(pairs) + sw[j:]
        if sw2 != sw:
            open(SW, 'w', encoding='utf-8').write(sw2)
            print('sw_stamp: %d stamps written' % len(pairs))
        else:
            print('sw_stamp: %d stamps already current' % len(pairs))
        return
    bad = [u for u, h in pairs if have.get(u) != h]
    extra = [u for u in have if u not in dict(pairs)]
    if bad or extra:
        for u in bad:
            print('sw_stamp: STALE %s (stamp %s, file %s)' % (u, (have.get(u) or '-')[:12], dict(pairs)[u][:12]))
        for u in extra:
            print('sw_stamp: EXTRA %s (stamped, not in PRECACHE)' % u)
        sys.exit(1)
    print('sw_stamp: %d stamps match their files' % len(pairs))


if __name__ == '__main__':
    main()
