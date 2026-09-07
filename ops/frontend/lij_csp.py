#!/usr/bin/env python3
# lij_csp.py — v704 (S45, DP GO — the CSP strict-mode lift, step 1).
#
# The wallet page's inline <script> blocks are hashed here, from the FINAL page
# bytes, at cut time, and the hashes are written into lij-pwa/frontend/_headers.
# Every build_vNNN.py calls write_and_gate() after its own cuts (the banner
# ENTRY lives inside a script block, so at least one hash changes every build).
#
# Facts the design rests on (read from the bytes, S45 open):
# - A CSP hash source = base64(sha256(the script element's text, UTF-8)),
#   exactly the bytes between <script ...> and </script>; the parser does no
#   entity decoding inside script text, so the file bytes are the hashed bytes.
# - CI copies lij-pwa/frontend verbatim to the deploy branch; Cloudflare adds
#   only its honeypot <a> after <body>, outside every script block (DP's diff
#   2026-09-05), so the hashes survive serving.
# - Once a hash source appears in script-src, browsers IGNORE 'unsafe-inline'
#   in that directive — so the hashes ride Content-Security-Policy-Report-Only
#   (console only, no report-uri) until step 3 flips the enforcing header.
# - Scope /wallet/* only: the site root and /join carry their own inline
#   script and keep the /* policy.
# - ONE block per path in _headers: Cloudflare's parser keys rules by path
#   (workers-sdk constructConfiguration.ts `rules[rule.path] = ...`), so a
#   second `/wallet/*` block overwrites the first (v704 served no Report-Only
#   for exactly this reason; fixed v705).
import re, hashlib, base64, sys

PAGE = 'lij-pwa/frontend/wallet/index.html'
HEADERS = 'lij-pwa/frontend/_headers'
SCRIPT_RE = re.compile(r'<script\b([^>]*)>(.*?)</script>', re.S)
RO_LINE_RE = re.compile(r'^  Content-Security-Policy-Report-Only: .*$', re.M)
# v708 (the flip): the wallet block unsets the /* policy and sets the strict one — the two lines are matched together
STRICT_LINES_RE = re.compile(r'^  ! Content-Security-Policy\n  Content-Security-Policy: .*$', re.M)

# The strict policy: identical to the enforcing /* line except script-src.
STRICT_TAIL = ("; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; "
               "connect-src 'self' https: wss:; worker-src 'self' blob:; frame-ancestors 'none'; "
               "object-src 'none'; base-uri 'self'; form-action 'self'")


def inline_blocks(page_text):
    """[(line_no, attrs, body)] for every <script> without src, in document order."""
    out = []
    for m in SCRIPT_RE.finditer(page_text):
        attrs, body = m.group(1), m.group(2)
        if re.search(r'\bsrc\s*=', attrs):
            continue
        out.append((page_text[:m.start()].count('\n') + 1, attrs.strip(), body))
    return out


def hashes(page_text):
    return ["'sha256-%s'" % base64.b64encode(hashlib.sha256(b.encode('utf-8')).digest()).decode('ascii')
            for _, _, b in inline_blocks(page_text)]


def strict_policy(hs):
    return "default-src 'self'; script-src 'self' " + ' '.join(hs) + " 'wasm-unsafe-eval'" + STRICT_TAIL


def census(page_text):
    """What a strict script-src would still block: inline handlers in the static
    markup, handlers built inside script text, setAttribute('on...') sites.
    Step 3's gate needs all three at 0."""
    parts = re.split(r'(<script\b[^>]*>.*?</script>)', page_text, flags=re.S)
    markup = ''.join(p for p in parts if not p.startswith('<script'))
    script = ''.join(p for p in parts if p.startswith('<script'))
    return {
        'static_on': len(re.findall(r'\son[a-z]+\s*=', markup)),
        'js_built_on': len(re.findall(r'\son[a-z]+\s*=\s*["\']', script)),
        'set_attribute_on': len(re.findall(r'\.setAttribute\(\s*["\']on', script)),
        'inline_blocks': len(inline_blocks(page_text)),
    }


def write_headers(headers_text, hs, enforcing=False):
    """Write the strict policy for these hashes: before the flip onto the single
    Report-Only line; from v708 onto the wallet block's unset+set pair."""
    if enforcing:
        n = len(STRICT_LINES_RE.findall(headers_text))
        if n != 1:
            raise SystemExit('GATE FAIL: _headers strict unset+set pair matched %d (want 1)' % n)
        if RO_LINE_RE.search(headers_text):
            raise SystemExit('GATE FAIL: a Report-Only line survives after the flip')
        return STRICT_LINES_RE.sub('  ! Content-Security-Policy\n  Content-Security-Policy: ' + strict_policy(hs), headers_text)
    n = len(RO_LINE_RE.findall(headers_text))
    if n != 1:
        raise SystemExit('GATE FAIL: _headers Report-Only line matched %d (want 1)' % n)
    return RO_LINE_RE.sub('  Content-Security-Policy-Report-Only: ' + strict_policy(hs), headers_text)


def write_and_gate(expected_blocks=9, enforcing=True):
    """Called by build_vNNN.py after the page is written. Reads the page from
    disk (the final bytes), writes _headers, re-reads both and checks.
    enforcing=True (v708 on): the strict policy is the wallet's ENFORCING CSP,
    so the census must be 0/0/0 — any inline handler would be dead."""
    page = open(PAGE, encoding='utf-8').read()
    hs = hashes(page)
    if len(hs) != expected_blocks:
        raise SystemExit('GATE FAIL: %d inline script blocks, expected %d' % (len(hs), expected_blocks))
    ht = open(HEADERS, encoding='utf-8').read()
    open(HEADERS, 'w', encoding='utf-8').write(write_headers(ht, hs, enforcing))
    # gate: what is on disk agrees with itself
    page2 = open(PAGE, encoding='utf-8').read()
    ht2 = open(HEADERS, encoding='utf-8').read()
    line = (STRICT_LINES_RE if enforcing else RO_LINE_RE).search(ht2).group(0)
    hs2 = hashes(page2)
    if hs2 != hs:
        raise SystemExit('GATE FAIL: page changed under the cut')
    for h in hs2:
        if h not in line:
            raise SystemExit('GATE FAIL: hash %s missing from _headers' % h)
    if line.count("'sha256-") != len(hs2):
        raise SystemExit('GATE FAIL: _headers carries %d hashes, page has %d' % (line.count("'sha256-"), len(hs2)))
    if "'unsafe-inline'" in line.split('script-src', 1)[1].split(';', 1)[0]:
        raise SystemExit("GATE FAIL: 'unsafe-inline' inside the strict script-src")
    c = census(page2)
    if enforcing and (c['static_on'] or c['js_built_on'] or c['set_attribute_on']):
        raise SystemExit('GATE FAIL: enforcing strict CSP with inline handlers left: %r' % c)
    print('CSP · %d inline blocks hashed · census: static on*= %d, JS-built on*= %d, setAttribute(on) %d'
          % (len(hs2), c['static_on'], c['js_built_on'], c['set_attribute_on']))
    return hs2, c


if __name__ == '__main__':
    # `python3 ops/frontend/lij_csp.py` from the repo root: print, write nothing.
    page = open(PAGE, encoding='utf-8').read()
    for (ln, attrs, body), h in zip(inline_blocks(page), hashes(page)):
        print('line %6d  %8d bytes  %s  %s' % (ln, len(body), h, attrs))
    print(census(page))
