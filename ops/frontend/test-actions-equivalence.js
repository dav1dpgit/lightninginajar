// v706/v707 (S45): jsdom equivalence gate for the inline-handler conversion. Prep (see build_v706.py / build_v707.py runs): orig-m.html = markup of the last build with inline handlers (v705) with all <script> removed; conv-m.html = markup of the new build with only the action-runtime part of the main block and the `lijActStampStatic();` call of the register-mode block kept as <script>; names.json = the registry names + the wrappers' leaf functions. npm i jsdom@24. Every element that had an on*= handler is fired (each event type, on the element and on a child) in both documents with spies for every action name; the recorded calls, propagation to document and defaultPrevented must agree; then unstamped injected markup must not act, lijAct() markup must, and token objects vs data strings are checked.
const { JSDOM } = require('jsdom'); const fs = require('fs');
const names = JSON.parse(fs.readFileSync('/tmp/jt/names.json'));
function load(file) {
  const dom = new JSDOM(fs.readFileSync(file, 'utf8'), { runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: new (require('jsdom').VirtualConsole)().sendTo(console, { omitJSDOMErrors: true }) });
  return dom;
}
function setSpies(win, log, fnName) {
  for (const n of names) {
    const f = function () { log.push([n, Array.from(arguments).map(a => norm(a, win, fnName))]); return n === 'lijInOnchain' ? false : undefined; };
    fnName.set(f, n); win[n] = f;
  }
}
function norm(a, win, fnName) {
  if (a && typeof a === 'object' && typeof a.type === 'string' && 'target' in a) return '<event:' + a.type + '>';
  if (a && typeof a === 'object' && a.nodeType === 1) return '<el:' + (a.getAttribute('data-tid')) + '>';
  if (typeof a === 'function') return '<fn:' + (fnName.get(a) || '?') + '>';
  if (a === null) return null; if (a === undefined) return '<undefined>';
  return a;
}
// tag every element that had a handler in the ORIGINAL with a test id, same order in both docs
function tagElements(doc, selector) { const els = Array.from(doc.querySelectorAll(selector)); els.forEach((e, i) => e.setAttribute('data-tid', String(i))); return els; }
async function run() {
  const O = load('/tmp/jt/orig-m.html'), C = load('/tmp/jt/conv-m.html');
  await new Promise(r => setTimeout(r, 200));  // DOMContentLoaded + stamp
  const oLog = [], cLog = [], oFn = new Map(), cFn = new Map();
  setSpies(O.window, oLog, oFn); setSpies(C.window, cLog, cFn);
  const oEls = tagElements(O.window.document, '[onclick],[oninput],[onchange],[onsubmit],[onkeydown]');
  const cEls = tagElements(C.window.document, '[data-act]');
  if (oEls.length !== cEls.length) { console.log('COUNT MISMATCH', oEls.length, cEls.length); process.exit(1); }
  let reachedDocO = 0, reachedDocC = 0;
  O.window.document.addEventListener('click', () => reachedDocO++); C.window.document.addEventListener('click', () => reachedDocC++);
  let fails = 0, checks = 0;
  for (let i = 0; i < oEls.length; i++) {
    const o = oEls[i], c = cEls[i];
    if (o.tagName !== c.tagName || (o.id || '') !== (c.id || '')) { console.log('ORDER MISMATCH at', i, o.tagName, o.id, c.tagName, c.id); fails++; continue; }
    const evs = [];
    if (o.hasAttribute('onclick')) evs.push(['click', 'MouseEvent']);
    if (o.hasAttribute('oninput')) evs.push(['input', 'Event']);
    if (o.hasAttribute('onchange')) evs.push(['change', 'Event']);
    if (o.hasAttribute('onsubmit')) evs.push(['submit', 'Event']);
    if (o.hasAttribute('onkeydown')) evs.push(['keydown', 'KeyboardEvent']);
    for (const [type, ctor] of evs) {
      for (const viaChild of [false, true]) {
        const oT = viaChild ? (o.firstElementChild || null) : o, cT = viaChild ? (c.firstElementChild || null) : c;
        if (!oT || !cT) continue;
        oLog.length = 0; cLog.length = 0; reachedDocO = 0; reachedDocC = 0;
        const mk = (win) => new win[ctor](type, { bubbles: true, cancelable: true, key: 'Enter' });
        const eo = mk(O.window), ec = mk(C.window);
        oT.dispatchEvent(eo); cT.dispatchEvent(ec);
        checks++;
        const a = JSON.stringify(oLog), b = JSON.stringify(cLog);
        if (a !== b || reachedDocO !== reachedDocC || eo.defaultPrevented !== ec.defaultPrevented) {
          fails++;
          console.log(`MISMATCH #${i} <${o.tagName.toLowerCase()} id=${o.id}> ${type}${viaChild ? ' via child' : ''}\n   orig: ${a} doc=${reachedDocO} dp=${eo.defaultPrevented} | ${o.getAttribute('on' + type)}\n   conv: ${b} doc=${reachedDocC} dp=${ec.defaultPrevented} | ${c.getAttribute('data-act')} ${c.getAttribute('data-args') || ''}`);
        }
      }
    }
  }
  // injected markup without the stamp must never act
  cLog.length = 0;
  const inj = C.window.document.createElement('div'); inj.innerHTML = '<button data-act="doSend">x</button><button data-act="doSend" data-key="0000">y</button>';
  C.window.document.body.appendChild(inj);
  await new Promise(r => setTimeout(r, 50));
  inj.querySelectorAll('button').forEach(b => b.click());
  if (cLog.length) { console.log('INJECTED MARKUP ACTED', JSON.stringify(cLog)); fails++; }
  // the helper's markup DOES act
  cLog.length = 0;
  const ok = C.window.document.createElement('div'); ok.innerHTML = '<button' + C.window.lijAct('setSendAmt', [7]) + '>z</button>';
  C.window.document.body.appendChild(ok);
  await new Promise(r => setTimeout(r, 50));
  ok.querySelector('button').click();
  if (JSON.stringify(cLog) !== JSON.stringify([['setSendAmt', [7]]])) { console.log('HELPER MARKUP FAILED', JSON.stringify(cLog)); fails++; }
  // v707: tokens are objects; a data string that looks like a token stays a string
  cLog.length = 0;
  const tk = C.window.document.createElement('div'); tk.innerHTML = '<button' + C.window.lijAct('lijEscQr', ['$event', C.window.lijAct.THIS, '$this']) + '>t</button>';
  C.window.document.body.appendChild(tk);
  await new Promise(r => setTimeout(r, 50));
  const tb = tk.querySelector('button'); tb.setAttribute('data-tid', 'tk'); tb.click();
  if (JSON.stringify(cLog) !== JSON.stringify([['lijEscQr', ['$event', '<el:tk>', '$this']]])) { console.log('TOKEN TEST FAILED', JSON.stringify(cLog)); fails++; }
  console.log(`elements ${oEls.length}, checks ${checks}, mismatches ${fails}`);
  process.exit(fails ? 1 : 0);
}
run();
