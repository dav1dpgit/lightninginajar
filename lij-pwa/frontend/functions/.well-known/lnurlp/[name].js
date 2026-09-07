// S43 (2026-09-02): the neutral address host, served BY THE PAGES SITE.
// lightninginajar.xyz is a Cloudflare Pages custom domain, and the site
// answered /.well-known/lnurlp/<name> itself (splash/redirect) ahead of the
// worker's zone route — WoS and LiJ both got HTML, not JSON. A Pages Function
// runs before static assets and _redirects on this path, so this is the
// authoritative front door; it hands the request to the LIJOX worker, which
// looks the name up and returns the owning LSP's own payRequest unchanged.
// The callback inside that answer points at the LSP; amounts never come here.
// Cached 60 s at the edge: the worker sees misses, not payers.
const WORKER = 'https://lij-worker.dp-a95.workers.dev';
const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Accept' };
const json = (o, status) => new Response(JSON.stringify(o), { status: status || 200, headers: { ...CORS, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

export async function onRequestOptions() { return new Response(null, { status: 204, headers: CORS }); }

export async function onRequestGet({ params }) {
  const name = String(params.name || '').toLowerCase();
  if (!/^[a-z0-9_-]{2,32}$/.test(name)) return json({ status: 'ERROR', reason: 'bad name' }, 400);
  let up;
  try {
    up = await fetch(WORKER + '/.well-known/lnurlp/' + name, { headers: { 'Accept': 'application/json' }, cf: { cacheTtl: 60, cacheEverything: true } });
  } catch (e) {
    return json({ status: 'ERROR', reason: 'name service unreachable' }, 502);
  }
  const text = await up.text();
  return new Response(text, { status: up.status, headers: { ...CORS, 'Content-Type': 'application/json', 'Cache-Control': up.status === 200 ? 'public, max-age=60' : 'no-store' } });
}
