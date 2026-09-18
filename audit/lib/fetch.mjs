// gvp-audit: fetch FREE surfaces only. Never signs, never pays, never retries a 402 with a payment
// header. A 402 is recorded as "paid route: supply served bodies", which is the honest answer -- the
// audit is over what the buyer actually received, and only the seller (or a paying buyer) has that.
export const MAX_BODY_BYTES = 16 * 1024 * 1024;
export const MAX_TIMES = 10;

// Read a body with a byte budget so a hostile URL cannot exhaust memory inside the timeout window.
async function readCapped(res, cap) {
  const len = Number(res.headers.get('content-length'));
  if (Number.isFinite(len) && len > cap) throw new Error(`body exceeds ${cap} bytes (content-length ${len})`);
  const reader = res.body && res.body.getReader ? res.body.getReader() : null;
  if (!reader) { const t = await res.text(); if (Buffer.byteLength(t, 'utf8') > cap) throw new Error(`body exceeds ${cap} bytes`); return t; }
  const chunks = []; let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > cap) { try { await reader.cancel(); } catch {} throw new Error(`body exceeds ${cap} bytes`); }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map(c => Buffer.from(c))).toString('utf8');
}

export async function fetchSamples(urls, { times = 2, timeoutMs = 15000, userAgent = 'gvp-audit (free-surface probe; never pays)', maxBytes = MAX_BODY_BYTES } = {}) {
  const out = [];
  const n = Math.max(1, Math.min(MAX_TIMES, Number(times) || 2));
  for (const url of urls) {
    const samples = [];
    let status = null, note = null, contentType = null;
    for (let i = 0; i < n; i++) {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        // Follows redirects; the URL is the operator's own choice. No cookies, no credentials, no payment header, ever.
        const res = await fetch(url, { headers: { 'accept': 'application/json', 'user-agent': userAgent }, signal: ctrl.signal, redirect: 'follow' });
        status = res.status; contentType = res.headers.get('content-type');
        if (res.status === 402) { note = 'paid route (402): the audit needs served bodies; save two paid responses as <route>.1.json / <route>.2.json'; break; }
        if (!res.ok) { note = `HTTP ${res.status}`; break; }
        samples.push({ name: `fetch-${i + 1}`, raw: await readCapped(res, maxBytes) });
      } catch (e) { note = `fetch failed: ${e.name === 'AbortError' ? 'timeout' : e.message}`; break; }
      finally { clearTimeout(t); }
    }
    // Route id = origin + path only: a query string (which may carry a key) never lands in a report.
    let endpoint = null, id = url;
    try { const u = new URL(url); endpoint = u.pathname; id = u.origin + u.pathname; } catch {}
    out.push({ id, endpoint, status, contentType, note, samples });
  }
  return out;
}
