// The size-controlled origin behind the cost table.
//
// `?n=<bytes>` returns exactly that many bytes of real minified JavaScript, tiled from the same
// 154 KiB corpus the offline benches use, so a figure taken here and a figure taken in `live/`
// describe the same content. Cloudflare gzips it on the way out, which is the point: the cost
// table is about decompressed megabytes arriving over a compressed wire, and a body that does not
// compress like content measures the wrong thing.
//
// Tiled rather than repeated at a small period. gzip's window is 32 KiB, so a repeat further apart
// than that does not compress; an earlier origin tiled a 150-byte fragment, hit 220:1, and erased
// the per-wire-byte cost from every number taken against it.
//
// This lived outside the repository until August 2026, was deleted, and took the reproducibility of
// the cost table with it. It is committed now for that reason and no other — nothing in `src/`
// imports it, and it is not published.
//
//   npx wrangler deploy        (from this directory)
//   https://<name>.workers.dev/?n=4194304

import { CORPUS } from '../../live/src/corpus.js';

const MAX = 32 << 20;

export default {
  fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/health') return new Response('ok');
    const n = Math.min(MAX, Math.max(0, Number(url.searchParams.get('n') ?? 0)));
    const out = new Uint8Array(n);
    for (let o = 0; o < n; o += CORPUS.byteLength) {
      out.set(CORPUS.subarray(0, Math.min(CORPUS.byteLength, n - o)), o);
    }
    return new Response(out, {
      headers: {
        // text/javascript is what makes the edge compress it. Length is explicit so the client
        // sees a framed body rather than a chunked one, which is the shape the table assumes.
        'content-type': 'text/javascript; charset=utf-8',
        'cache-control': 'no-store',
      },
    });
  },
};
