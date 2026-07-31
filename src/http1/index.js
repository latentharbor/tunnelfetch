// HTTP/1.1 wire layer: serialise request heads, parse response heads, frame bodies.
//
// This layer owns message boundaries and nothing else. It does not manage connections, follow
// redirects, or decode content codings; it guarantees exactly one thing — that the bytes it
// attributes to a message are precisely the bytes the framing rules assign to it, and that any
// ambiguity about where a message ends is an error instead of a guess.

export { serializeRequestHead } from './request.js';
export { readResponseHead, bodyFraming, readResponseBody } from './response.js';
export { decodeChunked } from './chunked.js';
