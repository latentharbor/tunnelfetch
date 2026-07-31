// A scriptable HTTP/2 server peer for offline connection tests.
//
// It sits on one end of an in-memory duplex, reads the client's preface and frames, and hands a
// test fine-grained control over what to send back. It is built on this package's own frame and
// HPACK primitives — which is acceptable here because those primitives are independently pinned
// against the RFC 7541/9113 vectors in huffman.test.js, hpack.test.js and frames.test.js, so a
// bug shared between client and server would already have been caught there, not hidden here.

import { concat } from '../../src/util/bytes.js';
import { ByteReader, ByteWriter } from '../../src/util/bytes.js';
import { HpackDecoder, encodeHeaderBlock } from '../../src/http2/hpack.js';
import {
  readFrame,
  serializeFrame,
  settingsFrame,
  dataFrame,
  headersFrame,
  continuationFrame,
  rstStreamFrame,
  windowUpdateFrame,
  goawayFrame,
  pingFrame,
  parseSettings,
  parseWindowUpdate,
  headersBlockFragment,
  stripPadding,
} from '../../src/http2/frames.js';
import { FRAME, FLAG } from '../../src/http2/constants.js';

const PREFACE_LEN = 24;

/**
 * Drive the server end of `duplex`. `handler(server)` is called once the client preface and its
 * SETTINGS have been read; it uses the returned control surface to send frames and inspect what
 * the client sent. The server auto-ACKs the client SETTINGS and sends its own opening SETTINGS.
 *
 * @param {{ readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array> }} duplex
 * @param {object} [opts]
 * @param {Array<[number, number]>} [opts.settings] server SETTINGS entries to advertise
 */
export function h2Server(duplex, opts = {}) {
  const reader = new ByteReader(duplex.readable);
  const writer = new ByteWriter(duplex.writable);
  const decoder = new HpackDecoder({});
  const requests = new Map(); // streamId -> { headers, body: [], ended, trailers }
  const events = [];
  let onFrame = null;

  const write = (bytes) => writer.write(bytes);

  const api = {
    requests,
    events,
    reader,
    write,
    sendResponse: async (streamId, fields, { endStream = false, maxFrame } = {}) => {
      const block = encodeHeaderBlock(fields);
      if (maxFrame && block.length > maxFrame) {
        // Fragment into HEADERS + CONTINUATION to exercise the client's reassembly.
        const first = block.subarray(0, maxFrame);
        const frames = [headersFrame(streamId, first, { endStream, endHeaders: false })];
        let o = maxFrame;
        while (o < block.length) {
          const chunk = block.subarray(o, Math.min(o + maxFrame, block.length));
          o += chunk.length;
          frames.push(continuationFrame(streamId, chunk, o >= block.length));
        }
        await write(concat(frames));
        return;
      }
      await write(headersFrame(streamId, block, { endStream, endHeaders: true }));
    },
    sendData: (streamId, data, endStream = false) => write(dataFrame(streamId, data, endStream)),
    sendTrailers: (streamId, fields) =>
      write(headersFrame(streamId, encodeHeaderBlock(fields), { endStream: true, endHeaders: true })),
    sendRst: (streamId, code) => write(rstStreamFrame(streamId, code)),
    sendWindowUpdate: (streamId, inc) => write(windowUpdateFrame(streamId, inc)),
    sendGoaway: (lastStreamId, code, debug) => write(goawayFrame(lastStreamId, code, debug)),
    sendPing: (opaque, ack) => write(pingFrame(opaque, ack)),
    sendSettings: (entries, ack) => write(settingsFrame(entries, ack)),
    sendRaw: (bytes) => write(bytes),
    close: () => writer.close(),
    /** Resolve on the next frame the server reads that matches `pred(frame)`. */
    waitForFrame: (pred) =>
      new Promise((resolve) => {
        onFrame = (f) => {
          if (pred(f)) {
            onFrame = null;
            resolve(f);
          }
        };
      }),
    onFrameHook: (fn) => {
      onFrame = fn;
    },
  };

  let markReady;
  api.ready = new Promise((r) => {
    markReady = r;
  });

  const done = (async () => {
    const preface = await reader.readExactly(PREFACE_LEN, 'client preface');
    events.push({ kind: 'preface', bytes: preface.slice() });
    // Server opening SETTINGS. A test that sends any unsolicited frame must await `ready` first, or
    // that frame could reach the client before this SETTINGS and be (correctly) rejected as an
    // illegal first frame.
    await write(settingsFrame(opts.settings ?? []));
    markReady();

    for (;;) {
      const frame = await readFrame(reader, 1 << 20).catch(() => null);
      if (frame === null) break;
      events.push({ kind: 'frame', type: frame.type, flags: frame.flags, streamId: frame.streamId });
      if (frame.type === FRAME.SETTINGS) {
        if (!(frame.flags & FLAG.ACK)) {
          api.clientSettings = parseSettings(frame.payload);
          await write(settingsFrame([], true)); // ACK the client's SETTINGS
        }
      } else if (frame.type === FRAME.HEADERS) {
        const fragment = headersBlockFragment(frame.payload, frame.flags);
        // Assume END_HEADERS for the common single-frame request; tests that fragment set it too.
        let block = fragment;
        if (!(frame.flags & FLAG.END_HEADERS)) {
          const parts = [fragment.slice()];
          for (;;) {
            const cont = await readFrame(reader, 1 << 20);
            parts.push(cont.payload.slice());
            if (cont.flags & FLAG.END_HEADERS) break;
          }
          block = concat(parts);
        }
        const pairs = decoder.decode(block);
        const headers = new Map();
        for (const [k, v] of pairs) headers.set(k, headers.has(k) ? `${headers.get(k)}, ${v}` : v);
        requests.set(frame.streamId, {
          headers,
          pairs,
          body: [],
          ended: Boolean(frame.flags & FLAG.END_STREAM),
        });
      } else if (frame.type === FRAME.DATA) {
        const req = requests.get(frame.streamId);
        const data = frame.flags & FLAG.PADDED ? stripPadding(frame.payload).data : frame.payload;
        if (req) {
          req.body.push(data.slice());
          if (frame.flags & FLAG.END_STREAM) req.ended = true;
        }
      } else if (frame.type === FRAME.WINDOW_UPDATE) {
        events.push({ kind: 'window_update', streamId: frame.streamId, inc: parseWindowUpdate(frame.payload) });
      }
      if (onFrame) onFrame(frame);
    }
  })();
  done.catch(() => {});
  api.done = done;
  return api;
}

/** Collect a body stream to a string. */
export async function readBodyText(body) {
  const reader = body.getReader();
  const parts = [];
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  return new TextDecoder().decode(concat(parts));
}

export { serializeFrame, FRAME, FLAG };
