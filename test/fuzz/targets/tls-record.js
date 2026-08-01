// The TLS record layer: the outermost framing, and the only parser that sees bytes before any
// handshake state exists at all. A record header is five bytes declaring a length the rest of the
// connection depends on, and the layer must refuse an unknown type, a length past the cap, and a
// fragment that spans records, rather than guessing.

import { RecordLayer } from '../../../src/tls/record.js';
import { readableFrom, recordingWritable } from '../../_harness.js';
import { RFC8448_1RTT } from '../../tls/_vectors.js';

const u16 = (n) => [n >> 8, n & 0xff];
const rec = (type, body) => [type, 0x03, 0x03, ...u16(body.length), ...body];
// warning(1) / close_notify(0). Every seed ends with one, because a stream that just stops IS a
// truncation and the layer is right to refuse it — the seeds have to be inputs it accepts, or the
// corpus check is testing the corpus rather than the parser.
const CLOSE_NOTIFY = rec(21, [1, 0]);
const record = (type, body) => Uint8Array.from([...rec(type, body), ...CLOSE_NOTIFY]);

/** A real handshake message: ServerHello, header included. */
const SH = RFC8448_1RTT.serverHello;

export default {
  name: 'tls.RecordLayer',
  // Only the record types that are legal while the handshake is in flight, because that is the
  // phase being driven. Mutations still produce illegal types — including application_data, which
  // the layer refuses during the handshake — and those are rejections, which is the point.
  corpus: [
    // The RFC 8448 ServerHello, complete with its handshake header — a real message, so the layer
    // gets past framing into reassembly instead of refusing filler at the first length field.
    record(22, SH),
    record(20, Uint8Array.from([1])),
    // The SAME message split across two records. Reassembly across a record boundary is where a
    // length that disagrees with the framing does its damage.
    Uint8Array.from([
      ...rec(22, SH.subarray(0, 20)), ...rec(22, SH.subarray(20)), ...CLOSE_NOTIFY,
    ]),
    // change_cipher_spec interleaved, the middlebox-compatibility case.
    Uint8Array.from([...rec(20, [1]), ...rec(22, SH), ...CLOSE_NOTIFY]),
  ],
  run: async (input) => {
    const rl = new RecordLayer(
      { readable: readableFrom([input]), writable: recordingWritable().stream },
      {},
    );
    // Drain until the layer refuses or the stream ends. Bounded, because the property under test is
    // "refuses or completes", and an unbounded loop over a parser that always yields would hang the
    // suite rather than report anything.
    for (let i = 0; i < 64; i++) {
      const m = await rl.nextHandshakeMessage();
      if (m == null) break;
    }
  },
};
