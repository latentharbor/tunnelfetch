// HTTP/2 frame headers: nine bytes that declare a length the rest of the connection depends on.
// A frame parser that trusts a declared length is how a peer makes a client allocate.

import { ByteReader } from '../../../src/util/bytes.js';
import { readFrame, serializeFrame } from '../../../src/http2/frames.js';
import { readableFrom } from '../../_harness.js';
import { FRAME } from '../../../src/http2/constants.js';

const enc = new TextEncoder();

export default {
  name: 'http2.readFrame',
  corpus: [
    serializeFrame(FRAME.DATA, 0x1, 1, enc.encode('hello there, a payload')),
    serializeFrame(FRAME.SETTINGS, 0, 0, new Uint8Array(12)),
    serializeFrame(FRAME.HEADERS, 0x4, 1, new Uint8Array([0x88, 0x0f, 0x10, 0x03, 0x61, 0x62, 0x63])),
    serializeFrame(FRAME.GOAWAY, 0, 0, new Uint8Array(8)),
    serializeFrame(FRAME.WINDOW_UPDATE, 0, 0, new Uint8Array([0, 0, 0x40, 0])),
  ],
  run: (input) => readFrame(new ByteReader(readableFrom([input]))),
};
