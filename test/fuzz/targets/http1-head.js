// The HTTP/1.1 response head: the first bytes a peer sends, parsed before anything about that peer
// has been established. Status lines, folded headers, and the framing decision that follows are all
// derived from here, and a head that parses two ways is request smuggling.

import { ByteReader } from '../../../src/util/bytes.js';
import { readResponseHead } from '../../../src/http1/response.js';
import { readableFrom } from '../../_harness.js';

const enc = new TextEncoder();
const head = (s) => enc.encode(s);

export default {
  name: 'http1.readResponseHead',
  corpus: [
    head('HTTP/1.1 200 OK\r\ncontent-length: 5\r\ncontent-type: text/plain\r\n\r\n'),
    head('HTTP/1.1 301 Moved\r\nlocation: /x\r\nset-cookie: a=b; Path=/; HttpOnly\r\n\r\n'),
    head('HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n'),
    head('HTTP/1.0 204 No Content\r\nconnection: keep-alive\r\n\r\n'),
  ],
  run: (input) => readResponseHead(new ByteReader(readableFrom([input])), { maxHeaderBytes: 65536 }),
};
