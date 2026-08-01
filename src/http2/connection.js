// The HTTP/2 connection engine (RFC 9113): one TCP+TLS byte duplex, many concurrent streams.
//
// CONNECTION SHARING — the decision the pool header warns about. HTTP/1.1 makes reuse safe by
// EXCLUSIVE CHECKOUT: a connection leaves the pool for one request and returns only when that
// response's body has reached its framed end, so bytes for one response can never be read as
// another's. HTTP/2 multiplexes, so exclusive checkout is the wrong model — the connection is
// never checked out at all. Here the same invariant ("bytes of one response are never delivered
// as another's") is carried by the stream id instead: exactly ONE reader — the frame loop below —
// touches the transport, it demultiplexes each DATA frame to the stream its id names, and every
// stream has its own body queue. A response's bytes reach a caller only through the stream object
// that owns that id, which is a different object per request. There is no shared byte cursor to
// desynchronise, so there is nothing to check out. The connection is held in a per-Client registry
// (see client.js) keyed exactly like the h1 pool, and a single connection serves every concurrent
// request to that key until it goes away.
//
// FLOW CONTROL is the other load-bearing part, and it is wired to CONSUMPTION, not arrival. When a
// DATA frame lands, its bytes are debited from our receive window immediately (the peer has spent
// that credit); the window is only reopened — a WINDOW_UPDATE is only sent — as the CONSUMER drains
// the body. Reopening on arrival instead would defeat backpressure (a fast server + slow reader
// would buffer without bound); never reopening at all would stall every body larger than the
// initial window forever, which looks exactly like a hung server. Both failure modes are real and
// each is guarded by a test.

import { Http2Error, codes } from '../errors.js';
import { ByteReader, ByteWriter, concat } from '../util/bytes.js';
import {
  CLIENT_CONNECTION_WINDOW,
  CLIENT_CONNECTION_WINDOW_INCREMENT,
  CLIENT_INITIAL_WINDOW_SIZE,
  CLIENT_MAX_CONCURRENT_STREAMS,
  CONNECTION_PREFACE,
  DEFAULT_INITIAL_WINDOW,
  DEFAULT_MAX_FRAME_SIZE,
  FLAG,
  FRAME,
  H2_ERROR,
  H2_ERROR_NAME,
  MAX_ALLOWED_FRAME_SIZE,
  MAX_WINDOW,
  PSEUDO_HEADER_ORDER,
  SETTINGS,
} from './constants.js';
import {
  continuationFrame,
  dataFrame,
  goawayFrame,
  headersBlockFragment,
  headersFrame,
  parseGoaway,
  parseRstStream,
  parseSettings,
  parseWindowUpdate,
  pingFrame,
  readFrame,
  rstStreamFrame,
  serializeFrame,
  settingsFrame,
  stripPadding,
  windowUpdateFrame,
} from './frames.js';
import { DEFAULT_HEADER_TABLE_SIZE, HpackDecoder, encodeHeaderBlock } from './hpack.js';

/** A promise with its settle functions exposed, rejection pre-observed so an unconsumed
 *  trailers/completed promise can never crash the isolate. */
function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  promise.catch(() => {});
  return { promise, resolve, reject, settled: false };
}

/** RFC 9113 s8.2.2 / s8.2.3: connection-specific header fields a client must not send in h2, and
 *  a server must not send either. Their presence in a response is malformed; we drop them on the
 *  request side and reject them on the response side. `te` is allowed only when its value is
 *  exactly "trailers", handled separately. */
const FORBIDDEN_H2_HEADERS = new Set([
  'connection',
  'proxy-connection',
  'keep-alive',
  'transfer-encoding',
  'upgrade',
]);

/**
 * @typedef {ReadableStream<Uint8Array> & { completed: Promise<boolean>,
 *   trailers: Promise<Headers | null> }} BodyStream
 */

/**
 * @typedef {object} Http2ResponseHead
 * @property {number} status
 * @property {string} statusText always '' — HTTP/2 has no reason phrase
 * @property {Headers} headers
 * @property {string[]} setCookie one entry per set-cookie field, kept separate like the h1 path
 * @property {'2'} httpVersion
 * @property {BodyStream} body
 */

/**
 * Raised by request() when the connection cannot take the stream but the request PROVABLY was not
 * processed (going away, or refused). It mirrors h1's serverNeverSawIt: only a request the server
 * demonstrably never saw may be re-sent, so client.js can safely open a fresh connection and retry.
 */
export class Http2Retryable extends Http2Error {}

/**
 * @typedef {object} Http2ConnectionOptions
 * @property {import('../transport.js').ConnectionInfo} [info] provenance attached to responses
 * @property {number} [initialWindowSize] our SETTINGS_INITIAL_WINDOW_SIZE (receive window per
 *   stream). Defaults to curl's 10 MiB; tests lower it to exercise flow control.
 * @property {number} [connectionWindow] the connection receive window we open with a WINDOW_UPDATE
 *   right after SETTINGS. Defaults to curl's 1000 MiB.
 * @property {number} [maxConcurrentStreams] our advertised SETTINGS_MAX_CONCURRENT_STREAMS.
 * @property {number} [maxHeaderTableSize] our advertised SETTINGS_HEADER_TABLE_SIZE.
 * @property {number} [maxHeaderListSize] self-protection cap on a decoded response header list.
 * @property {(err: Error | null) => void} [onClose] called once when the connection dies, so a
 *   registry can drop it.
 */

export class Http2Connection {
  /**
   * @param {import('../tls/connect.js').ByteDuplex | { readable: ReadableStream<Uint8Array>,
   *   writable: WritableStream<Uint8Array> }} duplex plaintext transport (a TLS session's
   *   plaintextDuplex, or a raw socket for cleartext h2 in tests)
   * @param {Http2ConnectionOptions} [opts]
   */
  constructor(duplex, opts = {}) {
    this._reader = new ByteReader(duplex.readable);
    this._writer = new ByteWriter(duplex.writable);
    this._closeTransport = () => duplex.close?.();
    this.info = opts.info ?? null;

    // Our advertised settings. The defaults ARE the fingerprint (see constants.js); overrides
    // exist for tests, and shifting them shifts what the server sees, so production leaves them.
    this._ourInitialWindow = opts.initialWindowSize ?? CLIENT_INITIAL_WINDOW_SIZE;
    this._ourConnWindow = opts.connectionWindow ?? CLIENT_CONNECTION_WINDOW;
    this._ourMaxConcurrent = opts.maxConcurrentStreams ?? CLIENT_MAX_CONCURRENT_STREAMS;
    this._ourHeaderTableSize = opts.maxHeaderTableSize ?? DEFAULT_HEADER_TABLE_SIZE;

    // Peer settings, at their protocol defaults until the server's SETTINGS arrives.
    this._peerInitialWindow = DEFAULT_INITIAL_WINDOW;
    this._peerMaxFrameSize = DEFAULT_MAX_FRAME_SIZE;
    this._peerMaxConcurrent = Infinity; // unknown until told; unlimited by default (RFC 9113 s6.5.2)
    this._peerHeaderTableSize = DEFAULT_HEADER_TABLE_SIZE;

    // Receive-side flow control (what the peer may send us). Connection window jumps to
    // `_ourConnWindow` the moment our opening WINDOW_UPDATE is written.
    this._connRecvWindow = DEFAULT_INITIAL_WINDOW;
    this._connConsumed = 0; // bytes consumed since the last connection WINDOW_UPDATE we sent
    // Send-side flow control (what WE may send the peer), connection level.
    this._connSendWindow = DEFAULT_INITIAL_WINDOW;
    /** @type {Array<() => void>} wakers for senders blocked on the connection window */
    this._connSendWaiters = [];

    this._decoder = new HpackDecoder({
      maxTableSize: this._ourHeaderTableSize,
      maxHeaderListSize: opts.maxHeaderListSize,
    });

    /** @type {Map<number, any>} live streams by id */
    this._streams = new Map();
    this._nextStreamId = 1; // client-initiated streams are odd (RFC 9113 s5.1.1)
    this._lastPeerStreamId = 0;

    // Header-block continuation state: while assembling a HEADERS+CONTINUATION run, no other frame
    // may interleave (RFC 9113 s6.10). Non-null means "the next frame must be CONTINUATION on this
    // stream id".
    this._continuation = null; // { streamId, fragments: Uint8Array[], endStream, kind }
    this._expectFirstSettings = true;

    this._fatal = null; // set once; rejects every stream and every future request
    this._goaway = null; // { lastStreamId, errorCode } received from the peer
    this._closed = false;
    this._onClose = opts.onClose ?? null;
    this._writeChain = Promise.resolve();

    // Kick off the preface flight and the read loop. Neither is awaited here: the constructor
    // returns a usable connection and request() serialises behind the preface via the write chain.
    this._sendPreface();
    this._readLoop().catch((err) => this._die(err));
  }

  /** Whether a new request may be dispatched onto this connection right now. */
  canDispatch() {
    return (
      !this._fatal &&
      !this._closed &&
      !this._goaway &&
      this._streams.size < this._peerMaxConcurrent &&
      this._nextStreamId <= 0x7fffffff
    );
  }

  get activeStreams() {
    return this._streams.size;
  }

  // ------------------------------------------------------------------ preface / writing

  _sendPreface() {
    // Exactly curl's flight and order: the 24-byte magic, then SETTINGS (ids 3,4,2), then a
    // connection-level WINDOW_UPDATE that raises the receive window to 1000 MiB. See constants.js.
    const settings = settingsFrame([
      [SETTINGS.MAX_CONCURRENT_STREAMS, this._ourMaxConcurrent],
      [SETTINGS.INITIAL_WINDOW_SIZE, this._ourInitialWindow],
      [SETTINGS.ENABLE_PUSH, 0],
    ]);
    const inc = this._ourConnWindow - DEFAULT_INITIAL_WINDOW;
    const flight =
      inc > 0
        ? concat([CONNECTION_PREFACE, settings, windowUpdateFrame(0, inc)])
        : concat([CONNECTION_PREFACE, settings]);
    this._connRecvWindow = this._ourConnWindow;
    this._write(flight);
  }

  /** Serialise a wire write behind every previous one, so a header block is never split by another
   *  frame and the preface always leads. Mirrors the record layer's write discipline. */
  _write(bytes) {
    const task = this._writeChain.then(() => this._writer.write(bytes));
    this._writeChain = task.then(
      () => undefined,
      () => undefined,
    );
    return task;
  }

  // ------------------------------------------------------------------ request

  /**
   * Open a stream and send a request. Resolves once the response header block (the first non-1xx
   * HEADERS) has arrived; the body streams after.
   *
   * @param {object} req
   * @param {string} req.method
   * @param {string} req.scheme
   * @param {string} req.authority
   * @param {string} req.path
   * @param {Array<[string, string]>} req.headers already lowercased, connection-specific ones removed
   * @param {Uint8Array | null} [req.body] buffered whole by the caller, so send flow control is simple
   * @param {AbortSignal} [req.signal] aborting it RST_STREAMs the stream and rejects its promises;
   *   this is how a per-request deadline tears down exactly one stream without touching the others
   * @returns {Promise<Http2ResponseHead>}
   */
  request({ method, scheme, authority, path, headers, body, signal }) {
    if (this._fatal) throw this._fatal;
    if (this._closed) throw new Http2Error(codes.HTTP2_PROTOCOL, 'connection is closed');
    if (this._goaway) {
      throw new Http2Retryable(
        codes.HTTP2_GOAWAY,
        'connection is going away; this stream was never opened',
        { lastStreamId: this._goaway.lastStreamId },
      );
    }
    if (this._streams.size >= this._peerMaxConcurrent) {
      throw new Http2Retryable(
        codes.HTTP2_STREAM_STATE,
        `at the peer's SETTINGS_MAX_CONCURRENT_STREAMS (${this._peerMaxConcurrent})`,
        { limit: this._peerMaxConcurrent },
      );
    }
    const id = this._nextStreamId;
    this._nextStreamId += 2;

    const stream = this._createStream(id);
    if (signal) {
      if (signal.aborted) {
        this._resetStream(stream, H2_ERROR.CANCEL, signal.reason ?? new Http2Error(codes.HTTP2_PROTOCOL, 'aborted'));
        return stream.head.promise;
      }
      const onAbort = () => {
        if (!stream.closed) {
          this._resetStream(stream, H2_ERROR.CANCEL, signal.reason ?? new Http2Error(codes.HTTP2_PROTOCOL, 'aborted'));
        }
      };
      signal.addEventListener('abort', onAbort, { once: true });
    }
    const hasBody = body != null && body.byteLength > 0;

    const fields = buildRequestFields({ method, scheme, authority, path, headers });
    const block = encodeHeaderBlock(fields);
    this._sendHeaderBlock(id, block, !hasBody);
    stream.localEnded = !hasBody;

    if (hasBody) {
      // Send the body respecting flow control. Not awaited: a large body may block on WINDOW_UPDATE,
      // and blocking request() would stop the caller from ever reading the response head that
      // unblocks it. Errors surface on the stream, which is what the caller is awaiting.
      this._sendBody(id, body, stream).catch((err) => this._failStream(stream, err));
    }
    return stream.head.promise;
  }

  _createStream(id) {
    const stream = {
      id,
      // response head
      head: deferred(),
      responseReceived: false,
      // body plumbing: an in-memory queue drained by the body stream's pull, so WINDOW_UPDATE is
      // tied to the consumer, not to arrival.
      /** @type {Uint8Array[]} */
      recvQueue: [],
      recvEnded: false,
      /** @type {Error | null} */
      bodyError: null,
      /** @type {(() => void) | null} */
      pullWaiter: null,
      completed: deferred(),
      trailers: deferred(),
      /** @type {Headers | null} */
      trailerFields: null,
      // flow control
      recvWindow: this._ourInitialWindow,
      recvConsumed: 0,
      sendWindow: this._peerInitialWindow,
      /** @type {Array<() => void>} */
      sendWaiters: [],
      localEnded: false,
      cancelled: false,
      closed: false,
      rstSent: false,
    };
    stream.body = this._makeBodyStream(stream);
    this._streams.set(id, stream);
    return stream;
  }

  /** Send a header block as HEADERS plus CONTINUATION frames if it overflows one frame. The whole
   *  run is one write, so no other frame can interleave it (RFC 9113 s6.10). */
  _sendHeaderBlock(streamId, block, endStream) {
    const max = this._peerMaxFrameSize;
    if (block.length <= max) {
      this._write(headersFrame(streamId, block, { endStream, endHeaders: true }));
      return;
    }
    const frames = [];
    let o = 0;
    const first = block.subarray(0, max);
    frames.push(headersFrame(streamId, first, { endStream, endHeaders: false }));
    o = max;
    while (o < block.length) {
      const chunk = block.subarray(o, Math.min(o + max, block.length));
      o += chunk.length;
      frames.push(continuationFrame(streamId, chunk, o >= block.length));
    }
    this._write(concat(frames));
  }

  /** Send a request body as DATA frames, respecting stream and connection send windows. */
  async _sendBody(streamId, body, stream) {
    let offset = 0;
    while (offset < body.byteLength) {
      if (stream.closed || stream.cancelled) return; // reset or cancelled underneath us
      const room = Math.min(stream.sendWindow, this._connSendWindow);
      if (room <= 0) {
        await this._awaitSendWindow(stream);
        continue;
      }
      const n = Math.min(room, this._peerMaxFrameSize, body.byteLength - offset);
      const slice = body.subarray(offset, offset + n);
      offset += n;
      stream.sendWindow -= n;
      this._connSendWindow -= n;
      const end = offset >= body.byteLength;
      await this._write(dataFrame(streamId, slice, end));
      if (end) stream.localEnded = true;
    }
  }

  /** Block until either the stream or the connection send window grows (a WINDOW_UPDATE arrives). */
  _awaitSendWindow(stream) {
    if (this._fatal) return Promise.reject(this._fatal);
    return new Promise((resolve) => {
      stream.sendWaiters.push(resolve);
      this._connSendWaiters.push(resolve);
    });
  }

  _wakeSendWaiters(stream) {
    const wake = (list) => {
      const waiters = list.splice(0);
      for (const w of waiters) w();
    };
    if (stream) wake(stream.sendWaiters);
    wake(this._connSendWaiters);
  }

  // ------------------------------------------------------------------ body stream / receive FC

  _makeBodyStream(stream) {
    const self = this;
    const rs = new ReadableStream(
      {
        // highWaterMark 0: pull only when a consumer actually reads, so delivering a chunk here IS
        // the moment of consumption — which is exactly when the flow-control window may be reopened.
        async pull(controller) {
          for (;;) {
            if (stream.recvQueue.length > 0) {
              const chunk = stream.recvQueue.shift();
              controller.enqueue(chunk);
              self._consumeStream(stream, chunk.byteLength);
              return;
            }
            if (stream.bodyError) {
              controller.error(stream.bodyError);
              self._settleReject(stream.completed, stream.bodyError);
              return;
            }
            if (stream.recvEnded) {
              controller.close();
              self._settleResolve(stream.completed, true);
              self._settleResolve(stream.trailers, stream.trailerFields);
              return;
            }
            await new Promise((resolve) => {
              stream.pullWaiter = resolve;
            });
          }
        },
        cancel() {
          // The caller abandoned the body at an unknown position. Tell the peer to stop (RST_STREAM
          // CANCEL) and settle the completion contract as "not finished" (resolve false, not reject).
          stream.cancelled = true;
          self._settleResolve(stream.completed, false);
          self._settleResolve(stream.trailers, null);
          self._sendRst(stream, H2_ERROR.CANCEL);
          self._removeStream(stream);
          return undefined;
        },
      },
      { highWaterMark: 0 },
    );
    return Object.assign(rs, { completed: stream.completed.promise, trailers: stream.trailers.promise });
  }

  _wakePull(stream) {
    if (stream.pullWaiter) {
      const w = stream.pullWaiter;
      stream.pullWaiter = null;
      w();
    }
  }

  /** Called as the CONSUMER drains `n` bytes: reopen the stream and connection receive windows,
   *  batched so a byte-at-a-time consumer does not produce a WINDOW_UPDATE storm. */
  _consumeStream(stream, n) {
    this._replenish(stream, n);
    this._replenishConn(n);
  }

  _replenish(stream, n) {
    stream.recvConsumed += n;
    stream.recvWindow += n;
    const threshold = Math.max(1, this._ourInitialWindow >> 1);
    if (stream.recvConsumed >= threshold && !stream.closed) {
      const inc = stream.recvConsumed;
      stream.recvConsumed = 0;
      this._write(windowUpdateFrame(stream.id, inc));
    }
  }

  _replenishConn(n) {
    this._connConsumed += n;
    this._connRecvWindow += n;
    const threshold = Math.max(1, this._ourConnWindow >> 1);
    if (this._connConsumed >= threshold) {
      const inc = this._connConsumed;
      this._connConsumed = 0;
      this._write(windowUpdateFrame(0, inc));
    }
  }

  // ------------------------------------------------------------------ read loop

  async _readLoop() {
    for (;;) {
      const frame = await readFrame(this._reader, DEFAULT_MAX_FRAME_SIZE);
      if (frame === null) {
        // Clean transport EOF. Any stream still open ended without END_STREAM — a truncation.
        this._die(
          this._streams.size === 0
            ? null
            : new Http2Error(codes.HTTP2_PROTOCOL, 'connection closed with streams still open'),
        );
        return;
      }
      if (this._fatal) return;
      this._dispatchFrame(frame);
    }
  }

  _dispatchFrame(frame) {
    const { type, flags, streamId, payload } = frame;

    // A header block in progress may be interrupted by nothing but its own CONTINUATION.
    if (this._continuation) {
      if (type !== FRAME.CONTINUATION || streamId !== this._continuation.streamId) {
        this._die(
          new Http2Error(
            codes.HTTP2_PROTOCOL,
            `expected CONTINUATION on stream ${this._continuation.streamId}, got frame type ` +
              `${type} on stream ${streamId}`,
            { expectedStream: this._continuation.streamId, gotType: type, gotStream: streamId },
          ),
        );
        return;
      }
      this._onContinuation(flags, payload);
      return;
    }

    // The very first frame from the server must be a SETTINGS frame (RFC 9113 s3.4).
    if (this._expectFirstSettings) {
      if (type !== FRAME.SETTINGS) {
        this._die(
          new Http2Error(
            codes.HTTP2_PROTOCOL,
            `first frame from the server was type ${type}, expected SETTINGS`,
            { type },
          ),
        );
        return;
      }
      this._expectFirstSettings = false;
    }

    switch (type) {
      case FRAME.SETTINGS:
        this._onSettings(flags, streamId, payload);
        break;
      case FRAME.HEADERS:
        this._onHeaders(flags, streamId, payload);
        break;
      case FRAME.DATA:
        this._onData(flags, streamId, payload);
        break;
      case FRAME.WINDOW_UPDATE:
        this._onWindowUpdate(streamId, payload);
        break;
      case FRAME.RST_STREAM:
        this._onRstStream(streamId, payload);
        break;
      case FRAME.PING:
        this._onPing(flags, streamId, payload);
        break;
      case FRAME.GOAWAY:
        this._onGoaway(payload);
        break;
      case FRAME.PUSH_PROMISE:
        // We advertised SETTINGS_ENABLE_PUSH = 0, so a PUSH_PROMISE is a protocol violation, not a
        // resource to accept (RFC 9113 s8.4). Fail the whole connection closed.
        this._die(
          new Http2Error(
            codes.HTTP2_PUSH_UNEXPECTED,
            'server sent PUSH_PROMISE despite SETTINGS_ENABLE_PUSH = 0',
          ),
        );
        break;
      case FRAME.PRIORITY:
        // The priority scheme is deprecated (RFC 9113 s5.3.2). A well-formed PRIORITY frame is
        // accepted and ignored; a mis-sized one is still a stream-level FRAME_SIZE_ERROR.
        if (payload.length !== 5) {
          this._die(
            new Http2Error(codes.HTTP2_FRAME_SIZE, `PRIORITY payload is ${payload.length} bytes, must be 5`),
          );
        }
        break;
      case FRAME.CONTINUATION:
        // A CONTINUATION with no HEADERS in progress has nothing to continue.
        this._die(
          new Http2Error(codes.HTTP2_PROTOCOL, 'CONTINUATION frame with no open header block'),
        );
        break;
      default:
        // Unknown frame types MUST be ignored (RFC 9113 s5.5) — this is deliberate and NOT a
        // relaxation of the fail-closed rule: an unknown frame is fully length-delimited, so
        // skipping it is unambiguous, and real servers (ALTSVC, ORIGIN, GREASE) send extension
        // frames that a client refusing them could never reach. The one place they are refused is
        // mid-header-block above, where s6.10 makes any interleaved frame a connection error.
        break;
    }
  }

  _onSettings(flags, streamId, payload) {
    if (streamId !== 0) {
      this._die(new Http2Error(codes.HTTP2_PROTOCOL, 'SETTINGS on a non-zero stream'));
      return;
    }
    if (flags & FLAG.ACK) {
      if (payload.length !== 0) {
        this._die(new Http2Error(codes.HTTP2_FRAME_SIZE, 'SETTINGS ACK must have an empty payload'));
      }
      return; // our SETTINGS were acknowledged; nothing to apply
    }
    let entries;
    try {
      entries = parseSettings(payload);
    } catch (err) {
      this._die(err);
      return;
    }
    for (const [id, value] of entries) {
      switch (id) {
        case SETTINGS.INITIAL_WINDOW_SIZE: {
          if (value > MAX_WINDOW) {
            this._die(
              new Http2Error(
                codes.HTTP2_FLOW_CONTROL,
                `SETTINGS_INITIAL_WINDOW_SIZE ${value} exceeds ${MAX_WINDOW}`,
                { value },
              ),
            );
            return;
          }
          // A change retroactively adjusts every open stream's SEND window by the delta
          // (RFC 9113 s6.9.2).
          const delta = value - this._peerInitialWindow;
          this._peerInitialWindow = value;
          for (const stream of this._streams.values()) {
            stream.sendWindow += delta;
            if (stream.sendWindow > 0) this._wakeSendWaiters(stream);
          }
          break;
        }
        case SETTINGS.MAX_FRAME_SIZE:
          if (value < DEFAULT_MAX_FRAME_SIZE || value > MAX_ALLOWED_FRAME_SIZE) {
            this._die(
              new Http2Error(codes.HTTP2_PROTOCOL, `illegal SETTINGS_MAX_FRAME_SIZE ${value}`, { value }),
            );
            return;
          }
          this._peerMaxFrameSize = value;
          break;
        case SETTINGS.MAX_CONCURRENT_STREAMS:
          this._peerMaxConcurrent = value;
          break;
        case SETTINGS.HEADER_TABLE_SIZE:
          this._peerHeaderTableSize = value;
          break;
        case SETTINGS.ENABLE_PUSH:
          if (value !== 0 && value !== 1) {
            this._die(new Http2Error(codes.HTTP2_PROTOCOL, `illegal SETTINGS_ENABLE_PUSH ${value}`));
            return;
          }
          break;
        default:
          break; // unknown settings are ignored (RFC 9113 s6.5.2)
      }
    }
    // Acknowledge, as required (RFC 9113 s6.5.3).
    this._write(settingsFrame([], true));
  }

  _onHeaders(flags, streamId, payload) {
    if (streamId === 0 || (streamId & 1) === 0) {
      // A response arrives on the odd, client-initiated stream we opened; 0 and even ids are wrong.
      this._die(new Http2Error(codes.HTTP2_PROTOCOL, `HEADERS on invalid stream ${streamId}`));
      return;
    }
    let fragment;
    try {
      fragment = headersBlockFragment(payload, flags);
    } catch (err) {
      this._die(err);
      return;
    }
    const endStream = (flags & FLAG.END_STREAM) !== 0;
    if (flags & FLAG.END_HEADERS) {
      this._completeHeaderBlock(streamId, fragment, endStream);
    } else {
      this._continuation = { streamId, fragments: [fragment.slice()], endStream };
    }
  }

  _onContinuation(flags, payload) {
    this._continuation.fragments.push(payload.slice());
    if (flags & FLAG.END_HEADERS) {
      const { streamId, fragments, endStream } = this._continuation;
      this._continuation = null;
      this._completeHeaderBlock(streamId, concat(fragments), endStream);
    }
  }

  /** A full header block has been assembled: HPACK-decode it (connection-fatal on failure, since
   *  HPACK state is shared) and route it to the stream as a response head or as trailers. */
  _completeHeaderBlock(streamId, block, endStream) {
    let pairs;
    try {
      pairs = this._decoder.decode(block);
    } catch (err) {
      // An HPACK error corrupts the shared decoder for every stream, so it is a connection error
      // of type COMPRESSION_ERROR (RFC 9113 s4.3), never a stream-local one.
      this._die(err);
      return;
    }
    const stream = this._streams.get(streamId);
    if (!stream) {
      // HEADERS for a stream we have closed. It cost us HPACK work (already done, so the table is
      // consistent) but we owe it nothing else; ignore it rather than tear the connection down.
      return;
    }
    if (!stream.responseReceived) {
      this._deliverResponseHead(stream, pairs, endStream);
    } else {
      this._deliverTrailers(stream, pairs, endStream);
    }
  }

  _deliverResponseHead(stream, pairs, endStream) {
    let head;
    try {
      head = parseResponseHeaders(pairs);
    } catch (err) {
      // A malformed response is a STREAM error: reset this stream, leave the connection and its
      // other streams untouched (RFC 9113 s8.1.1).
      this._resetStream(stream, H2_ERROR.PROTOCOL_ERROR, err);
      return;
    }
    if (head.status >= 100 && head.status <= 199) {
      // Interim (1xx) response. It never carries a body and is not the real response; wait for the
      // final HEADERS. An interim response with END_STREAM is malformed.
      if (endStream) {
        this._resetStream(
          stream,
          H2_ERROR.PROTOCOL_ERROR,
          new Http2Error(codes.HTTP2_HEADER, `interim ${head.status} response ended the stream`),
        );
      }
      return;
    }
    stream.responseReceived = true;
    if (endStream) {
      // No body and no trailers: the completion contract is satisfiable now, exactly like the h1
      // "complete at creation" case, so a caller that never reads the (empty) body still lets the
      // deadline dispose.
      stream.recvEnded = true;
      this._settleResolve(stream.completed, true);
      this._settleResolve(stream.trailers, null);
      this._wakePull(stream);
    }
    this._settleResolve(stream.head, {
      status: head.status,
      statusText: '',
      headers: head.headers,
      setCookie: head.setCookie,
      httpVersion: '2',
      body: stream.body,
    });
    if (endStream) this._maybeCloseStream(stream);
  }

  _deliverTrailers(stream, pairs, endStream) {
    if (!endStream) {
      // A second header block that is not the end can only be trailers, and trailers END the
      // stream by definition (RFC 9113 s8.1).
      this._resetStream(
        stream,
        H2_ERROR.PROTOCOL_ERROR,
        new Http2Error(codes.HTTP2_TRAILER, 'trailing HEADERS without END_STREAM'),
      );
      return;
    }
    try {
      stream.trailerFields = parseTrailers(pairs);
    } catch (err) {
      this._resetStream(stream, H2_ERROR.PROTOCOL_ERROR, err);
      return;
    }
    stream.recvEnded = true;
    this._wakePull(stream);
    this._maybeCloseStream(stream);
  }

  _onData(flags, streamId, payload) {
    const stream = this._streams.get(streamId);
    // Flow control is accounted at the connection level for EVERY DATA frame, even one for a
    // stream we have already closed — the peer spent connection window to send it, and not
    // crediting it back would slowly starve the connection (RFC 9113 s6.9.1).
    const flowLen = payload.byteLength;
    this._connRecvWindow -= flowLen;
    if (this._connRecvWindow < 0) {
      this._die(
        new Http2Error(codes.HTTP2_FLOW_CONTROL, 'peer overran the connection flow-control window'),
      );
      return;
    }
    if (!stream || stream.closed) {
      // No consumer will ever drain these bytes, so credit the whole frame back now.
      this._replenishConn(flowLen);
      return;
    }
    if (!stream.responseReceived) {
      this._resetStream(
        stream,
        H2_ERROR.PROTOCOL_ERROR,
        new Http2Error(codes.HTTP2_STREAM_STATE, 'DATA before response HEADERS'),
      );
      return;
    }
    let data;
    try {
      data = flags & FLAG.PADDED ? stripPadding(payload).data : payload;
    } catch (err) {
      this._die(err);
      return;
    }
    stream.recvWindow -= flowLen;
    if (stream.recvWindow < 0) {
      this._resetStream(
        stream,
        H2_ERROR.FLOW_CONTROL_ERROR,
        new Http2Error(codes.HTTP2_FLOW_CONTROL, 'peer overran the stream window'),
      );
      return;
    }
    // Padding (and the pad-length byte) is discarded, so it is consumed immediately for
    // flow-control purposes; only the payload's data defers to the consumer.
    const overhead = flowLen - data.byteLength;
    if (overhead > 0) this._replenishConn(overhead);
    // The stream window was debited by flowLen; credit the overhead back on the stream too.
    if (overhead > 0) this._replenish(stream, overhead);
    if (data.byteLength > 0) {
      stream.recvQueue.push(data.slice());
      this._wakePull(stream);
    }
    if (flags & FLAG.END_STREAM) {
      stream.recvEnded = true;
      this._wakePull(stream);
      this._maybeCloseStream(stream);
    }
  }

  _onWindowUpdate(streamId, payload) {
    let inc;
    try {
      inc = parseWindowUpdate(payload);
    } catch (err) {
      this._die(err);
      return;
    }
    if (inc === 0) {
      // A zero increment is a PROTOCOL_ERROR — connection-level when on stream 0, else stream-level.
      if (streamId === 0) {
        this._die(new Http2Error(codes.HTTP2_PROTOCOL, 'connection WINDOW_UPDATE with a zero increment'));
      } else {
        const stream = this._streams.get(streamId);
        if (stream) {
          this._resetStream(
            stream,
            H2_ERROR.PROTOCOL_ERROR,
            new Http2Error(codes.HTTP2_PROTOCOL, 'zero WINDOW_UPDATE increment'),
          );
        }
      }
      return;
    }
    if (streamId === 0) {
      this._connSendWindow += inc;
      if (this._connSendWindow > MAX_WINDOW) {
        this._die(new Http2Error(codes.HTTP2_FLOW_CONTROL, 'connection send window exceeded 2^31-1'));
        return;
      }
      this._wakeSendWaiters(null);
    } else {
      const stream = this._streams.get(streamId);
      if (!stream) return; // WINDOW_UPDATE for a closed stream is harmless and ignored
      stream.sendWindow += inc;
      if (stream.sendWindow > MAX_WINDOW) {
        this._resetStream(
          stream,
          H2_ERROR.FLOW_CONTROL_ERROR,
          new Http2Error(codes.HTTP2_FLOW_CONTROL, 'stream send window exceeded 2^31-1'),
        );
        return;
      }
      this._wakeSendWaiters(stream);
    }
  }

  _onRstStream(streamId, payload) {
    let errorCode;
    try {
      errorCode = parseRstStream(payload);
    } catch (err) {
      this._die(err);
      return;
    }
    if (streamId === 0) {
      this._die(new Http2Error(codes.HTTP2_PROTOCOL, 'RST_STREAM on stream 0'));
      return;
    }
    const stream = this._streams.get(streamId);
    if (!stream) return;
    const name = H2_ERROR_NAME[errorCode] ?? `0x${errorCode.toString(16)}`;
    // REFUSED_STREAM specifically means the server did not process the request (RFC 9113 s8.7), so
    // it is safe to retry on a fresh connection — the same "server never saw it" guarantee the h1
    // path relies on. Everything else is reported as-is.
    const retryable = errorCode === H2_ERROR.REFUSED_STREAM && !stream.responseReceived;
    const err = retryable
      ? new Http2Retryable(codes.HTTP2_STREAM_CLOSED, 'server refused the stream (REFUSED_STREAM)', { errorCode })
      : new Http2Error(codes.HTTP2_STREAM_CLOSED, `server reset the stream: ${name}`, { errorCode });
    this._failStream(stream, err);
  }

  _onPing(flags, streamId, payload) {
    if (streamId !== 0) {
      this._die(new Http2Error(codes.HTTP2_PROTOCOL, 'PING on a non-zero stream'));
      return;
    }
    if (payload.length !== 8) {
      this._die(new Http2Error(codes.HTTP2_FRAME_SIZE, `PING payload is ${payload.length} bytes, must be 8`));
      return;
    }
    if (flags & FLAG.ACK) return; // a reply to a PING we never send; ignore
    this._write(pingFrame(payload.slice(), true)); // echo the opaque data (RFC 9113 s6.7)
  }

  _onGoaway(payload) {
    let g;
    try {
      g = parseGoaway(payload);
    } catch (err) {
      this._die(err);
      return;
    }
    this._goaway = { lastStreamId: g.lastStreamId, errorCode: g.errorCode };
    // Streams the server never committed to (id > lastStreamId) provably were not processed and
    // may be retried elsewhere; streams within the promise keep running until they finish or the
    // transport dies.
    for (const stream of this._streams.values()) {
      if (stream.id > g.lastStreamId && !stream.responseReceived) {
        const name = H2_ERROR_NAME[g.errorCode] ?? `0x${g.errorCode.toString(16)}`;
        this._failStream(
          stream,
          new Http2Retryable(codes.HTTP2_GOAWAY, `stream not processed before GOAWAY (${name})`, {
            errorCode: g.errorCode,
          }),
        );
      }
    }
    if (this._onClose) this._onClose(null); // stop new dispatch; existing streams finish
  }

  // ------------------------------------------------------------------ stream teardown
  //
  // Three composable, idempotent primitives so every teardown path is exact about two independent
  // questions: does the peer need an RST_STREAM (only when WE abandon a stream it still believes
  // is live), and do the caller's promises reject or resolve. Conflating them is how a stream ends
  // up both RST'd in response to the peer's own RST (illegal) and left un-rejected.

  /** Forget a stream: drop it from the table and wake anything blocked on it. */
  _removeStream(stream) {
    if (stream.closed) return;
    stream.closed = true;
    this._streams.delete(stream.id);
    this._wakePull(stream);
    this._wakeSendWaiters(stream);
  }

  /** Reject the caller's promises for a stream. Idempotent via the deferreds' settled flags. */
  _rejectStream(stream, err) {
    if (!stream.bodyError) stream.bodyError = err;
    this._settleReject(stream.head, err);
    this._settleReject(stream.completed, err);
    this._settleReject(stream.trailers, err);
    this._wakePull(stream);
  }

  /** Send RST_STREAM once, telling the peer to stop spending bandwidth on a stream we gave up on. */
  _sendRst(stream, errorCode) {
    if (stream.rstSent) return;
    stream.rstSent = true;
    if (!this._fatal && !this._closed) this._write(rstStreamFrame(stream.id, errorCode));
  }

  /** A stream finished cleanly once both halves ended: our request fully sent, END_STREAM received. */
  _maybeCloseStream(stream) {
    if (stream.recvEnded && stream.localEnded) this._removeStream(stream);
  }

  /** A failure originating with the PEER (its RST_STREAM, its GOAWAY, a connection death): reject
   *  the caller, never RST back — RFC 9113 s5.4.2 forbids answering a reset with a reset. */
  _failStream(stream, err) {
    this._removeStream(stream);
    this._rejectStream(stream, err);
  }

  /** A failure originating with US (malformed response, our timeout, flow-control overrun we caught):
   *  tell the peer with RST_STREAM, then reject the caller. */
  _resetStream(stream, errorCode, err) {
    this._sendRst(stream, errorCode);
    this._removeStream(stream);
    if (err) this._rejectStream(stream, err);
  }

  // ------------------------------------------------------------------ connection teardown

  _die(err) {
    if (this._fatal) return;
    this._fatal = err ?? new Http2Error(codes.HTTP2_PROTOCOL, 'connection closed');
    // A GOAWAY on the way out is a courtesy so the peer knows the last stream we handled; failures
    // are ignored because the transport may already be unusable.
    if (!this._closed) {
      this._closed = true;
      this._write(goawayFrame(this._lastPeerStreamId, err ? H2_ERROR.PROTOCOL_ERROR : H2_ERROR.NO_ERROR)).catch(
        () => {},
      );
    }
    for (const stream of [...this._streams.values()]) {
      this._failStream(stream, this._fatal);
    }
    void this._writer.close?.();
    try {
      void this._reader.cancel?.(this._fatal);
    } catch {
      /* already gone */
    }
    void Promise.resolve(this._closeTransport()).catch(() => {});
    if (this._onClose) {
      const cb = this._onClose;
      this._onClose = null;
      cb(err ?? null);
    }
  }

  /**
   * Graceful shutdown: GOAWAY(NO_ERROR), then close the transport. Any live stream is failed.
   *
   * The GOAWAY and the writer close are BEST-EFFORT and are not awaited: a peer that has stopped
   * reading applies backpressure that never clears, and awaiting a courtesy frame into a full
   * buffer would hang close() forever — the exact trap the record layer avoids with its grace
   * window. Only the transport close is awaited, because that is what actually releases the socket.
   */
  async close() {
    if (this._closed) return;
    this._closed = true;
    this._write(goawayFrame(this._lastPeerStreamId, H2_ERROR.NO_ERROR)).catch(() => {});
    const err = new Http2Error(codes.HTTP2_PROTOCOL, 'connection closed by client');
    if (!this._fatal) this._fatal = err;
    for (const stream of [...this._streams.values()]) this._failStream(stream, err);
    void this._writer.close?.().catch?.(() => {});
    try {
      void this._reader.cancel?.(err);
    } catch {
      /* already gone */
    }
    await Promise.resolve(this._closeTransport()).catch(() => {});
    if (this._onClose) {
      const cb = this._onClose;
      this._onClose = null;
      cb(null);
    }
  }

  // ------------------------------------------------------------------ settle helpers

  _settleResolve(d, value) {
    if (d.settled) return;
    d.settled = true;
    d.resolve(value);
  }

  _settleReject(d, err) {
    if (d.settled) return;
    d.settled = true;
    d.reject(err);
  }
}

// ---------------------------------------------------------------------- header building / parsing

/**
 * Build the ordered HPACK field list for a request, pseudo-headers first in curl's order
 * (:method, :scheme, :authority, :path). :path is emitted "without indexing" and the rest
 * "incremental", matching the captured curl encoding.
 *
 * @param {{ method: string, scheme: string, authority: string, path: string,
 *   headers: Array<[string, string]> }} req
 * @returns {import('./hpack.js').HpackField[]}
 */
export function buildRequestFields({ method, scheme, authority, path, headers }) {
  const pseudo = { ':method': method, ':scheme': scheme, ':authority': authority, ':path': path };
  const fields = [];
  for (const name of PSEUDO_HEADER_ORDER) {
    fields.push({ name, value: pseudo[name], indexing: name === ':path' ? 'without' : 'incremental' });
  }
  for (const [name, value] of headers) {
    fields.push({ name, value, indexing: 'incremental' });
  }
  return fields;
}

/** Validate and split a decoded RESPONSE header list into status + regular headers + set-cookie. */
function parseResponseHeaders(pairs) {
  let status = null;
  let sawRegular = false;
  const headers = new Headers();
  const setCookie = [];
  for (const [name, value] of pairs) {
    if (name.length === 0) {
      throw new Http2Error(codes.HTTP2_HEADER, 'empty header field name');
    }
    if (name[0] === ':') {
      if (sawRegular) {
        throw new Http2Error(codes.HTTP2_HEADER, `pseudo-header ${name} appeared after a regular header`);
      }
      if (name !== ':status') {
        throw new Http2Error(codes.HTTP2_HEADER, `unknown response pseudo-header ${name}`, { name });
      }
      if (status !== null) {
        throw new Http2Error(codes.HTTP2_HEADER, 'duplicate :status pseudo-header');
      }
      if (!/^[0-9]{3}$/.test(value)) {
        throw new Http2Error(codes.HTTP2_HEADER, `:status ${JSON.stringify(value)} is not three digits`, { value });
      }
      status = Number(value);
      continue;
    }
    assertHeaderNameGrammar(name);
    if (FORBIDDEN_H2_HEADERS.has(name)) {
      throw new Http2Error(codes.HTTP2_HEADER, `connection-specific header ${name} is forbidden in HTTP/2`, { name });
    }
    if (name === 'te' && value.toLowerCase() !== 'trailers') {
      throw new Http2Error(codes.HTTP2_HEADER, 'the only legal te value in HTTP/2 is "trailers"');
    }
    sawRegular = true;
    if (name === 'set-cookie') setCookie.push(value);
    headers.append(name, value);
  }
  if (status === null) {
    throw new Http2Error(codes.HTTP2_HEADER, 'response has no :status pseudo-header');
  }
  return { status, headers, setCookie };
}

/** Validate decoded trailers: regular field lines only, never a pseudo-header (RFC 9113 s8.1). */
function parseTrailers(pairs) {
  const trailers = new Headers();
  for (const [name, value] of pairs) {
    if (name.length === 0 || name[0] === ':') {
      throw new Http2Error(codes.HTTP2_TRAILER, `trailer field ${JSON.stringify(name)} is not a regular header`);
    }
    assertHeaderNameGrammar(name);
    if (FORBIDDEN_H2_HEADERS.has(name)) {
      throw new Http2Error(codes.HTTP2_TRAILER, `connection-specific header ${name} is forbidden in a trailer`);
    }
    trailers.append(name, value);
  }
  return trailers;
}

/** RFC 9113 s8.2.1: field names are lowercase; an uppercase letter is malformed. Also reject the
 *  bytes the field-name grammar forbids, so a decoded name can never split a downstream parser. */
function assertHeaderNameGrammar(name) {
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    if (c >= 0x41 && c <= 0x5a) {
      throw new Http2Error(codes.HTTP2_HEADER, `header name ${JSON.stringify(name)} contains an uppercase letter`, { name });
    }
    // Control bytes, space, and the HTTP/2 forbidden separators have no place in a field name.
    if (c <= 0x20 || c === 0x7f || c === 0x3a /* ':' mid-name */) {
      throw new Http2Error(codes.HTTP2_HEADER, `header name ${JSON.stringify(name)} contains an illegal byte`, { name });
    }
  }
}
