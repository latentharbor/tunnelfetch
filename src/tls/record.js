// The record layer: framing, fragmentation, reassembly, alerts, key changes, KeyUpdate.
//
// This class sits between a ciphertext duplex ({readable, writable} of raw transport bytes)
// and the handshake driver / application data. It owns everything RFC 8446 s5 owns:
//
//   * record parsing that is provably independent of transport chunking (ByteReader),
//   * per-direction cipher state with sequence numbers that reset on every key change,
//   * handshake message reassembly — one message may span records, one record may carry many
//     messages, and a message may never span a key change,
//   * TLS 1.3 compatibility-mode change_cipher_spec handling,
//   * alert decode/encode, close_notify lifecycle, and post-handshake KeyUpdate.
//
// The failure discipline is: any protocol violation makes the layer permanently unusable (the
// first error is sticky and rethrown), a best-effort fatal alert is sent so the peer is not
// left hanging, and nothing decrypted after a violation is ever surfaced.

import {
  ByteReader, ByteWriter, UnexpectedEofError, concat, u8, u16, readU16, readU24,
} from '../util/bytes.js';
import { TlsError, TlsUnsupportedError, codes, hex8, hex16 } from '../errors.js';
import {
  RECORD_TYPE, HANDSHAKE_TYPE, ALERT_DESC, ALERT_LEVEL, MAX_PLAINTEXT, MAX_CIPHERTEXT,
  LEGACY_VERSION, TLS12, TLS13, CIPHER_PARAMS,
} from './constants.js';
import { createAead } from './aead.js';
import { trafficKeys, nextTrafficSecret } from './keyschedule.js';

/** Reverse alert map (name -> number), derived so constants.js stays the single source. */
const ALERT = Object.fromEntries(Object.entries(ALERT_DESC).map(([n, name]) => [name, +n]));

// Flood caps. All are counts, not clocks, so the layer stays deterministic with no injected
// time source. A compliant peer sends at most one compatibility CCS and has no reason to
// stream warning alerts or empty records; the caps only bound how long we humour a broken or
// hostile one.
const MAX_IGNORED_CCS = 8;
const MAX_IGNORED_ALERTS = 4;
const MAX_CONSECUTIVE_EMPTY = 32;

const KEY_UPDATE_NOT_REQUESTED = Uint8Array.from([HANDSHAKE_TYPE.key_update, 0, 0, 1, 0]);
const KEY_UPDATE_REQUESTED = Uint8Array.from([HANDSHAKE_TYPE.key_update, 0, 0, 1, 1]);

const typeName = (t) =>
  Object.entries(RECORD_TYPE).find(([, v]) => v === t)?.[0] ?? hex8(t);

export class RecordLayer {
  /**
   * @param {{ readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array> }} duplex
   * @param {{
   *   maxHandshakeMessage?: number,  // per-message cap; certificate chains dominate sizing
   *   maxKeyUpdates?: number,        // received KeyUpdates before we call it a flood
   *   padding?: null | ((type: number, length: number) => number), // extra zero bytes per record
   *   onPostHandshake?: null | ((msg: { type: number, body: Uint8Array, raw: Uint8Array })
   *     => void | Promise<void>),    // NewSessionTicket consumer; default is to discard
   * }} [opts]
   */
  constructor({ readable, writable }, opts = {}) {
    this._r = new ByteReader(readable);
    this._w = new ByteWriter(writable);
    this._maxHandshakeMessage = opts.maxHandshakeMessage ?? 1 << 17;
    this._maxKeyUpdates = opts.maxKeyUpdates ?? 32;
    this._padding = opts.padding ?? null;
    this._onPostHandshake = opts.onPostHandshake ?? null;

    this._version = TLS13; // semantics selector; setVersion() pins it when negotiated
    /** @type {null | { aead: any, seq: bigint, cipher: number, hash: string,
     *   secret: Uint8Array | null }} */
    this._send = null;
    this._recv = null;

    /** Handshake reassembly. Chunk list, not one growing buffer, so a peer drip-feeding a
     * message in tiny records costs O(records), not O(records^2). */
    this._hsChunks = [];
    this._hsLen = 0;
    this._hsHeader = null; // cached { type, len } of the message being assembled

    this._handshakeComplete = false;
    this._closedByPeer = false;  // close_notify received; everything after is ignored
    this._closedLocally = false; // close_notify or fatal alert sent; no further writes
    this._fatal = null;          // first protocol error; sticky
    this._anyRecordWritten = false;
    this._reading = false;

    /** All wire emission is funnelled through this chain. Two interleaved writers would
     * reorder — or worse, reuse — AEAD sequence numbers, and with GCM a single reused nonce
     * forfeits the key, so serialization here is a security control, not a convenience. */
    this._writeChain = Promise.resolve();

    this._ignoredCcs = 0;
    this._ignoredAlerts = 0;
    this._emptyStreak = 0;
    this._keyUpdatesReceived = 0;
  }

  // ------------------------------------------------------------------ configuration

  /**
   * Pin the negotiated version. Chooses CCS semantics (1.3: compatibility noise to ignore;
   * 1.2: a real key-change signal surfaced as `{ ccs: true }`), alert strictness, and AEAD
   * framing. Must happen before any keys are installed.
   */
  setVersion(version) {
    if (version !== TLS12 && version !== TLS13) {
      throw new TlsUnsupportedError(codes.TLS_VERSION_UNSUPPORTED,
        `record layer cannot speak version ${hex16(version)}`, { version });
    }
    if (this._send || this._recv) {
      throw new TlsError(codes.CONFIG_INVALID, 'version cannot change after keys are installed');
    }
    this._version = version;
  }

  get version() {
    return this._version;
  }

  get handshakeComplete() {
    return this._handshakeComplete;
  }

  /** The handshake driver calls this after the Finished exchange. Gates CCS and KeyUpdate. */
  markHandshakeComplete() {
    this._handshakeComplete = true;
  }

  // ------------------------------------------------------------------ key management

  /**
   * Install send-direction protection. Pass `secret` (a TLS 1.3 traffic secret; key and IV are
   * derived per RFC 8446 s7.3, and KeyUpdate rotation becomes possible) or raw `key`+`iv`
   * (TLS 1.2 key_block slices, which have no forward rotation). Sequence numbers reset.
   */
  async setSendKeys({ cipher, secret, key, iv }) {
    this._send = await this._makeState({ cipher, secret, key, iv });
  }

  /**
   * Install receive-direction protection. Refuses if a partially reassembled handshake
   * message is pending: RFC 8446 s5.1 forbids a handshake message from spanning a key change,
   * and enforcing it here — at the only point where the receive cipher can change — covers
   * both driver-installed keys and KeyUpdate rotation with a single check.
   */
  async setReceiveKeys({ cipher, secret, key, iv }) {
    if (this._hsLen > 0) {
      this._fail(codes.TLS_RECORD,
        `a handshake message (${this._hsLen} bytes pending) spans a key change`,
        { pending: this._hsLen }, ALERT.unexpected_message);
    }
    this._recv = await this._makeState({ cipher, secret, key, iv });
  }

  async _makeState({ cipher, secret, key, iv }) {
    const params = CIPHER_PARAMS[cipher];
    if (!params) {
      throw new TlsUnsupportedError(codes.TLS_CIPHER_UNSUPPORTED,
        `cipher suite ${hex16(cipher)} has no parameters`, { cipher });
    }
    if (secret) {
      if (this._version !== TLS13) {
        throw new TlsError(codes.CONFIG_INVALID,
          'traffic secrets are TLS 1.3; TLS 1.2 installs raw key_block slices');
      }
      ({ key, iv } = await trafficKeys(params.hash, secret, params.keyLen, params.ivLen));
    } else if (!key || !iv) {
      throw new TlsError(codes.CONFIG_INVALID, 'keys need either a traffic secret or key+iv');
    }
    const aead = await createAead({ version: this._version, cipher, key, iv });
    return { aead, seq: 0n, cipher, hash: params.hash, secret: secret ?? null };
  }

  // ------------------------------------------------------------------ read side

  /**
   * Next handshake message during the handshake phase.
   * Returns `{ type, body, raw }` (raw includes the 4-byte header, ready for the transcript),
   * `{ ccs: true }` in TLS 1.2 mode when the peer's change_cipher_spec arrives, or `null` if
   * the peer closed cleanly (which mid-handshake the driver should treat as failure).
   */
  async nextHandshakeMessage() {
    return this._guardedRead(async () => {
      const ev = await this._nextEvent();
      if (ev.kind === 'close') return null;
      if (ev.kind === 'ccs') return { ccs: true };
      if (ev.kind === 'data') {
        this._fail(codes.TLS_RECORD, 'application data received during the handshake',
          { length: ev.bytes.byteLength }, ALERT.unexpected_message);
      }
      return { type: ev.msgType, body: ev.body, raw: ev.raw };
    });
  }

  /**
   * Next application data chunk, or null at clean close_notify EOF. Post-handshake handshake
   * messages (KeyUpdate, NewSessionTicket) are consumed transparently here.
   */
  async readAppData() {
    if (!this._handshakeComplete) {
      throw new TlsError(codes.CONFIG_INVALID, 'readAppData before the handshake completed');
    }
    return this._guardedRead(async () => {
      for (;;) {
        const ev = await this._nextEvent();
        if (ev.kind === 'close') return null;
        if (ev.kind === 'data') return ev.bytes;
        if (ev.kind === 'handshake') {
          await this._postHandshakeMessage(ev);
          continue;
        }
        // 'ccs' is unreachable here: both versions reject CCS once keys/handshake are done.
        this._fail(codes.TLS_RECORD, 'unexpected change_cipher_spec after the handshake', {},
          ALERT.unexpected_message);
      }
    });
  }

  async _guardedRead(fn) {
    if (this._fatal) throw this._fatal;
    if (this._reading) {
      throw new TlsError(codes.CONFIG_INVALID, 'concurrent reads on one record layer');
    }
    this._reading = true;
    try {
      return await fn();
    } finally {
      this._reading = false;
    }
  }

  /**
   * One protocol event: a complete handshake message, an app-data chunk, a 1.2 CCS, or close.
   * All the "ignore and keep reading" cases (compat CCS, warning alerts, empty app records)
   * loop in here, each behind a flood cap.
   */
  async _nextEvent() {
    for (;;) {
      const msg = this._takeHandshakeMessage();
      if (msg) return msg;
      const rec = await this._nextPlaintextRecord();
      if (rec === null) return { kind: 'close' };
      const { type, data } = rec;
      if (type === RECORD_TYPE.handshake) {
        if (data.byteLength === 0) {
          // RFC 8446 s5.1: zero-length handshake fragments MUST NOT be sent. Tolerating them
          // would allow infinite record streams that never assemble a message.
          this._fail(codes.TLS_RECORD, 'zero-length handshake record', {},
            ALERT.unexpected_message);
        }
        this._hsChunks.push(data.slice()); // copy: record bodies may alias transport buffers
        this._hsLen += data.byteLength;
        continue;
      }
      if (type === RECORD_TYPE.alert) {
        if (this._handleAlert(data) === 'close') return { kind: 'close' };
        continue;
      }
      if (type === RECORD_TYPE.application_data) {
        if (data.byteLength === 0) {
          if (++this._emptyStreak > MAX_CONSECUTIVE_EMPTY) {
            this._fail(codes.TLS_RECORD,
              `${this._emptyStreak} consecutive empty application_data records`, {},
              ALERT.unexpected_message);
          }
          continue;
        }
        this._emptyStreak = 0;
        return { kind: 'data', bytes: data };
      }
      return { kind: 'ccs' }; // TLS 1.2 only; 1.3 CCS never escapes _nextPlaintextRecord
    }
  }

  /** Complete message off the reassembly buffer, if one is there. */
  _takeHandshakeMessage() {
    if (this._hsLen < 4) return null;
    if (!this._hsHeader) {
      const four = new Uint8Array(4);
      let o = 0;
      for (const c of this._hsChunks) {
        const n = Math.min(4 - o, c.byteLength);
        four.set(c.subarray(0, n), o);
        o += n;
        if (o === 4) break;
      }
      const len = readU24(four, 1);
      if (len > this._maxHandshakeMessage) {
        this._fail(codes.TLS_HANDSHAKE,
          `handshake message type ${four[0]} declares ${len} bytes, over the ` +
          `${this._maxHandshakeMessage} byte cap`,
          { type: four[0], length: len, limit: this._maxHandshakeMessage },
          ALERT.unexpected_message);
      }
      this._hsHeader = { type: four[0], len };
    }
    const total = 4 + this._hsHeader.len;
    if (this._hsLen < total) return null;
    const all = concat(this._hsChunks, this._hsLen);
    const rest = all.subarray(total);
    this._hsChunks = rest.byteLength ? [rest] : [];
    this._hsLen = rest.byteLength;
    const { type } = this._hsHeader;
    this._hsHeader = null;
    return {
      kind: 'handshake', msgType: type, body: all.subarray(4, total), raw: all.subarray(0, total),
    };
  }

  /**
   * Read one record off the wire and reduce it to (inner type, plaintext), or null once the
   * peer has said close_notify. Handles decryption, the plaintext/ciphertext legality rules,
   * and TLS 1.3 compatibility CCS.
   */
  async _nextPlaintextRecord() {
    for (;;) {
      if (this._closedByPeer) return null; // RFC 8446 s6.1: ignore everything after close_notify
      let header;
      try {
        header = await this._r.readExactly(5, 'record header');
      } catch (e) {
        if (e instanceof UnexpectedEofError) {
          // EOF without close_notify is indistinguishable from an attacker cutting the
          // stream at a record boundary — a truncation attack. Fail, never "clean end".
          this._fail(codes.TLS_TRUNCATED, e.detail?.got === 0
            ? 'peer closed the transport without close_notify'
            : `transport ended mid record header (${e.detail?.got} of 5 bytes)`,
          { got: e.detail?.got });
        }
        throw e;
      }
      const type = header[0];
      const length = readU16(header, 3);
      // header[1..2] is legacy_record_version: deliberately unchecked. RFC 8446 s5.1 requires
      // ignoring it, and real middleboxes emit historical values there.
      if (type !== RECORD_TYPE.change_cipher_spec && type !== RECORD_TYPE.alert &&
          type !== RECORD_TYPE.handshake && type !== RECORD_TYPE.application_data) {
        this._fail(codes.TLS_RECORD, `unknown record type ${hex8(type)}`, { type },
          ALERT.unexpected_message);
      }
      // 2^14 for plaintext records, +256 for AEAD expansion once keys are on. The 1.3 bound is
      // also imposed on 1.2 peers: RFC 5246 nominally allows 2^14+2048, but the only 1.2
      // suites we speak are GCM with 24 bytes of overhead, so a compliant peer stays far under.
      const limit = this._recv ? MAX_CIPHERTEXT : MAX_PLAINTEXT;
      if (length > limit) {
        this._fail(codes.TLS_RECORD, `record length ${length} exceeds ${limit}`,
          { type, length, limit }, ALERT.record_overflow);
      }
      let body;
      try {
        body = await this._r.readExactly(length, `${typeName(type)} record body`);
      } catch (e) {
        if (e instanceof UnexpectedEofError) {
          this._fail(codes.TLS_TRUNCATED,
            `transport ended mid record: got ${e.detail?.got} of ${length} body bytes`,
            { type, length, got: e.detail?.got });
        }
        throw e;
      }

      if (type === RECORD_TYPE.change_cipher_spec) {
        if (length !== 1 || body[0] !== 0x01) {
          this._fail(codes.TLS_RECORD,
            `change_cipher_spec must be exactly one 0x01 byte, got ${length} byte(s)` +
            (length >= 1 ? ` starting ${hex8(body[0])}` : ''),
          { length }, ALERT.unexpected_message);
        }
        if (this._version === TLS12) {
          if (this._recv) {
            // A second CCS would signal renegotiation, which this package refuses to speak.
            this._fail(codes.TLS_RECORD, 'change_cipher_spec after keys were installed', {},
              ALERT.unexpected_message);
          }
          return { type, data: body };
        }
        // TLS 1.3 compatibility mode (RFC 8446 s5): drop, but only mid-handshake, and not
        // in unlimited quantity.
        if (this._handshakeComplete) {
          this._fail(codes.TLS_RECORD, 'change_cipher_spec after handshake completion', {},
            ALERT.unexpected_message);
        }
        if (++this._ignoredCcs > MAX_IGNORED_CCS) {
          this._fail(codes.TLS_RECORD, `${this._ignoredCcs} change_cipher_spec records`, {},
            ALERT.unexpected_message);
        }
        continue;
      }

      if (!this._recv) return { type, data: body };

      if (this._version === TLS13 && type !== RECORD_TYPE.application_data) {
        // Once the peer encrypts, a plaintext alert/handshake record can only be injected or
        // a peer bug; surfacing it would hand an attacker a plaintext channel.
        this._fail(codes.TLS_RECORD,
          `plaintext ${typeName(type)} record after encryption started`, { type },
          ALERT.unexpected_message);
      }
      let opened;
      try {
        opened = await this._recv.aead.decrypt(this._recv.seq, body, header);
      } catch (e) {
        if (e instanceof TlsError && !this._fatal) {
          this._fatal = e;
          this._sendAlertBestEffort(ALERT.bad_record_mac);
        }
        throw e;
      }
      this._recv.seq++;
      if (this._version === TLS13) {
        const t = opened.type;
        if (t !== RECORD_TYPE.alert && t !== RECORD_TYPE.handshake &&
            t !== RECORD_TYPE.application_data) {
          // Includes protected change_cipher_spec, which RFC 8446 s5 singles out as fatal.
          this._fail(codes.TLS_RECORD, `forbidden inner content type ${hex8(t)}`, { type: t },
            ALERT.unexpected_message);
        }
        return { type: t, data: opened.plaintext };
      }
      return { type, data: opened.plaintext };
    }
  }

  /** @returns {'close' | 'ignored'} or throws for fatal alerts */
  _handleAlert(data) {
    if (data.byteLength !== 2) {
      this._fail(codes.TLS_RECORD, `alert record of ${data.byteLength} bytes (must be exactly 2)`,
        { length: data.byteLength }, ALERT.decode_error);
    }
    const [level, desc] = data;
    const name = ALERT_DESC[desc] ?? `unknown_${desc}`;
    if (desc === ALERT.close_notify) {
      this._closedByPeer = true;
      return 'close';
    }
    // TLS 1.3 (s6): every alert except close_notify/user_canceled is an error regardless of
    // its claimed level. TLS 1.2 peers legitimately send warnings (unrecognized_name, most
    // famously) that a client must survive.
    const ignorable = this._version === TLS13
      ? desc === ALERT.user_canceled
      : level === ALERT_LEVEL.warning;
    if (ignorable) {
      if (++this._ignoredAlerts > MAX_IGNORED_ALERTS) {
        this._fail(codes.TLS_RECORD, `peer sent ${this._ignoredAlerts} warning alerts`, {},
          ALERT.unexpected_message);
      }
      return 'ignored';
    }
    const err = new TlsError(codes.TLS_ALERT, `peer sent fatal alert: ${name} (${desc})`,
      { level, description: desc, name });
    this._fatal = err;
    throw err;
  }

  /** KeyUpdate and NewSessionTicket arriving under application keys. */
  async _postHandshakeMessage({ msgType, body, raw }) {
    if (this._version === TLS13 && msgType === HANDSHAKE_TYPE.key_update) {
      if (++this._keyUpdatesReceived > this._maxKeyUpdates) {
        this._fail(codes.TLS_RECORD,
          `peer sent ${this._keyUpdatesReceived} KeyUpdates, over the ` +
          `${this._maxKeyUpdates} cap`, { count: this._keyUpdatesReceived },
        ALERT.unexpected_message);
      }
      if (body.byteLength !== 1 || body[0] > 1) {
        this._fail(codes.TLS_HANDSHAKE,
          `malformed KeyUpdate: ${body.byteLength} byte body` +
          (body.byteLength >= 1 ? `, request ${hex8(body[0])}` : ''),
        {}, ALERT.illegal_parameter);
      }
      // The peer already switched its send keys; rotate our receive state first so the very
      // next record decrypts. setReceiveKeys re-checks the spans-a-key-change rule, which
      // also catches a peer that put more handshake bytes after KeyUpdate in the same record.
      const r = this._recv;
      if (!r?.secret) {
        this._fail(codes.TLS_RECORD, 'KeyUpdate but receive keys are not rotatable', {},
          ALERT.unexpected_message);
      }
      await this.setReceiveKeys({
        cipher: r.cipher, secret: await nextTrafficSecret(r.hash, r.secret),
      });
      if (body[0] === 1) {
        // update_requested: answer with update_not_requested under the OLD send keys, then
        // rotate our send side (RFC 8446 s4.6.3 ordering). One chained task, so a concurrent
        // application write cannot slip between the response and the rotation. Deliberately
        // NOT awaited: this runs on the read path, and blocking reads until the peer drains
        // our writes deadlocks two zero-buffer endpoints (each waiting on the other's read
        // loop). The chain still orders it before any later write of ours; if the transport
        // is dead the very next operation will surface that, so the error adds nothing here.
        this._enqueueWrite(async () => {
          await this._emit(RECORD_TYPE.handshake, KEY_UPDATE_NOT_REQUESTED);
          await this._rotateSend();
        }).catch(() => {});
      }
      return;
    }
    if (this._version === TLS13 && msgType === HANDSHAKE_TYPE.new_session_ticket) {
      // Tickets are optional to use and safe to drop (RFC 8446 s4.6.1).
      if (this._onPostHandshake) await this._onPostHandshake({ type: msgType, body, raw });
      return;
    }
    this._fail(codes.TLS_HANDSHAKE, `unexpected post-handshake message type ${msgType}`,
      { type: msgType }, ALERT.unexpected_message);
  }

  // ------------------------------------------------------------------ write side

  /**
   * Write one or more complete handshake messages, coalescing them into as few records as
   * possible (the ClientHello flight and the 1.2 client second flight benefit) and
   * fragmenting anything over 2^14.
   * @param {Uint8Array | Uint8Array[]} messages
   */
  async writeHandshake(messages) {
    const bytes = Array.isArray(messages) ? concat(messages) : messages;
    if (bytes.byteLength === 0) {
      throw new TlsError(codes.CONFIG_INVALID, 'refusing to write a zero-length handshake record');
    }
    await this._writeFragmented(RECORD_TYPE.handshake, bytes);
  }

  /** Write application data, fragmented to the record size limit. */
  async writeAppData(bytes) {
    if (!this._send) {
      throw new TlsError(codes.CONFIG_INVALID, 'writeAppData before send keys were installed');
    }
    await this._writeFragmented(RECORD_TYPE.application_data, bytes);
  }

  /** The one-byte compatibility (1.3) or key-change (1.2) CCS record. Always plaintext. */
  async writeChangeCipherSpec() {
    this._assertWritable();
    await this._enqueueWrite(() =>
      this._writeRecord(RECORD_TYPE.change_cipher_spec, Uint8Array.from([0x01])));
  }

  /**
   * Post-handshake KeyUpdate initiated by us: send under current keys, then rotate our send
   * chain. With `requestPeer` the peer must answer and rotate its own send keys too.
   */
  async updateKeys({ requestPeer = false } = {}) {
    if (this._version !== TLS13 || !this._handshakeComplete || !this._send?.secret) {
      throw new TlsError(codes.CONFIG_INVALID,
        'KeyUpdate needs a completed TLS 1.3 handshake with secret-based keys');
    }
    this._assertWritable();
    await this._enqueueWrite(async () => {
      await this._emit(RECORD_TYPE.handshake,
        requestPeer ? KEY_UPDATE_REQUESTED : KEY_UPDATE_NOT_REQUESTED);
      await this._rotateSend();
    });
  }

  async sendAlert(level, desc) {
    this._assertWritable();
    await this._enqueueWrite(() =>
      this._emit(RECORD_TYPE.alert, Uint8Array.from([level & 0xff, desc & 0xff])));
  }

  /** Clean shutdown: close_notify, then close the transport write side. */
  async close() {
    if (!this._closedLocally) {
      this._closedLocally = true;
      try {
        await this._enqueueWrite(() => this._emit(RECORD_TYPE.alert,
          Uint8Array.from([ALERT_LEVEL.warning, ALERT.close_notify])));
      } catch {
        /* peer may already be gone; close_notify is best-effort by nature */
      }
    }
    // Through the chain, so a pending best-effort alert still beats the FIN.
    await this._enqueueWrite(() => this._w.close());
  }

  /**
   * Abort: send a fatal alert naming why, then close. A peer left to time out on a dead
   * connection is an interop bug of ours, not a neutral choice.
   */
  async abort(desc = ALERT.internal_error) {
    if (!this._closedLocally) {
      this._closedLocally = true;
      try {
        await this._enqueueWrite(() => this._emit(RECORD_TYPE.alert,
          Uint8Array.from([ALERT_LEVEL.fatal, desc & 0xff])));
      } catch {
        /* transport may be gone */
      }
    }
    await this._enqueueWrite(() => this._w.close());
  }

  /**
   * Application-data face of the connection as a {readable, writable} pair, for stacking the
   * HTTP layer on top exactly like it would stack on a raw socket.
   */
  plaintextDuplex() {
    const self = this;
    return {
      readable: new ReadableStream({
        async pull(controller) {
          const bytes = await self.readAppData();
          if (bytes === null) controller.close();
          else controller.enqueue(bytes);
        },
        cancel() {
          return self._r.cancel();
        },
      }),
      writable: new WritableStream({
        write(chunk) {
          return self.writeAppData(chunk);
        },
        close() {
          return self.close();
        },
        abort() {
          return self.abort(ALERT.internal_error);
        },
      }),
    };
  }

  // ------------------------------------------------------------------ write internals

  _assertWritable() {
    if (this._closedLocally) {
      throw new TlsError(codes.CONFIG_INVALID, 'write after close_notify or a fatal alert');
    }
  }

  /** Serialize a wire-writing task behind every previously enqueued one. */
  _enqueueWrite(fn) {
    const task = this._writeChain.then(fn);
    this._writeChain = task.then(() => undefined, () => undefined);
    return task;
  }

  async _writeFragmented(type, bytes) {
    this._assertWritable();
    // The whole call is one chained task so fragments of two concurrent writes cannot
    // interleave (which would corrupt the plaintext order even though each record decrypts).
    await this._enqueueWrite(async () => {
      if (bytes.byteLength === 0) {
        await this._emit(type, bytes); // an empty app-data record is a legal keepalive
        return;
      }
      for (let o = 0; o < bytes.byteLength; o += MAX_PLAINTEXT) {
        await this._emit(type, bytes.subarray(o, Math.min(o + MAX_PLAINTEXT, bytes.byteLength)));
      }
    });
  }

  /** Encrypt-and-frame one fragment. Only ever runs inside the write chain. */
  async _emit(type, chunk) {
    if (!this._send) {
      await this._writeRecord(type, chunk);
      return;
    }
    let padding = 0;
    if (this._padding && this._version === TLS13) {
      padding = this._padding(type, chunk.byteLength);
      if (!Number.isInteger(padding) || padding < 0) {
        throw new TlsError(codes.CONFIG_INVALID,
          `padding policy returned ${padding}, not a non-negative integer`);
      }
    }
    // Claim the sequence number synchronously, before any await, so a bug that lets two
    // emits race can only skip a number — never reuse one.
    const state = this._send;
    const seq = state.seq;
    state.seq = seq + 1n;
    const body = await state.aead.encrypt(seq, type, chunk, { padding });
    const outer = this._version === TLS13 ? RECORD_TYPE.application_data : type;
    await this._writeRecord(outer, body);
  }

  async _writeRecord(type, body) {
    // RFC 8446 s5.1: the first plaintext ClientHello record MAY say 0x0301, and doing so is
    // the compatibility choice (RFC 8448's traces do the same); everything else says 0x0303.
    const version = !this._anyRecordWritten && type === RECORD_TYPE.handshake && !this._send
      ? 0x0301
      : LEGACY_VERSION;
    this._anyRecordWritten = true;
    await this._w.writeAll([u8(type), u16(version), u16(body.byteLength), body]);
  }

  /** Derive application_traffic_secret_N+1 and swap the send state. Runs inside the chain. */
  async _rotateSend() {
    const s = this._send;
    const secret = await nextTrafficSecret(s.hash, s.secret);
    const params = CIPHER_PARAMS[s.cipher];
    const { key, iv } = await trafficKeys(params.hash, secret, params.keyLen, params.ivLen);
    const aead = await createAead({ version: this._version, cipher: s.cipher, key, iv });
    this._send = { aead, seq: 0n, cipher: s.cipher, hash: s.hash, secret };
  }

  // ------------------------------------------------------------------ failure plumbing

  /** Record the first fatal error, tell the peer (best-effort), throw. Never returns. */
  _fail(code, message, detail, alertDesc) {
    const err = new TlsError(code, message, detail);
    if (!this._fatal) {
      this._fatal = err;
      if (alertDesc !== undefined) this._sendAlertBestEffort(alertDesc);
    }
    throw err;
  }

  /**
   * Fire-and-forget: awaiting a write here could park the failure path behind transport
   * backpressure, and the error must reach our caller no matter what the peer does. The
   * write chain still orders it before the transport close.
   */
  _sendAlertBestEffort(desc) {
    if (this._closedLocally) return;
    this._closedLocally = true;
    this._enqueueWrite(async () => {
      await this._emit(RECORD_TYPE.alert, Uint8Array.from([ALERT_LEVEL.fatal, desc]));
      await this._w.close();
    }).catch(() => {});
  }
}
