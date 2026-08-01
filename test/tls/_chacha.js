// A real ChaCha20-Poly1305 (RFC 8439 IETF AEAD) for tests, over node:crypto — which HAS it,
// unlike the WebCrypto this package targets. Shaped exactly like the injected `impl` aead.js
// expects: seal(key, nonce, plaintext, aad) -> ciphertext||tag, open(...) -> plaintext | null.
//
// node:crypto is fine here: this is a test helper, not shipped code. On the target runtime the
// caller injects a WASM (or node:crypto) implementation of this same shape.

import { createCipheriv, createDecipheriv } from 'node:crypto';

export function nodeChacha20() {
  return {
    seal(key, nonce, plaintext, aad) {
      const c = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
      if (aad && aad.length) c.setAAD(aad, { plaintextLength: plaintext.length });
      const body = Buffer.concat([c.update(plaintext), c.final()]);
      return new Uint8Array(Buffer.concat([body, c.getAuthTag()]));
    },
    open(key, nonce, ciphertext, aad) {
      if (ciphertext.length < 16) return null;
      const body = ciphertext.subarray(0, ciphertext.length - 16);
      const tag = ciphertext.subarray(ciphertext.length - 16);
      const d = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
      if (aad && aad.length) d.setAAD(aad, { plaintextLength: body.length });
      d.setAuthTag(tag);
      try {
        return new Uint8Array(Buffer.concat([d.update(body), d.final()]));
      } catch {
        return null; // authentication failed
      }
    },
  };
}
