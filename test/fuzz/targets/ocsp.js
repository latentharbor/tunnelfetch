// OCSP responses arrive stapled inside the handshake, signed by a key that is only trusted AFTER
// the response has been parsed — so the parser runs on unauthenticated bytes by construction.

import { parseOcspResponse } from '../../../src/trust/ocsp.js';
import { caFixture, makeOcspResponse } from '../../trust/_certs.js';

const fx = caFixture();
const now = Date.UTC(2026, 0, 1);
const good = makeOcspResponse({
  issuer: fx.intermediate,
  subject: fx.leaf,
  thisUpdate: now - 3600_000,
  nextUpdate: now + 86_400_000,
}).der;

export default {
  name: 'ocsp.parseOcspResponse',
  corpus: [good],
  run: (input) => parseOcspResponse(input),
};
