// X.509 certificate parsing: the largest hand-written parser in the package, fed bytes chosen by
// whoever answers the TLS handshake. DER is nested TLV all the way down, so every length field is
// an opportunity to read past the end of a buffer.

import { parseCertificate } from '../../../src/trust/x509.js';
import { caFixture } from '../../trust/_certs.js';

const fx = caFixture();

export default {
  name: 'x509.parseCertificate',
  // Real DER, so mutations start from structurally valid input and stay near the shapes the parser
  // actually walks. Fuzzing from random bytes would spend every iteration rejected by the first tag.
  corpus: [fx.leaf.der, fx.intermediate.der, fx.root.der],
  run: (input) => parseCertificate(input),
};
