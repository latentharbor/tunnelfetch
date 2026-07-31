// Every line below MUST be a compile error. test/types.test.js runs tsc over this file and fails
// if any of them type-checks — the point of generating declarations at all was that a caller
// cannot express a trust policy the runtime would reject, so if these start compiling the types
// have stopped earning their keep.
//
// The file is never executed and never imported by anything at runtime.

import { Client } from '../../types/index.js';

// @ts-expect-error pinning without pins is meaningless and must not be expressible
new Client({ trust: { mode: 'pinned' } });

// @ts-expect-error reaching "none" requires spelling out the flag that says you meant it
new Client({ trust: { mode: 'none' } });

// @ts-expect-error and writing `false` must not be a way to satisfy that requirement
new Client({ trust: { mode: 'none', insecureAcceptAnyCertificate: false } });

// @ts-expect-error the discriminant is a closed set, so a typo is caught rather than defaulted
new Client({ trust: { mode: 'systm', } });

// @ts-expect-error anchors mode needs anchors
new Client({ trust: { mode: 'anchors' } });

// @ts-expect-error there is no revocation value that switches the check off
new Client({ trust: { mode: 'system', revocation: 'off' } });

// @ts-expect-error mode 'none' has no validated issuer, so revocation is not expressible there
new Client({ trust: { mode: 'none', insecureAcceptAnyCertificate: true, revocation: 'staple' } });

// @ts-expect-error a numeric option is not a string
new Client({ maxRedirects: 'ten' });

// @ts-expect-error a misspelled option is caught rather than silently ignored
new Client({ maxRedirect: 10 });
