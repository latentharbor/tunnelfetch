#!/usr/bin/env node
// Regenerates src/trust/roots.js from the CCADB list of roots trusted for TLS server auth.
//
// Runs on a developer machine (node:fs / node:crypto / network are fine HERE — never in src/).
// The anchors are parsed with this package's own x509 parser, which doubles as a smoke test:
// generation fails loudly if the parser chokes on any real-world root.
//
// Usage:
//   node scripts/refresh-roots.mjs                 # fetch from CCADB, rewrite src/trust/roots.js
//   node scripts/refresh-roots.mjs --from-file p.pem [--out path]   # offline regeneration
//
// Root certificate data: Mozilla / Common CA Database (CCADB), licensed CDLA-Permissive-2.0.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import process from 'node:process';
import { parseCertificate, decodePem, OID } from '../src/trust/x509.js';

export const SOURCE_URL =
  'https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites';

/**
 * What provenance.source records for a CCADB fetch. Deliberately not the URL: src/ (including
 * the generated store) carries no endpoints — the URL lives here in scripts/, and the identifier
 * names the feed unambiguously for anyone auditing the store.
 */
export const SOURCE_ID = 'ccadb:IncludedRootsPEMTxt?TrustBitsInclude=Websites';

const b64 = (u8) => (u8 == null ? null : Buffer.from(u8).toString('base64'));
const sha256hex = (u8) => createHash('sha256').update(u8).digest('hex');

/**
 * PEM text -> packed anchor records. Strips each root to the RFC 5280 s6.1.1 trust-anchor triple
 * (name, key, constraints) plus validity and SKI: the self-signature is never verified by path
 * validation, so shipping it (and the rest of the certificate) would be dead weight on every
 * cold start.
 */
export function buildAnchors(pemText) {
  const seen = new Set();
  const anchors = [];
  for (const der of decodePem(pemText)) {
    const cert = parseCertificate(der);
    if (!cert.isSelfIssued) {
      // CCADB ships self-signed roots only; anything else means the feed or the parser broke.
      throw new Error(`root "${cert.subject.text}" is not self-issued; refusing to generate`);
    }
    const dedupeKey = sha256hex(Buffer.concat([cert.subject.bytes, cert.spki.spkiDer]));
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    anchors.push({
      subjectHash: sha256hex(cert.subject.bytes),
      name: cert.subject.text,
      s: b64(cert.subject.bytes),
      spki: b64(cert.spki.spkiDer),
      ski: b64(cert.subjectKeyIdentifier),
      nc: b64(cert.extensions.get(OID.nameConstraints)?.valueBytes ?? null),
      nb: cert.notBefore,
      na: cert.notAfter,
    });
  }
  // Deterministic order: by subject hash, then by key, so regeneration from identical input is
  // byte-identical output and diffs show only real changes.
  anchors.sort((a, b) => (a.subjectHash < b.subjectHash ? -1 : a.subjectHash > b.subjectHash ? 1 :
    a.spki < b.spki ? -1 : a.spki > b.spki ? 1 : 0));
  return anchors;
}

/** Assemble the complete module source for src/trust/roots.js. */
export function buildModuleSource(pemText, { source, retrievedAt }) {
  const anchors = buildAnchors(pemText);
  const upstreamSha256 = sha256hex(typeof pemText === 'string' ? Buffer.from(pemText) : pemText);
  const groups = new Map();
  for (const a of anchors) {
    if (!groups.has(a.subjectHash)) groups.set(a.subjectHash, []);
    groups.get(a.subjectHash).push(a);
  }
  const entries = [...groups.entries()].map(([hash, list]) => {
    const packed = list.map((a) =>
      `{ name: ${JSON.stringify(a.name)}, s: ${JSON.stringify(a.s)}, spki: ${JSON.stringify(a.spki)}, ` +
      `ski: ${JSON.stringify(a.ski)}, nc: ${JSON.stringify(a.nc)}, nb: ${a.nb}, na: ${a.na} }`);
    return `  '${hash}': [\n    ${packed.join(',\n    ')},\n  ],`;
  });

  const code = `// Bundled trust anchor store. GENERATED FILE — do not edit; run \`npm run roots:refresh\`.
//
// Root certificate data from Mozilla / Common CA Database (CCADB),
// licensed under CDLA-Permissive-2.0 (https://cdla.dev/permissive-2-0/).
//
// Anchors are STRIPPED per RFC 5280 s6.1.1 — subject DN bytes, SPKI, validity, subject key
// identifier, and raw name-constraints — because a trust anchor is a (name, key, constraints)
// triple and a root's own self-signature is never verified. The store is indexed by SHA-256 of
// the subject DN so a handshake decodes exactly the one anchor its chain lands on: this runs on
// CPU-metered runtimes, and scanning every anchor per connection is not acceptable.
//
// A stale store is a slow-burning availability bug ("TLS randomly fails", months later), which
// is why provenance below records exactly what was fetched and when.
//
// This module must never import from \`node:\` — it ships to runtimes that have none of it.

import { equal, toHex } from '../util/bytes.js';

/** Where these anchors came from. */
export const provenance = Object.freeze({
  source: ${JSON.stringify(source)},
  retrievedAt: ${JSON.stringify(retrievedAt)},
  upstreamSha256: ${JSON.stringify(upstreamSha256)},
  anchorCount: ${anchors.length},
});

/**
 * hex(SHA-256(subject DN DER)) -> packed anchors sharing that subject.
 * Packed anchor: { name, s: base64 subject DN, spki: base64 SPKI DER, ski: base64|null,
 * nc: base64 raw nameConstraints extnValue|null, nb/na: epoch ms }.
 */
const STORE = {
${entries.join('\n')}
};

function fromBase64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function unpack(p) {
  return {
    subjectText: p.name,
    subjectBytes: fromBase64(p.s),
    spkiDer: fromBase64(p.spki),
    subjectKeyIdentifier: p.ski ? fromBase64(p.ski) : null,
    nameConstraintsBytes: p.nc ? fromBase64(p.nc) : null,
    notBefore: p.nb,
    notAfter: p.na,
  };
}

/**
 * Anchor source consumed by path validation: resolves the anchors for one issuer DN. The DN is
 * hashed to index the store, and the stored DN is compared byte-for-byte afterwards so even a
 * hash-bucket surprise cannot alias two names.
 */
export const systemAnchors = {
  async forIssuer(dnBytes) {
    const digest = await crypto.subtle.digest('SHA-256', dnBytes);
    const packed = STORE[toHex(new Uint8Array(digest))];
    if (!packed) return [];
    return packed.map(unpack).filter((a) => equal(a.subjectBytes, dnBytes));
  },
};
`;
  return { code, count: anchors.length, upstreamSha256 };
}

async function main() {
  const args = process.argv.slice(2);
  const argOf = (flag) => {
    const i = args.indexOf(flag);
    return i === -1 ? null : args[i + 1];
  };
  const fromFile = argOf('--from-file');
  const out = argOf('--out') ?? fileURLToPath(new URL('../src/trust/roots.js', import.meta.url));

  let pemText;
  let source;
  if (fromFile) {
    pemText = readFileSync(fromFile, 'utf8');
    source = `file:${fromFile}`;
  } else {
    const res = await fetch(SOURCE_URL);
    if (!res.ok) throw new Error(`CCADB fetch failed: ${res.status} ${res.statusText}`);
    pemText = await res.text();
    source = SOURCE_ID;
  }

  const retrievedAt = new Date().toISOString().slice(0, 10);
  const { code, count, upstreamSha256 } = buildModuleSource(pemText, { source, retrievedAt });
  if (!fromFile && count < 100) {
    // The Mozilla store has hovered around 150 roots for a decade; a sudden collapse means a
    // truncated download or a format change, and either must not silently become the store.
    throw new Error(`only ${count} anchors parsed from CCADB; refusing to write a suspicious store`);
  }
  writeFileSync(out, code);
  console.log(`wrote ${out}: ${count} anchors, source ${source}, sha256 ${upstreamSha256}, ${retrievedAt}`);
}

// Import-safe: the test suite imports buildAnchors/buildModuleSource without running main.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
