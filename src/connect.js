// Obtaining the host runtime's raw-socket factory.
//
// Every layer above this one takes `connect` as an argument, and that is deliberate: it is what
// keeps src/ free of runtime-specific imports and what makes every protocol path testable over an
// in-memory pipe. This module does not weaken that. It answers a narrower question that callers
// kept answering badly by hand:
//
//   given a runtime whose socket factory lives behind a module specifier, produce a validated
//   ConnectFn, or fail with an error that says what was tried.
//
// Two rules shape the design.
//
//  1. The specifier is DATA, supplied by the caller. No module name is baked in here, because a
//     name baked in is behaviour conditioned on one vendor's runtime, and this package is not
//     allowed to have any. The host application knows which runtime it is running on; this module
//     does not need to guess, and a wrong guess is worse than an argument.
//
//  2. The import is dynamic and its failure is caught. A static import of a specifier that only
//     resolves on one runtime makes this module unloadable everywhere else, which would take the
//     whole package down with it on every other platform.
//
// A BUNDLER CAVEAT that matters more than it looks. The default importer calls `import(spec)` with
// a variable. Bundlers cannot see through a variable specifier, so they will not include the
// target module in the output, and on a bundled deployment the import fails at runtime even though
// the module exists. Where a bundler is in play — which on edge runtimes is nearly always — pass
// the socket factory straight in as `connect`, or pass an `importModule` that closes over a
// LITERAL specifier the bundler can see:
//
//   resolveConnect({ importModule: () => import('some:sockets') })
//
// That is why `connect` is checked first and short-circuits without importing anything: direct
// injection is the recommended path, and the specifier list is the convenience, not the contract.

import { ConfigError, codes } from './errors.js';

/** @typedef {import('./proxy/index.js').ConnectFn} ConnectFn */
/** @typedef {import('./proxy/index.js').Duplex} Duplex */

/**
 * @typedef {object} ResolveConnectOptions
 * @property {ConnectFn} [connect] an already-obtained socket factory. Checked first and returned
 *   as-is, so the recommended path costs no import and cannot be defeated by a bundler.
 * @property {string[]} [specifiers] module specifiers to try, in order. The first module whose
 *   `exportName` is callable wins.
 * @property {(specifier: string) => Promise<object>} [importModule] the importer. Defaults to a
 *   dynamic `import()`; override it to hand the bundler a literal specifier.
 * @property {string} [exportName] the export to read off each module. Default 'connect'.
 */

/**
 * Is `value` shaped like a socket factory? Only callability can be checked without dialling, so
 * that is what this checks — the duplex contract is enforced when a socket is actually opened.
 * @param {unknown} value
 * @returns {value is ConnectFn}
 */
export function isConnectFn(value) {
  return typeof value === 'function';
}

/**
 * Resolve a ConnectFn from an injected factory or from the first module specifier that yields one.
 *
 * Resolution order, and nothing else is consulted:
 *   1. `options.connect`, when callable.
 *   2. each entry of `options.specifiers`, in order.
 *
 * Throws ConfigError (CONFIG_UNSATISFIABLE) when nothing resolves, listing every specifier tried
 * with the reason it failed. A socket factory that cannot be found is a deployment mistake, and a
 * deployment mistake deserves to name the thing that was missing rather than surface later as
 * "connect is not a function" from inside the TLS layer.
 *
 * @param {ResolveConnectOptions} [options]
 * @returns {Promise<ConnectFn>}
 */
export async function resolveConnect(options = {}) {
  const { connect, specifiers = [], importModule = defaultImport, exportName = 'connect' } = options;

  if (connect !== undefined && connect !== null) {
    if (!isConnectFn(connect)) {
      throw new ConfigError(
        codes.CONFIG_INVALID,
        `connect must be a function returning { readable, writable, opened?, close? }, got ` +
          `${describe(connect)}`,
      );
    }
    return connect;
  }

  if (!Array.isArray(specifiers)) {
    throw new ConfigError(codes.CONFIG_INVALID, 'specifiers must be an array of module specifiers');
  }
  if (typeof importModule !== 'function') {
    throw new ConfigError(codes.CONFIG_INVALID, 'importModule must be a function');
  }

  /** @type {string[]} */
  const tried = [];
  for (const specifier of specifiers) {
    if (typeof specifier !== 'string' || specifier === '') {
      throw new ConfigError(
        codes.CONFIG_INVALID,
        `specifiers must be non-empty strings, got ${describe(specifier)}`,
      );
    }
    let mod;
    try {
      mod = await importModule(specifier);
    } catch (cause) {
      // Not resolvable on this runtime, which for a portable specifier list is the expected
      // outcome for every entry but one. Recorded, not thrown.
      tried.push(`${specifier}: not importable (${cause?.message ?? cause})`);
      continue;
    }
    const candidate = mod?.[exportName] ?? mod?.default?.[exportName];
    if (isConnectFn(candidate)) return candidate;
    tried.push(`${specifier}: imported, but has no callable "${exportName}" export`);
  }

  throw new ConfigError(
    codes.CONFIG_UNSATISFIABLE,
    'no socket factory could be resolved. Supply `connect` directly — the raw-TCP socket factory ' +
      'of the host runtime, returning { readable, writable, opened?, close? } — or name a module ' +
      'that exports one. ' +
      (tried.length ? `Tried:\n  ${tried.join('\n  ')}` : 'No specifiers were given.'),
    { tried },
  );
}

/**
 * Flatten a runtime socket into a plain duplex object.
 *
 * Worth its own function because of a trap that has already cost this package a bug: on the edge
 * runtime a socket's `readable` and `writable` are ACCESSORS ON THE PROTOTYPE, so `{ ...socket }`
 * copies neither and the first read fails far away, inside the TLS layer, with "Cannot read
 * properties of undefined (reading 'getReader')". Reading the properties explicitly — which is
 * what this does — is the only spread-safe way to hand a host socket to code that may copy it.
 *
 * @param {Duplex} socket
 * @returns {Duplex}
 */
export function normaliseSocket(socket) {
  if (!socket || typeof socket !== 'object') {
    throw new ConfigError(
      codes.CONFIG_INVALID,
      `connect must return a socket object, got ${describe(socket)}`,
    );
  }
  const { readable, writable } = socket;
  if (!readable || typeof readable.getReader !== 'function') {
    throw new ConfigError(codes.CONFIG_INVALID, 'socket has no ReadableStream `readable`');
  }
  if (!writable || typeof writable.getWriter !== 'function') {
    throw new ConfigError(codes.CONFIG_INVALID, 'socket has no WritableStream `writable`');
  }
  return {
    readable,
    writable,
    opened: socket.opened,
    close: () => socket.close?.(),
  };
}

/**
 * Wrap a ConnectFn so every socket it returns is flattened by normaliseSocket. Useful when the
 * factory comes from a runtime whose sockets are host objects rather than plain records.
 * @param {ConnectFn} connect
 * @returns {ConnectFn}
 */
export function normalisingConnect(connect) {
  if (!isConnectFn(connect)) {
    throw new ConfigError(codes.CONFIG_INVALID, `connect must be a function, got ${describe(connect)}`);
  }
  return (addr, opts) => normaliseSocket(connect(addr, opts));
}

/** The default importer: a dynamic import a bundler cannot see through. See the header caveat. */
function defaultImport(specifier) {
  return import(specifier);
}

/** A short, safe rendering of a bad argument for an error message. */
function describe(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'an array';
  const t = typeof value;
  return t === 'object' ? 'an object' : t === 'string' ? JSON.stringify(value) : t;
}
