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
export function isConnectFn(value: unknown): value is ConnectFn;
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
export function resolveConnect(options?: ResolveConnectOptions): Promise<ConnectFn>;
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
export function normaliseSocket(socket: Duplex): Duplex;
/**
 * Wrap a ConnectFn so every socket it returns is flattened by normaliseSocket. Useful when the
 * factory comes from a runtime whose sockets are host objects rather than plain records.
 * @param {ConnectFn} connect
 * @returns {ConnectFn}
 */
export function normalisingConnect(connect: ConnectFn): ConnectFn;
export type ConnectFn = import("./proxy/index.js").ConnectFn;
export type Duplex = import("./proxy/index.js").Duplex;
export type ResolveConnectOptions = {
    /**
     * an already-obtained socket factory. Checked first and returned
     * as-is, so the recommended path costs no import and cannot be defeated by a bundler.
     */
    connect?: import("./proxy/index.js").ConnectFn | undefined;
    /**
     * module specifiers to try, in order. The first module whose
     * `exportName` is callable wins.
     */
    specifiers?: string[] | undefined;
    /**
     * the importer. Defaults to a
     * dynamic `import()`; override it to hand the bundler a literal specifier.
     */
    importModule?: ((specifier: string) => Promise<object>) | undefined;
    /**
     * the export to read off each module. Default 'connect'.
     */
    exportName?: string | undefined;
};
