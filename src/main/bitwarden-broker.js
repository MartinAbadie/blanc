'use strict';

// Runs only in an Electron utility process. This is the sole module allowed to
// start the Bitwarden CLI (`bw`), hold its session key, or see decrypted vault
// items. Replies are bounded projections; CLI failures are reduced to fixed
// codes before crossing back to Blanc's main process, so no stderr text, item
// name, or secret ever leaves this file by way of an error.
//
// Unlike 1Password's DesktopAuth, `bw` has no app-mediated approval: the user
// unlocks the vault with the master password. The password is passed to the
// child only through its environment (never argv), the resulting session key
// lives only in this process's memory, and neither is logged or persisted.

const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { rankMatches, parseWebUrl } = require('./onepassword-policy');
const { websitesFor } = require('./bitwarden-policy');

const CLI_TIMEOUT_MS = 20000;
const CLI_MAX_BUFFER = 16 * 1024 * 1024;
const LOGIN_TYPE = 1; // Bitwarden cipher type: Login
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

let session = null; // BW_SESSION key; memory only
let runner = runBw;

/** Fixed install locations, like onepassword-app.js: PATH is never searched,
 * so a writable directory earlier on PATH cannot substitute its own `bw`.
 * npm's `bw.cmd` shim is excluded on purpose (a batch file cannot be started
 * without a shell). BLANC_BITWARDEN_CLI is a development override and must be
 * an absolute path. */
function candidateBinaries({ platform = process.platform, env = process.env } = {}) {
  const override = env.BLANC_BITWARDEN_CLI;
  const list = [];
  if (typeof override === 'string' && path.isAbsolute(override)) list.push(override);
  if (platform === 'win32') {
    const local = env.LOCALAPPDATA;
    const home = env.USERPROFILE;
    if (local) list.push(path.win32.join(local, 'Microsoft', 'WinGet', 'Links', 'bw.exe'));
    if (home) list.push(path.win32.join(home, 'scoop', 'shims', 'bw.exe'));
    list.push('C:\\ProgramData\\chocolatey\\bin\\bw.exe');
  } else if (platform === 'darwin') {
    list.push('/opt/homebrew/bin/bw', '/usr/local/bin/bw');
  } else {
    list.push('/usr/local/bin/bw', '/usr/bin/bw', '/snap/bin/bw');
    if (env.HOME) list.push(path.posix.join(env.HOME, '.local', 'bin', 'bw'));
  }
  return list;
}

function findBinary(options = {}, exists = fs.existsSync) {
  return candidateBinaries(options).find((candidate) => exists(candidate)) || null;
}

function childEnv(extra) {
  const keep = ['PATH', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'SystemRoot',
    'TMPDIR', 'TEMP', 'TMP', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_RUNTIME_DIR',
    'BITWARDENCLI_APPDATA_DIR'];
  const env = {};
  for (const key of keep) if (process.env[key] !== undefined) env[key] = process.env[key];
  env.BW_NOINTERACTION = 'true';
  env.BW_QUIET = 'true';
  return { ...env, ...extra };
}

function runBw(args, extraEnv) {
  const binary = findBinary();
  if (!binary) {
    return Promise.reject(Object.assign(new Error('bw not found'), { code: 'cli-unavailable' }));
  }
  return new Promise((resolve, reject) => {
    execFile(binary, args, {
      env: childEnv(extraEnv),
      timeout: CLI_TIMEOUT_MS,
      maxBuffer: CLI_MAX_BUFFER,
      windowsHide: true,
      shell: false,
    }, (error, stdout, stderr) => {
      if (error) {
        reject(Object.assign(new Error(String(stderr || error.message || '')),
          { code: error.killed ? 'timeout' : error.code, cliExit: true }));
      } else {
        resolve(String(stdout));
      }
    });
  });
}

function validPassword(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 1024;
}

function validId(value) {
  return typeof value === 'string' && GUID.test(value);
}

function fixedErrorCode(error) {
  if (error?.code === 'selection-changed') return 'selection-changed';
  if (error?.code === 'invalid-request') return 'invalid-request';
  if (error?.code === 'cli-unavailable' || error?.code === 'ENOENT'
      || error?.code === 'EACCES') return 'cli-unavailable';
  if (error?.code === 'timeout') return 'timeout';
  const message = String(error?.message || '');
  if (/invalid master password|username or password is incorrect/i.test(message)) {
    return 'not-authorized';
  }
  if (/not logged in|unauthenticated|you are not logged in/i.test(message)) return 'unauthenticated';
  if (/vault is locked|invalid session|session key is invalid|locked/i.test(message)) {
    return 'locked';
  }
  return 'cli-error';
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    throw Object.assign(new Error('unparseable cli output'), { code: 'cli-error' });
  }
}

function requireSession() {
  if (!session) throw Object.assign(new Error('vault is locked'), { code: 'locked-local' });
  return { BW_SESSION: session };
}

function lockedCode(error) {
  // A missing local session surfaces as the same fixed `locked` code.
  return error?.code === 'locked-local' ? 'locked' : null;
}

async function status() {
  const out = parseJson(await runner(['status'], session ? { BW_SESSION: session } : {}));
  const state = out?.status;
  if (state === 'unauthenticated') return { state: 'unauthenticated' };
  // `bw status` only reports `unlocked` when it was handed a valid session.
  return { state: state === 'unlocked' && session ? 'unlocked' : 'locked' };
}

async function unlock({ password }) {
  if (!validPassword(password)) {
    throw Object.assign(new Error('invalid password'), { code: 'invalid-request' });
  }
  const key = (await runner(['unlock', '--passwordenv', 'BLANC_BW_PASSWORD', '--raw'],
    { BLANC_BW_PASSWORD: password })).trim();
  if (!key) throw Object.assign(new Error('empty session'), { code: 'cli-error' });
  session = key;
  return { ok: true };
}

function lock() {
  session = null;
  return { ok: true };
}

function projectCandidate(item) {
  const uris = item?.login?.uris;
  return {
    itemId: item.id,
    vaultName: '',
    vaultId: '',
    title: typeof item.name === 'string' ? item.name.slice(0, 200) : '',
    // `websites` is rewritten per page by websitesFor() below.
    websites: uris,
    updatedAt: typeof item.revisionDate === 'string' ? item.revisionDate : '',
    username: typeof item.login?.username === 'string' ? item.login.username.slice(0, 320) : '',
    itemVersion: typeof item.revisionDate === 'string' ? item.revisionDate : null,
  };
}

async function findLogins({ pageUrl }) {
  // A scheme-less value such as `--help` parses as https://--help, so pass the
  // normalized href (always http(s)://…), never the caller's raw text, as argv.
  const parsed = parseWebUrl(pageUrl);
  if (!parsed) {
    throw Object.assign(new Error('invalid page url'), { code: 'invalid-request' });
  }
  const env = requireSession();
  let items = parseJson(await runner(['list', 'items', '--url', parsed.href], env));
  if (!Array.isArray(items)) throw Object.assign(new Error('bad list'), { code: 'cli-error' });
  const candidates = [];
  for (const item of items) {
    if (item?.type !== LOGIN_TYPE || !validId(item.id) || item.deletedDate) continue;
    const projected = projectCandidate(item);
    // Re-apply Blanc's own matcher: `--url` uses Bitwarden's looser base-domain
    // rule, which would also offer siblings of the current subdomain.
    candidates.push({ ...projected, websites: websitesFor(projected.websites, pageUrl) });
  }
  items = null; // drop decrypted items, including passwords, right away
  const ranked = rankMatches(candidates, pageUrl);
  return {
    candidates: ranked.kept.map(({ websites, tier, host, ...safe }) => safe),
    truncated: ranked.truncated,
  };
}

async function revealCredential({
  itemId, expectedItemVersion, includeUsername, includePassword,
}) {
  if (!validId(itemId)) {
    throw Object.assign(new Error('invalid ref'), { code: 'invalid-request' });
  }
  if (typeof includeUsername !== 'boolean' || typeof includePassword !== 'boolean'
      || (!includeUsername && !includePassword)) {
    throw Object.assign(new Error('invalid field request'), { code: 'invalid-request' });
  }
  if (expectedItemVersion !== null && expectedItemVersion !== undefined
      && typeof expectedItemVersion !== 'string') {
    throw Object.assign(new Error('invalid item version'), { code: 'invalid-request' });
  }
  let item = parseJson(await runner(['get', 'item', itemId], requireSession()));
  try {
    if (item?.id !== itemId || item?.type !== LOGIN_TYPE) {
      throw Object.assign(new Error('not a login'), { code: 'cli-error' });
    }
    if (expectedItemVersion !== null && expectedItemVersion !== undefined
        && item.revisionDate !== expectedItemVersion) {
      throw Object.assign(new Error('selected item changed'), { code: 'selection-changed' });
    }
    const login = item.login || {};
    return {
      username: includeUsername && typeof login.username === 'string' ? login.username : null,
      password: includePassword && typeof login.password === 'string' ? login.password : null,
    };
  } finally {
    item = null;
  }
}

async function dispatch(method, payload) {
  if (method === 'status') return status();
  if (method === 'unlock') return unlock(payload ?? {});
  if (method === 'lock') return lock();
  if (method === 'find-logins') return findLogins(payload ?? {});
  if (method === 'reveal-credential') return revealCredential(payload ?? {});
  throw Object.assign(new Error('unknown method'), { code: 'invalid-request' });
}

async function handleMessage(message, send) {
  const id = message?.id;
  if (!Number.isSafeInteger(id) || id < 1) return;
  try {
    send({ id, ok: true, value: await dispatch(message.method, message.payload) });
  } catch (error) {
    send({ id, ok: false, error: lockedCode(error) || fixedErrorCode(error) });
  }
}

if (process.parentPort) {
  process.parentPort.on('message', (event) => {
    handleMessage(event.data, (reply) => process.parentPort.postMessage(reply));
  });
}

module.exports = {
  candidateBinaries,
  findBinary,
  fixedErrorCode,
  dispatch,
  handleMessage,
  // Test seams: never used by shipping code.
  _setRunner: (fn) => { runner = fn || runBw; },
  _resetSession: () => { session = null; },
};
