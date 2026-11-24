'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  candidateBinaries,
  findBinary,
  fixedErrorCode,
  dispatch,
  handleMessage,
  _setRunner,
  _resetSession,
} = require('../../src/main/bitwarden-broker');
const { URI_MATCH, websitesFor } = require('../../src/main/bitwarden-policy');
const { rankMatches } = require('../../src/main/onepassword-policy');

const ID_A = '11111111-1111-4111-8111-111111111111';
const ID_B = '22222222-2222-4222-8222-222222222222';
const ID_C = '33333333-3333-4333-8333-333333333333';

const login = (id, name, uris, extra = {}) => ({
  id,
  type: 1,
  name,
  revisionDate: '2026-11-01T10:00:00.000Z',
  login: { username: `${name}@example.test`, password: `pw-${name}`, uris, ...extra },
});

function installRunner(handler) {
  const calls = [];
  _setRunner(async (args, env) => {
    calls.push({ args, env });
    return handler(args, env);
  });
  return calls;
}

test.afterEach(() => {
  _setRunner(null);
  _resetSession();
});

async function unlocked() {
  installRunner(() => 'session-key\n');
  await dispatch('unlock', { password: 'correct horse' });
}

test('URI match types map to the shared matcher and unsupported ones fail closed', () => {
  const page = 'https://app.example.com/account/login?next=1';
  const matches = (uri, match) => rankMatches(
    [{ vaultId: '', itemId: 'x', title: 't', vaultName: '', updatedAt: '',
      websites: websitesFor([{ uri, match }], page) }],
    page,
  ).kept.length === 1;

  // Domain (and the account default, null): the saved host and descendants only.
  assert.ok(matches('example.com', null));
  assert.ok(matches('app.example.com', URI_MATCH.DOMAIN));
  assert.ok(!matches('other.example.com', URI_MATCH.DOMAIN), 'siblings are not guessed');
  assert.ok(!matches('example.com.evil.test', URI_MATCH.DOMAIN));
  // Host: hostname and port must agree.
  assert.ok(matches('https://app.example.com', URI_MATCH.HOST));
  assert.ok(!matches('https://app.example.com:8443', URI_MATCH.HOST));
  assert.ok(!matches('https://example.com', URI_MATCH.HOST));
  // StartsWith: path prefix on a segment boundary, same origin.
  assert.ok(matches('https://app.example.com/account', URI_MATCH.STARTS_WITH));
  assert.ok(!matches('https://app.example.com/acc', URI_MATCH.STARTS_WITH));
  assert.ok(!matches('http://app.example.com/account', URI_MATCH.STARTS_WITH));
  // Exact: same path and query.
  assert.ok(matches('https://app.example.com/account/login?next=1', URI_MATCH.EXACT));
  assert.ok(!matches('https://app.example.com/account/login', URI_MATCH.EXACT));
  // Regex, Never and unknown future values never match.
  assert.ok(!matches('.*', URI_MATCH.REGEX));
  assert.ok(!matches('app.example.com', URI_MATCH.NEVER));
  assert.ok(!matches('app.example.com', 99));
});

test('binary lookup uses fixed locations, never PATH, and skips npm .cmd shims', () => {
  const linux = candidateBinaries({ platform: 'linux', env: { HOME: '/home/u', PATH: '/tmp/evil' } });
  assert.deepEqual(linux, ['/usr/local/bin/bw', '/usr/bin/bw', '/snap/bin/bw', '/home/u/.local/bin/bw']);
  const windows = candidateBinaries({
    platform: 'win32', env: { LOCALAPPDATA: 'C:\\Users\\u\\AppData\\Local', USERPROFILE: 'C:\\Users\\u' },
  });
  assert.ok(windows.every((candidate) => candidate.endsWith('bw.exe')));
  // Only an absolute development override is honored.
  assert.equal(candidateBinaries({ platform: 'linux', env: { BLANC_BITWARDEN_CLI: 'bw' } })[0],
    '/usr/local/bin/bw');
  assert.equal(candidateBinaries({ platform: 'linux', env: { BLANC_BITWARDEN_CLI: '/opt/bw' } })[0],
    '/opt/bw');
  assert.equal(findBinary({ platform: 'linux', env: {} }, (p) => p === '/usr/bin/bw'), '/usr/bin/bw');
  assert.equal(findBinary({ platform: 'linux', env: {} }, () => false), null);
});

test('unlock passes the master password only through the child environment', async () => {
  const calls = installRunner(() => '  s3cret-session  \n');
  assert.deepEqual(await dispatch('unlock', { password: 'hunter2' }), { ok: true });
  assert.equal(JSON.stringify(calls[0].args).includes('hunter2'), false, 'never in argv');
  assert.equal(calls[0].env.BLANC_BW_PASSWORD, 'hunter2');
  // The session key goes to later calls via BW_SESSION and is never returned.
  installRunner(() => '[]');
  const later = [];
  _setRunner(async (args, env) => { later.push(env); return '[]'; });
  const result = await dispatch('find-logins', { pageUrl: 'https://example.com/' });
  assert.equal(later[0].BW_SESSION, 's3cret-session');
  assert.equal(JSON.stringify(result).includes('s3cret-session'), false);
});

test('unlock rejects empty or oversized passwords before starting the CLI', async () => {
  const calls = installRunner(() => 'x');
  await assert.rejects(() => dispatch('unlock', { password: '' }), { code: 'invalid-request' });
  await assert.rejects(() => dispatch('unlock', { password: 'x'.repeat(1025) }), { code: 'invalid-request' });
  await assert.rejects(() => dispatch('unlock', {}), { code: 'invalid-request' });
  assert.equal(calls.length, 0);
});

test('find-logins and reveal fail with `locked` until unlocked, and lock forgets the key', async () => {
  const calls = installRunner(() => '[]');
  const replies = [];
  await handleMessage({ id: 1, method: 'find-logins', payload: { pageUrl: 'https://example.com/' } },
    (reply) => replies.push(reply));
  await handleMessage({ id: 2, method: 'reveal-credential',
    payload: { itemId: ID_A, includeUsername: true, includePassword: true } },
  (reply) => replies.push(reply));
  assert.deepEqual(replies, [{ id: 1, ok: false, error: 'locked' }, { id: 2, ok: false, error: 'locked' }]);
  assert.equal(calls.length, 0, 'the CLI is not started without a session');

  await unlocked();
  await dispatch('lock');
  await assert.rejects(() => dispatch('find-logins', { pageUrl: 'https://example.com/' }),
    { code: 'locked-local' });
});

test('find-logins keeps only matching, live Login items and projects bounded fields', async () => {
  await unlocked();
  const calls = installRunner(() => JSON.stringify([
    login(ID_A, 'alice', [{ uri: 'https://example.com', match: null }]),
    login(ID_B, 'sibling', [{ uri: 'https://other.example.com', match: null }]),
    { ...login(ID_C, 'trashed', [{ uri: 'example.com' }]), deletedDate: '2026-11-02T00:00:00Z' },
    { id: '44444444-4444-4444-8444-444444444444', type: 2, name: 'note' },
    login('not-a-guid', 'bad-id', [{ uri: 'example.com' }]),
  ]));
  const result = await dispatch('find-logins', { pageUrl: 'https://login.example.com/' });
  assert.deepEqual(calls[0].args, ['list', 'items', '--url', 'https://login.example.com/']);
  assert.deepEqual(result.candidates.map((c) => c.itemId), [ID_A]);
  assert.equal(result.truncated, 0);
  const [candidate] = result.candidates;
  assert.equal(candidate.username, 'alice@example.test');
  assert.equal(candidate.itemVersion, '2026-11-01T10:00:00.000Z');
  assert.equal(JSON.stringify(result).includes('pw-alice'), false, 'no password in a listing');
  assert.equal('websites' in candidate, false);
});

test('find-logins rejects non-web page URLs without starting the CLI', async () => {
  await unlocked();
  const calls = installRunner(() => '[]');
  for (const pageUrl of ['file:///etc/passwd', 'javascript:alert(1)', '', null]) {
    await assert.rejects(() => dispatch('find-logins', { pageUrl }), { code: 'invalid-request' });
  }
  assert.equal(calls.length, 0);
  // Option-shaped text must reach the CLI only as a normalized http(s) URL.
  await dispatch('find-logins', { pageUrl: '--help' });
  assert.match(calls[0].args[3], /^https:\/\//);
});

test('reveal returns only the requested built-ins and aborts when the item changed', async () => {
  await unlocked();
  installRunner(() => JSON.stringify(login(ID_A, 'alice', [{ uri: 'example.com' }])));
  assert.deepEqual(
    await dispatch('reveal-credential', {
      itemId: ID_A, expectedItemVersion: '2026-11-01T10:00:00.000Z',
      includeUsername: false, includePassword: true,
    }),
    { username: null, password: 'pw-alice' },
  );
  await assert.rejects(() => dispatch('reveal-credential', {
    itemId: ID_A, expectedItemVersion: '2020-01-01T00:00:00.000Z',
    includeUsername: true, includePassword: true,
  }), { code: 'selection-changed' });
});

test('reveal validates its request before starting the CLI', async () => {
  await unlocked();
  const calls = installRunner(() => '{}');
  const base = { itemId: ID_A, includeUsername: true, includePassword: true };
  for (const bad of [
    { ...base, itemId: '--help' },
    { ...base, itemId: '../etc' },
    { ...base, includeUsername: false, includePassword: false },
    { ...base, includePassword: 'yes' },
    { ...base, expectedItemVersion: 3 },
  ]) {
    await assert.rejects(() => dispatch('reveal-credential', bad), { code: 'invalid-request' });
  }
  assert.equal(calls.length, 0);
});

test('reveal refuses a response for a different item or a non-login', async () => {
  await unlocked();
  installRunner(() => JSON.stringify(login(ID_B, 'other', [])));
  await assert.rejects(() => dispatch('reveal-credential',
    { itemId: ID_A, includeUsername: true, includePassword: true }), { code: 'cli-error' });
  installRunner(() => JSON.stringify({ id: ID_A, type: 2 }));
  await assert.rejects(() => dispatch('reveal-credential',
    { itemId: ID_A, includeUsername: true, includePassword: true }), { code: 'cli-error' });
});

test('CLI failures reduce to fixed codes that never carry stderr text', async () => {
  const cases = [
    [{ message: 'Invalid master password.' }, 'not-authorized'],
    [{ message: 'You are not logged in.' }, 'unauthenticated'],
    [{ message: 'Vault is locked.' }, 'locked'],
    [{ message: 'Session key is invalid.' }, 'locked'],
    [{ code: 'ENOENT', message: 'spawn bw ENOENT' }, 'cli-unavailable'],
    [{ code: 'timeout', message: '' }, 'timeout'],
    [{ message: 'secret-site.example vault item 1234 exploded' }, 'cli-error'],
  ];
  for (const [error, expected] of cases) {
    assert.equal(fixedErrorCode(Object.assign(new Error(error.message), error)), expected);
  }
  await unlocked();
  installRunner(() => { throw Object.assign(new Error('boom: hunter2 leaked'), { cliExit: true }); });
  const replies = [];
  await handleMessage({ id: 9, method: 'find-logins', payload: { pageUrl: 'https://example.com/' } },
    (reply) => replies.push(reply));
  assert.deepEqual(replies, [{ id: 9, ok: false, error: 'cli-error' }]);
});

test('unparseable CLI output is a fixed error, and bad messages are dropped or rejected', async () => {
  await unlocked();
  installRunner(() => 'not json');
  await assert.rejects(() => dispatch('find-logins', { pageUrl: 'https://example.com/' }),
    { code: 'cli-error' });
  const replies = [];
  await handleMessage({ method: 'status' }, (reply) => replies.push(reply));
  await handleMessage({ id: 0, method: 'status' }, (reply) => replies.push(reply));
  assert.deepEqual(replies, []);
  await handleMessage({ id: 3, method: 'rm -rf' }, (reply) => replies.push(reply));
  assert.deepEqual(replies, [{ id: 3, ok: false, error: 'invalid-request' }]);
});

test('status reports unlocked only when this process holds a session', async () => {
  installRunner(() => JSON.stringify({ status: 'unlocked' }));
  assert.deepEqual(await dispatch('status'), { state: 'locked' });
  await unlocked();
  installRunner(() => JSON.stringify({ status: 'unlocked' }));
  assert.deepEqual(await dispatch('status'), { state: 'unlocked' });
  installRunner(() => JSON.stringify({ status: 'unauthenticated' }));
  assert.deepEqual(await dispatch('status'), { state: 'unauthenticated' });
});
