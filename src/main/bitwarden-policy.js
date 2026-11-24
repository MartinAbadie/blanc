'use strict';

// Pure policy for the Bitwarden integration. No Electron, no child process:
// URI matching stays directly unit-testable. It deliberately reuses the
// 1Password matcher (`websiteMatch` / `rankMatches`) so both password managers
// share one definition of "which saved site may fill this page", including the
// one-way subdomain rule and the refusal to guess registrable domains.

const { AUTOFILL, parseWebUrl } = require('./onepassword-policy');

// Bitwarden's per-URI match detection (`login.uris[].match`). null/undefined
// means "use the account default", which Bitwarden defines as Domain.
const URI_MATCH = Object.freeze({
  DOMAIN: 0,
  HOST: 1,
  STARTS_WITH: 2,
  EXACT: 3,
  REGEX: 4,
  NEVER: 5,
});

function sameDocumentTarget(stored, page) {
  return stored.protocol === page.protocol
    && stored.host.toLowerCase() === page.host.toLowerCase();
}

function withoutTrailingSlash(pathname) {
  return pathname.length > 1 && pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
}

/** Translate one Bitwarden URI into the website shape `rankMatches` expects.
 * Anything this prototype cannot honor exactly fails closed as `Never`:
 * regular expressions (a stored pattern is attacker-influenced input in a
 * shared organization vault), the Never setting, and unknown future values. */
function toWebsite(uri, pageUrl) {
  const url = typeof uri?.uri === 'string' ? uri.uri.slice(0, 2048) : '';
  const never = { url, autofillBehavior: AUTOFILL.NEVER };
  const page = parseWebUrl(pageUrl);
  const stored = parseWebUrl(url, { defaultProtocol: page?.protocol });
  if (!page || !stored) return never;
  const match = uri.match === null || uri.match === undefined ? URI_MATCH.DOMAIN : uri.match;

  if (match === URI_MATCH.DOMAIN) return { url, autofillBehavior: AUTOFILL.ANYWHERE };
  if (match === URI_MATCH.HOST) return { url, autofillBehavior: AUTOFILL.EXACT };
  if (match === URI_MATCH.STARTS_WITH) {
    const prefix = withoutTrailingSlash(stored.pathname);
    const path = page.pathname;
    const covered = sameDocumentTarget(stored, page)
      && (prefix === '/' || path === prefix || path.startsWith(`${prefix}/`));
    return covered ? { url, autofillBehavior: AUTOFILL.EXACT } : never;
  }
  if (match === URI_MATCH.EXACT) {
    const covered = sameDocumentTarget(stored, page)
      && withoutTrailingSlash(stored.pathname) === withoutTrailingSlash(page.pathname)
      && stored.search === page.search;
    return covered ? { url, autofillBehavior: AUTOFILL.EXACT } : never;
  }
  return never; // REGEX, NEVER and any value Bitwarden adds later
}

function websitesFor(uris, pageUrl) {
  return (Array.isArray(uris) ? uris : []).slice(0, 50).map((uri) => toWebsite(uri, pageUrl));
}

module.exports = { URI_MATCH, toWebsite, websitesFor };
