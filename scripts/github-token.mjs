/**
 * GitHub Actions GITHUB_TOKEN is an opaque installation bearer. GitHub's 2026
 * stateless format can be longer than 512 characters and contain JWT dots.
 * Enforce only safe printable ASCII for an HTTP Authorization header; the
 * provider, not a local token-shape regex, proves its authentication/rights.
 * Never log, parse, decode, store, inspect or fingerprint the token itself.
 */
export function isHeaderSafeGitHubToken(token) {
  return typeof token === 'string' && token.length > 0 &&
    !/[^\x21-\x7e]/.test(token);
}
