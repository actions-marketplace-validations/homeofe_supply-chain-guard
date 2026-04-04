import { describe, it, expect } from "vitest";
import { C2_EXTENDED_PATTERNS, SECRETS_PATTERNS } from "../patterns.js";

function matchPattern(pattern: string, input: string): boolean {
  return new RegExp(pattern, "i").test(input);
}

describe("C2 Extended Patterns", () => {
  it("should detect DNS-over-HTTPS resolver", () => {
    const p = C2_EXTENDED_PATTERNS.find((p) => p.rule === "C2_DOH_RESOLVER");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'fetch("https://cloudflare-dns.com/dns-query?name=evil.com")')).toBe(true);
    expect(matchPattern(p!.pattern, 'fetch("https://dns.google/dns-query")')).toBe(true);
  });

  it("should detect GitHub Gist dead-drop", () => {
    const p = C2_EXTENDED_PATTERNS.find((p) => p.rule === "DEAD_DROP_GIST");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "https://gist.githubusercontent.com/user/abc123def456")).toBe(true);
  });

  it("should detect dynamic WebSocket URL", () => {
    const p = C2_EXTENDED_PATTERNS.find((p) => p.rule === "C2_WEBSOCKET_DYNAMIC");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'new WebSocket(atob("d3NzOi8vZXZpbC5jb20="))')).toBe(true);
    expect(matchPattern(p!.pattern, "new WebSocket(`wss://${host}`)")).toBe(true);
  });
});

describe("Secrets Patterns", () => {
  it("should detect AWS access keys", () => {
    const p = SECRETS_PATTERNS.find((p) => p.rule === "SECRETS_AWS_KEY");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "AKIAIOSFODNN7EXAMPLE")).toBe(true);
    expect(matchPattern(p!.pattern, "ASIAJEXAMPLEKEY12345")).toBe(true);
  });

  it("should detect GitHub tokens", () => {
    const p = SECRETS_PATTERNS.find((p) => p.rule === "SECRETS_GITHUB_TOKEN");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234")).toBe(true);
    expect(matchPattern(p!.pattern, "github_pat_ABCDEFGHIJKLMNOPQRSTUVWx")).toBe(true);
  });

  it("should detect private keys", () => {
    const p = SECRETS_PATTERNS.find((p) => p.rule === "SECRETS_PRIVATE_KEY");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "-----BEGIN RSA PRIVATE KEY-----")).toBe(true);
    expect(matchPattern(p!.pattern, "-----BEGIN OPENSSH PRIVATE KEY-----")).toBe(true);
  });

  it("should detect SSH key reading", () => {
    const p = SECRETS_PATTERNS.find((p) => p.rule === "SECRETS_SSH_KEY_READ");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'readFileSync("~/.ssh/id_rsa")')).toBe(true);
  });

  it("should detect npm tokens", () => {
    const p = SECRETS_PATTERNS.find((p) => p.rule === "SECRETS_NPM_TOKEN");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12")).toBe(true);
  });

  it("should detect generic API keys", () => {
    const p = SECRETS_PATTERNS.find((p) => p.rule === "SECRETS_GENERIC_API_KEY");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'api_key = "sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZab"')).toBe(true);
  });

  it("should not match short random strings", () => {
    const p = SECRETS_PATTERNS.find((p) => p.rule === "SECRETS_AWS_KEY");
    expect(matchPattern(p!.pattern, "AKIA")).toBe(false); // Too short
  });
});
