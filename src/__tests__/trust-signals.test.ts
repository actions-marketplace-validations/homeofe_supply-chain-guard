import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { detectTrustSignals } from "../trust-signals.js";

describe("Trust Signals", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(process.env.TEMP ?? "/tmp", "scg-trust-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should detect SECURITY.md", () => {
    fs.writeFileSync(path.join(tmpDir, "SECURITY.md"), "# Security\nReport to...");
    const signals = detectTrustSignals(tmpDir);
    expect(signals.some((f) => f.rule === "TRUST_SECURITY_POLICY_PRESENT")).toBe(true);
  });

  it("should flag missing SECURITY.md", () => {
    const signals = detectTrustSignals(tmpDir);
    expect(signals.some((f) => f.rule === "REPO_SECURITY_POLICY_ABSENT")).toBe(true);
  });

  it("should detect CODEOWNERS", () => {
    fs.mkdirSync(path.join(tmpDir, ".github"), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, ".github", "CODEOWNERS"), "* @team");
    const signals = detectTrustSignals(tmpDir);
    expect(signals.some((f) => f.rule === "TRUST_CODEOWNERS_PRESENT")).toBe(true);
  });

  it("should detect LICENSE", () => {
    fs.writeFileSync(path.join(tmpDir, "LICENSE"), "MIT License...");
    const signals = detectTrustSignals(tmpDir);
    expect(signals.some((f) => f.rule === "TRUST_LICENSE_PRESENT")).toBe(true);
  });

  it("should detect package.json with repository", () => {
    fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({
      name: "test", repository: { url: "https://github.com/test/test" },
    }));
    const signals = detectTrustSignals(tmpDir);
    expect(signals.some((f) => f.rule === "TRUST_REPO_LINKED")).toBe(true);
  });

  it("should detect lockfile", () => {
    fs.writeFileSync(path.join(tmpDir, "package-lock.json"), "{}");
    const signals = detectTrustSignals(tmpDir);
    expect(signals.some((f) => f.rule === "TRUST_LOCKFILE_PRESENT")).toBe(true);
  });

  it("should return all info severity", () => {
    const signals = detectTrustSignals(tmpDir);
    for (const s of signals) {
      expect(s.severity).toBe("info");
    }
  });
});
