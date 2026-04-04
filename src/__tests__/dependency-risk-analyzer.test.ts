import { describe, it, expect } from "vitest";
import { analyzeDependencyRisks, levenshtein } from "../dependency-risk-analyzer.js";

describe("Dependency Risk Analyzer", () => {
  describe("levenshtein", () => {
    it("should return 0 for identical strings", () => {
      expect(levenshtein("lodash", "lodash")).toBe(0);
    });

    it("should return 1 for single edit", () => {
      expect(levenshtein("lodash", "lodas")).toBe(1);
      expect(levenshtein("lodash", "1odash")).toBe(1);
    });

    it("should return 2 for two edits", () => {
      expect(levenshtein("lodash", "l0das")).toBe(2);
    });

    it("should handle empty strings", () => {
      expect(levenshtein("", "abc")).toBe(3);
      expect(levenshtein("abc", "")).toBe(3);
    });
  });

  describe("analyzeDependencyRisks", () => {
    it("should detect typosquatted package names", () => {
      const findings = analyzeDependencyRisks(
        { "lodas": "^4.17.0", "react": "^18.0.0" },
        "package.json",
      );
      expect(findings.some((f) => f.rule === "TYPOSQUAT_LEVENSHTEIN")).toBe(true);
      expect(findings.find((f) => f.rule === "TYPOSQUAT_LEVENSHTEIN")?.description).toContain("lodash");
    });

    it("should detect similar dependency names", () => {
      const findings = analyzeDependencyRisks(
        { "expres": "^4.0.0", "express": "^4.18.0" },
        "package.json",
      );
      expect(findings.some((f) => f.rule === "TYPOSQUAT_SIMILAR_TO_DEP")).toBe(true);
    });

    it("should detect internal-looking scoped packages", () => {
      const findings = analyzeDependencyRisks(
        { "@mycompany/internal-auth": "^1.0.0" },
        "package.json",
      );
      expect(findings.some((f) => f.rule === "DEP_INTERNAL_NAME_PUBLIC")).toBe(true);
    });

    it("should not flag legitimate popular packages", () => {
      const findings = analyzeDependencyRisks(
        { "lodash": "^4.17.0", "express": "^4.18.0", "react": "^18.0.0" },
        "package.json",
      );
      expect(findings.some((f) => f.rule === "TYPOSQUAT_LEVENSHTEIN")).toBe(false);
    });

    it("should not flag very different names", () => {
      const findings = analyzeDependencyRisks(
        { "totally-different-name": "^1.0.0" },
        "package.json",
      );
      expect(findings).toHaveLength(0);
    });

    it("should include confidence scores", () => {
      const findings = analyzeDependencyRisks(
        { "axio": "^1.0.0" },
        "package.json",
      );
      const f = findings.find((f) => f.rule === "TYPOSQUAT_LEVENSHTEIN");
      if (f) {
        expect(f.confidence).toBeGreaterThan(0);
        expect(f.confidence).toBeLessThanOrEqual(1);
      }
    });
  });
});
