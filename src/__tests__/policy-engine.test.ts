import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { applyPolicy, applyBaseline, saveBaseline, loadPolicyConfig } from "../policy-engine.js";
import type { Finding, PolicyConfig } from "../types.js";

function makeFinding(rule: string, severity: "critical" | "high" | "medium" = "high", file?: string): Finding {
  return { rule, description: `Finding: ${rule}`, severity, file, recommendation: "Fix it" };
}

describe("Policy Engine", () => {
  describe("applyPolicy", () => {
    it("should disable specified rules", () => {
      const findings = [makeFinding("EVAL_ATOB", "critical"), makeFinding("HEX_ARRAY", "medium")];
      const policy: PolicyConfig = { rules: { disable: ["HEX_ARRAY"] } };
      const result = applyPolicy(findings, policy);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].rule).toBe("EVAL_ATOB");
      expect(result.suppressedCount).toBe(1);
    });

    it("should override severity", () => {
      const findings = [makeFinding("GHA_UNPINNED_ACTION", "high")];
      const policy: PolicyConfig = { rules: { severityOverrides: { GHA_UNPINNED_ACTION: "medium" } } };
      const result = applyPolicy(findings, policy);
      expect(result.findings[0].severity).toBe("medium");
    });

    it("should suppress specified rules", () => {
      const findings = [makeFinding("RELEASE_EXE_ARTIFACT", "critical")];
      const policy: PolicyConfig = { suppress: [{ rule: "RELEASE_EXE_ARTIFACT", reason: "Legit installer" }] };
      const result = applyPolicy(findings, policy);
      expect(result.findings).toHaveLength(0);
      expect(result.suppressedCount).toBe(1);
    });

    it("should allowlist packages for typosquat checks", () => {
      const findings = [{ ...makeFinding("TYPOSQUAT_LEVENSHTEIN"), description: 'Dependency "internal-utils" is...' }];
      const policy: PolicyConfig = { allowlist: { packages: ["internal-utils"] } };
      const result = applyPolicy(findings, policy);
      expect(result.findings).toHaveLength(0);
    });

    it("should pass through findings with no matching policy", () => {
      const findings = [makeFinding("EVAL_ATOB", "critical")];
      const policy: PolicyConfig = { rules: { disable: ["UNRELATED_RULE"] } };
      const result = applyPolicy(findings, policy);
      expect(result.findings).toHaveLength(1);
    });

    it("should handle empty policy", () => {
      const findings = [makeFinding("EVAL_ATOB", "critical")];
      const result = applyPolicy(findings, {});
      expect(result.findings).toHaveLength(1);
      expect(result.suppressedCount).toBe(0);
    });
  });

  describe("Baseline system", () => {
    let tmpDir: string;
    let baselinePath: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(process.env.TEMP ?? "/tmp", "scg-bl-"));
      baselinePath = path.join(tmpDir, ".scg-baseline.json");
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it("should save baseline", () => {
      const findings = [makeFinding("EVAL_ATOB", "critical", "src/index.js")];
      saveBaseline(findings, baselinePath);
      expect(fs.existsSync(baselinePath)).toBe(true);
      const saved = JSON.parse(fs.readFileSync(baselinePath, "utf-8"));
      expect(saved).toHaveLength(1);
      expect(saved[0].rule).toBe("EVAL_ATOB");
    });

    it("should filter out baseline findings", () => {
      const findings = [
        makeFinding("EVAL_ATOB", "critical", "src/index.js"),
        makeFinding("HEX_ARRAY", "medium", "src/data.js"),
      ];
      saveBaseline(findings, baselinePath);

      const newFindings = [
        makeFinding("EVAL_ATOB", "critical", "src/index.js"), // in baseline
        makeFinding("NEW_RULE", "high", "src/new.js"),        // not in baseline
      ];
      const result = applyBaseline(newFindings, baselinePath);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].rule).toBe("NEW_RULE");
      expect(result.suppressedCount).toBe(1);
    });

    it("should return all findings when no baseline exists", () => {
      const findings = [makeFinding("EVAL_ATOB", "critical")];
      const result = applyBaseline(findings, "/nonexistent/path");
      expect(result.findings).toHaveLength(1);
      expect(result.suppressedCount).toBe(0);
    });
  });

  describe("loadPolicyConfig", () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(process.env.TEMP ?? "/tmp", "scg-cfg-"));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it("should load .supply-chain-guard.yml", () => {
      fs.writeFileSync(path.join(tmpDir, ".supply-chain-guard.yml"), [
        "rules:",
        "  disable:",
        "    - HEX_ARRAY",
        "    - CHARCODE_OBFUSCATION",
        "  severityOverrides:",
        "    GHA_UNPINNED_ACTION: medium",
        "allowlist:",
        "  packages:",
        "    - internal-utils",
      ].join("\n"));

      const config = loadPolicyConfig(tmpDir);
      expect(config).not.toBeNull();
      expect(config!.rules?.disable).toContain("HEX_ARRAY");
      expect(config!.rules?.severityOverrides?.GHA_UNPINNED_ACTION).toBe("medium");
      expect(config!.allowlist?.packages).toContain("internal-utils");
    });

    it("should return null when no config exists", () => {
      expect(loadPolicyConfig(tmpDir)).toBeNull();
    });
  });
});
