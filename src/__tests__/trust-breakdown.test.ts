import { describe, it, expect } from "vitest";
import { calculateTrustBreakdown } from "../trust-breakdown.js";
import type { Finding } from "../types.js";

function makeFinding(rule: string, severity: "critical" | "high" | "medium" | "low" = "high"): Finding {
  return { rule, description: "test", severity, recommendation: "test" };
}

describe("Trust Breakdown", () => {
  it("should return high scores for clean package", () => {
    const tb = calculateTrustBreakdown([], "clean-package", true);
    expect(tb.overallScore).toBeGreaterThan(80);
    expect(tb.publisherTrust.score).toBe(100);
    expect(tb.codeQuality.score).toBe(100);
    expect(tb.dependencyTrust.score).toBe(100);
    expect(tb.releaseProcess.score).toBe(100);
  });

  it("should penalize maintainer change", () => {
    const findings = [makeFinding("PUBLISH_MAINTAINER_CHANGE", "critical")];
    const tb = calculateTrustBreakdown(findings, "test", true);
    expect(tb.publisherTrust.score).toBeLessThan(70);
  });

  it("should penalize critical findings in code quality", () => {
    const findings = [
      makeFinding("EVAL_ATOB", "critical"),
      makeFinding("EVAL_BUFFER", "critical"),
    ];
    const tb = calculateTrustBreakdown(findings, "test", true);
    expect(tb.codeQuality.score).toBeLessThan(60);
  });

  it("should penalize known bad versions", () => {
    const findings = [makeFinding("IOC_KNOWN_BAD_VERSION", "critical")];
    const tb = calculateTrustBreakdown(findings, "test", true);
    expect(tb.dependencyTrust.score).toBeLessThanOrEqual(50);
  });

  it("should penalize suspicious releases", () => {
    const findings = [
      makeFinding("RELEASE_EXE_ARTIFACT", "critical"),
      makeFinding("RELEASE_7Z_ARCHIVE"),
    ];
    const tb = calculateTrustBreakdown(findings, "test", true);
    expect(tb.releaseProcess.score).toBeLessThan(80);
  });

  it("should give zero publisher trust for known malicious accounts", () => {
    const findings = [makeFinding("REPO_KNOWN_MALICIOUS_ACCOUNT", "critical")];
    const tb = calculateTrustBreakdown(findings, "test", false);
    expect(tb.publisherTrust.score).toBe(0);
  });

  it("should include indicators with status", () => {
    const findings = [makeFinding("EVAL_ATOB", "critical")];
    const tb = calculateTrustBreakdown(findings, "test", true);
    expect(tb.codeQuality.indicators.length).toBeGreaterThan(0);
    expect(tb.codeQuality.indicators.some((i) => i.status === "red")).toBe(true);
  });

  it("should weight overall score correctly", () => {
    // Overall = publisher*0.4 + code*0.3 + dep*0.2 + release*0.1
    const tb = calculateTrustBreakdown([], "test", true);
    const expected = Math.round(100 * 0.4 + 100 * 0.3 + 100 * 0.2 + 100 * 0.1);
    expect(tb.overallScore).toBe(expected);
  });
});
