/**
 * Publishing anomaly detector (v4.2).
 *
 * Detects account-takeover signals and suspicious publishing patterns
 * by analyzing npm registry metadata: maintainer changes, version gaps,
 * script additions, and republish events.
 */

import type { Finding } from "./types.js";

interface NpmVersionMeta {
  version: string;
  publishedAt: string;
  maintainers: string[];
  hasInstallScripts: boolean;
  tarballUrl: string;
}

/**
 * Analyze npm package publishing history for anomalies.
 * Requires pre-fetched version metadata (from npm registry API).
 */
export function analyzePublishingAnomalies(
  packageName: string,
  versions: NpmVersionMeta[],
): Finding[] {
  const findings: Finding[] = [];
  if (versions.length < 2) return findings;

  // Sort by publish date
  const sorted = [...versions].sort(
    (a, b) => new Date(a.publishedAt).getTime() - new Date(b.publishedAt).getTime(),
  );

  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1];
    const curr = sorted[i];

    // Maintainer change
    const prevMaintainers = new Set(prev.maintainers);
    const newMaintainers = curr.maintainers.filter((m) => !prevMaintainers.has(m));
    if (newMaintainers.length > 0) {
      findings.push({
        rule: "PUBLISH_MAINTAINER_CHANGE",
        description: `${packageName}@${curr.version}: New maintainer(s) added before release: ${newMaintainers.join(", ")}. Possible account takeover.`,
        severity: "critical",
        confidence: 0.75,
        category: "supply-chain",
        recommendation: `Verify the maintainer change on ${packageName} was intentional. Account takeovers often precede malicious releases.`,
      });
    }

    // Version gap (> 2 years)
    const gapMs = new Date(curr.publishedAt).getTime() - new Date(prev.publishedAt).getTime();
    const gapDays = gapMs / (1000 * 60 * 60 * 24);
    if (gapDays > 730) {
      findings.push({
        rule: "PUBLISH_VERSION_GAP",
        description: `${packageName}@${curr.version}: Published ${Math.round(gapDays)} days after previous version. Dormant packages suddenly publishing are a takeover indicator.`,
        severity: "high",
        confidence: 0.65,
        category: "supply-chain",
        recommendation: `A ${Math.round(gapDays / 365)}-year gap before a new release is unusual. Check if the maintainer account was compromised.`,
      });
    }

    // Install scripts added (didn't have them before)
    if (!prev.hasInstallScripts && curr.hasInstallScripts) {
      findings.push({
        rule: "PUBLISH_SCRIPT_ADDED",
        description: `${packageName}@${curr.version}: Install scripts were added in this version (previous had none). New install scripts can execute malware on npm install.`,
        severity: "high",
        confidence: 0.7,
        category: "supply-chain",
        recommendation: `Review the new install scripts in ${packageName}@${curr.version}. Legitimate packages rarely add install hooks to existing releases.`,
      });
    }

    // Version number jump (e.g., 1.0.0 → 9.0.0)
    const prevMajor = parseInt(prev.version.split(".")[0], 10);
    const currMajor = parseInt(curr.version.split(".")[0], 10);
    if (!isNaN(prevMajor) && !isNaN(currMajor) && currMajor - prevMajor > 3) {
      findings.push({
        rule: "PUBLISH_VERSION_JUMP",
        description: `${packageName}@${curr.version}: Major version jumped from ${prevMajor} to ${currMajor}. Large version jumps can indicate a dependency confusion attack (higher version wins).`,
        severity: "high",
        confidence: 0.6,
        category: "supply-chain",
        recommendation: `Verify ${packageName}@${curr.version} is legitimate. Dependency confusion attacks use abnormally high version numbers.`,
      });
    }
  }

  return findings;
}

/**
 * Extract version metadata from npm registry response.
 * Expects the full package metadata from https://registry.npmjs.org/<package>
 */
export function extractVersionMeta(
  registryData: Record<string, unknown>,
): NpmVersionMeta[] {
  const versions = registryData.versions as Record<string, Record<string, unknown>> | undefined;
  const time = registryData.time as Record<string, string> | undefined;

  if (!versions || !time) return [];

  const result: NpmVersionMeta[] = [];

  for (const [ver, meta] of Object.entries(versions)) {
    const scripts = meta.scripts as Record<string, string> | undefined;
    const maintainers = (meta.maintainers as Array<{ name?: string }> | undefined) ?? [];
    const dist = meta.dist as { tarball?: string } | undefined;

    result.push({
      version: ver,
      publishedAt: time[ver] ?? "",
      maintainers: maintainers.map((m) => m.name ?? "unknown"),
      hasInstallScripts: !!(scripts?.preinstall || scripts?.postinstall || scripts?.install),
      tarballUrl: dist?.tarball ?? "",
    });
  }

  return result;
}
