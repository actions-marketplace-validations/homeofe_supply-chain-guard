/**
 * Output formatting for scan reports.
 * Supports text, JSON, and markdown output.
 */

import type { Finding, ScanReport, Severity } from "./types.js";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "\x1b[91m", // bright red
  high: "\x1b[31m",     // red
  medium: "\x1b[33m",   // yellow
  low: "\x1b[36m",      // cyan
  info: "\x1b[37m",     // white
};
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

/**
 * Format a scan report for output.
 */
export function formatReport(
  report: ScanReport,
  format: "text" | "json" | "markdown",
): string {
  switch (format) {
    case "json":
      return formatJson(report);
    case "markdown":
      return formatMarkdown(report);
    case "text":
    default:
      return formatText(report);
  }
}

/**
 * Format as JSON.
 */
function formatJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Format as human-readable text with colors.
 */
function formatText(report: ScanReport): string {
  const lines: string[] = [];

  // Header
  lines.push("");
  lines.push(`${BOLD}  supply-chain-guard${RESET} scan report`);
  lines.push(`${DIM}  ${"─".repeat(50)}${RESET}`);
  lines.push(`  Target:    ${report.target}`);
  lines.push(`  Type:      ${report.scanType}`);
  lines.push(`  Time:      ${report.timestamp}`);
  lines.push(`  Duration:  ${report.durationMs}ms`);
  lines.push("");

  // Score
  const scoreColor =
    report.score === 0
      ? "\x1b[32m"
      : report.score <= 10
        ? "\x1b[36m"
        : report.score <= 30
          ? "\x1b[33m"
          : report.score <= 60
            ? "\x1b[31m"
            : "\x1b[91m";

  lines.push(
    `  Risk Score: ${scoreColor}${BOLD}${report.score}/100${RESET} (${report.riskLevel.toUpperCase()})`,
  );
  lines.push("");

  // Summary
  lines.push(`${BOLD}  Summary${RESET}`);
  lines.push(`${DIM}  ${"─".repeat(50)}${RESET}`);

  if (report.scanType === "directory" || report.scanType === "github") {
    lines.push(`  Files:     ${report.summary.filesScanned}/${report.summary.totalFiles} scanned`);
  }

  const counts = [
    report.summary.critical > 0
      ? `${SEVERITY_COLORS.critical}${report.summary.critical} critical${RESET}`
      : null,
    report.summary.high > 0
      ? `${SEVERITY_COLORS.high}${report.summary.high} high${RESET}`
      : null,
    report.summary.medium > 0
      ? `${SEVERITY_COLORS.medium}${report.summary.medium} medium${RESET}`
      : null,
    report.summary.low > 0
      ? `${SEVERITY_COLORS.low}${report.summary.low} low${RESET}`
      : null,
    report.summary.info > 0
      ? `${SEVERITY_COLORS.info}${report.summary.info} info${RESET}`
      : null,
  ].filter(Boolean);

  if (counts.length > 0) {
    lines.push(`  Findings:  ${counts.join(", ")}`);
  } else {
    lines.push(`  Findings:  \x1b[32mNone${RESET}`);
  }
  lines.push("");

  // Findings
  if (report.findings.length > 0) {
    lines.push(`${BOLD}  Findings${RESET}`);
    lines.push(`${DIM}  ${"─".repeat(50)}${RESET}`);

    // Sort by severity (critical first)
    const sorted = [...report.findings].sort(
      (a, b) => severityRank(b.severity) - severityRank(a.severity),
    );

    for (const finding of sorted) {
      lines.push("");
      lines.push(
        `  ${SEVERITY_ICONS[finding.severity]} ${SEVERITY_COLORS[finding.severity]}${BOLD}[${finding.severity.toUpperCase()}]${RESET} ${finding.description}`,
      );
      lines.push(`     Rule: ${finding.rule}`);
      if (finding.file) {
        const location = finding.line
          ? `${finding.file}:${finding.line}`
          : finding.file;
        lines.push(`     File: ${location}`);
      }
      if (finding.match) {
        lines.push(`     Match: ${DIM}${finding.match}${RESET}`);
      }
      lines.push(`     Fix: ${finding.recommendation}`);
    }
    lines.push("");
  }

  // Recommendations
  if (report.recommendations.length > 0) {
    lines.push(`${BOLD}  Recommendations${RESET}`);
    lines.push(`${DIM}  ${"─".repeat(50)}${RESET}`);
    for (const rec of report.recommendations) {
      lines.push(`  • ${rec}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Format as markdown (for PR comments, GitHub Actions).
 */
function formatMarkdown(report: ScanReport): string {
  const lines: string[] = [];

  // Header
  lines.push("## 🛡️ supply-chain-guard Scan Report");
  lines.push("");
  lines.push(`| Property | Value |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Target | \`${report.target}\` |`);
  lines.push(`| Type | ${report.scanType} |`);
  lines.push(`| Time | ${report.timestamp} |`);
  lines.push(`| Duration | ${report.durationMs}ms |`);
  lines.push(
    `| **Risk Score** | **${report.score}/100** (${report.riskLevel.toUpperCase()}) |`,
  );
  lines.push("");

  // Summary
  lines.push("### Summary");
  lines.push("");

  if (report.scanType === "directory" || report.scanType === "github") {
    lines.push(
      `Scanned ${report.summary.filesScanned} of ${report.summary.totalFiles} files.`,
    );
    lines.push("");
  }

  if (report.findings.length === 0) {
    lines.push("> ✅ No malicious indicators detected.");
    lines.push("");
  } else {
    const badges: string[] = [];
    if (report.summary.critical > 0)
      badges.push(`🔴 ${report.summary.critical} critical`);
    if (report.summary.high > 0) badges.push(`🟠 ${report.summary.high} high`);
    if (report.summary.medium > 0)
      badges.push(`🟡 ${report.summary.medium} medium`);
    if (report.summary.low > 0) badges.push(`🔵 ${report.summary.low} low`);
    if (report.summary.info > 0) badges.push(`⚪ ${report.summary.info} info`);
    lines.push(badges.join(" | "));
    lines.push("");
  }

  // Findings
  if (report.findings.length > 0) {
    lines.push("### Findings");
    lines.push("");

    const sorted = [...report.findings].sort(
      (a, b) => severityRank(b.severity) - severityRank(a.severity),
    );

    for (const finding of sorted) {
      lines.push(
        `#### ${SEVERITY_ICONS[finding.severity]} [${finding.severity.toUpperCase()}] ${finding.description}`,
      );
      lines.push("");
      lines.push(`- **Rule:** \`${finding.rule}\``);
      if (finding.file) {
        const location = finding.line
          ? `${finding.file}:${finding.line}`
          : finding.file;
        lines.push(`- **File:** \`${location}\``);
      }
      if (finding.match) {
        lines.push(`- **Match:** \`${finding.match}\``);
      }
      lines.push(`- **Recommendation:** ${finding.recommendation}`);
      lines.push("");
    }
  }

  // Recommendations
  if (report.recommendations.length > 0) {
    lines.push("### Recommendations");
    lines.push("");
    for (const rec of report.recommendations) {
      lines.push(`- ${rec}`);
    }
    lines.push("");
  }

  lines.push(
    `---\n*Generated by [supply-chain-guard](https://github.com/homeofe/supply-chain-guard)*`,
  );

  return lines.join("\n");
}

/**
 * Get numeric rank for severity sorting.
 */
function severityRank(severity: Severity): number {
  const ranks: Record<Severity, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  return ranks[severity];
}
