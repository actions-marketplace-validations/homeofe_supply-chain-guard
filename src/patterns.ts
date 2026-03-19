/**
 * Known malicious patterns database
 *
 * This file is designed to be regularly updated as new threats emerge.
 * Add new patterns, wallet addresses, or domain patterns as they are discovered.
 */

import type { PatternEntry, Severity } from "./types.js";

// ---------------------------------------------------------------------------
// GlassWorm-specific IOCs
// ---------------------------------------------------------------------------

/** Known GlassWorm marker variables */
export const GLASSWORM_MARKERS = ["lzcdrtfxyqiplpd"];

/** Known GlassWorm Solana wallet addresses used for C2 */
export const KNOWN_C2_WALLETS: string[] = [
  // Add confirmed wallet addresses here as they are discovered
  // Example: "2fTGKciRBTwLpcMVMPGwWEqGkRrG7MkR1FoKGhCPNw2S"
];

/** Known C2 domain patterns (regex strings) */
export const C2_DOMAIN_PATTERNS: string[] = [
  // Domains seen in GlassWorm payloads
  "connect\\.\\w+\\.workers\\.dev",
  "\\w+-api\\.\\w+\\.workers\\.dev",
];

// ---------------------------------------------------------------------------
// File-based detection patterns
// ---------------------------------------------------------------------------

export const FILE_PATTERNS: PatternEntry[] = [
  // GlassWorm marker
  {
    name: "glassworm-marker",
    pattern: "lzcdrtfxyqiplpd",
    description: "GlassWorm campaign marker variable detected",
    severity: "critical",
    rule: "GLASSWORM_MARKER",
  },

  // Invisible Unicode characters (zero-width spaces, joiners, etc.)
  {
    name: "invisible-unicode",
    pattern:
      "[\\u200B\\u200C\\u200D\\u2060\\uFEFF\\u00AD\\u034F\\u061C\\u180E\\u2028\\u2029\\u202A-\\u202E\\u2066-\\u2069]{3,}",
    description:
      "Suspicious invisible Unicode characters detected (potential code obfuscation)",
    severity: "high",
    rule: "INVISIBLE_UNICODE",
  },

  // Encoded eval/exec patterns
  {
    name: "eval-atob",
    pattern: "eval\\s*\\(\\s*atob\\s*\\(",
    description: "Base64-encoded eval detected (common malware obfuscation)",
    severity: "critical",
    rule: "EVAL_ATOB",
  },
  {
    name: "eval-buffer-from",
    pattern: "eval\\s*\\(\\s*Buffer\\.from\\s*\\(",
    description:
      "Buffer-encoded eval detected (common malware obfuscation in Node.js)",
    severity: "critical",
    rule: "EVAL_BUFFER",
  },
  {
    name: "new-function-atob",
    pattern: "new\\s+Function\\s*\\(\\s*atob\\s*\\(",
    description:
      "Base64-encoded Function constructor detected (malware obfuscation)",
    severity: "critical",
    rule: "FUNCTION_ATOB",
  },
  {
    name: "eval-buffer-hex",
    pattern: "eval\\s*\\(\\s*Buffer\\.from\\s*\\([^)]+,\\s*['\"]hex['\"]\\s*\\)",
    description: "Hex-encoded eval detected",
    severity: "critical",
    rule: "EVAL_HEX",
  },
  {
    name: "exec-encoded",
    pattern:
      "exec\\s*\\(\\s*(?:atob|Buffer\\.from|decodeURIComponent)\\s*\\(",
    description: "Encoded exec call detected",
    severity: "high",
    rule: "EXEC_ENCODED",
  },

  // Solana C2 references
  {
    name: "solana-mainnet",
    pattern: "mainnet-beta\\.solana\\.com",
    description: "Solana mainnet RPC reference detected (potential C2 channel)",
    severity: "medium",
    rule: "SOLANA_MAINNET",
  },
  {
    name: "helius-rpc",
    pattern: "helius(?:-rpc)?\\.(?:com|dev)",
    description:
      "Helius Solana RPC reference detected (used in GlassWorm C2)",
    severity: "medium",
    rule: "HELIUS_RPC",
  },

  // Obfuscation patterns
  {
    name: "hex-string-array",
    pattern:
      "\\[\\s*(?:0x[0-9a-fA-F]+\\s*,\\s*){10,}",
    description: "Large hex array detected (potential obfuscated payload)",
    severity: "medium",
    rule: "HEX_ARRAY",
  },
  {
    name: "string-char-concat",
    pattern:
      "(?:String\\.fromCharCode|\\\\x[0-9a-fA-F]{2}){5,}",
    description:
      "Character code string construction detected (obfuscation technique)",
    severity: "medium",
    rule: "CHARCODE_OBFUSCATION",
  },

  // Network exfiltration
  {
    name: "env-exfil",
    pattern:
      "process\\.env\\b[^;]*(?:fetch|https?\\.(?:get|request)|axios|got|node-fetch)",
    description:
      "Environment variable access combined with network request (data exfiltration pattern)",
    severity: "high",
    rule: "ENV_EXFILTRATION",
  },
  {
    name: "dns-exfil",
    pattern: "dns\\.resolve.*process\\.env",
    description: "DNS-based data exfiltration pattern detected",
    severity: "high",
    rule: "DNS_EXFILTRATION",
  },
];

// ---------------------------------------------------------------------------
// Suspicious file names
// ---------------------------------------------------------------------------

/** Files that are suspicious by name alone */
export const SUSPICIOUS_FILES: Array<{
  pattern: string;
  description: string;
  severity: Severity;
  rule: string;
}> = [
  {
    pattern: "^i\\.js$",
    description:
      "Suspicious i.js file (commonly used as GlassWorm payload dropper)",
    severity: "high",
    rule: "SUSPICIOUS_I_JS",
  },
  {
    pattern: "^init\\.json$",
    description:
      "init.json persistence file (used by GlassWorm for configuration persistence)",
    severity: "high",
    rule: "SUSPICIOUS_INIT_JSON",
  },
];

// ---------------------------------------------------------------------------
// Suspicious npm scripts
// ---------------------------------------------------------------------------

/** Package.json script patterns that are suspicious */
export const SUSPICIOUS_SCRIPTS: PatternEntry[] = [
  {
    name: "postinstall-curl",
    pattern: "curl\\s+.*\\|\\s*(?:bash|sh|node)",
    description: "postinstall script downloads and executes remote code",
    severity: "critical",
    rule: "SCRIPT_CURL_EXEC",
  },
  {
    name: "postinstall-wget",
    pattern: "wget\\s+.*\\|\\s*(?:bash|sh|node)",
    description: "postinstall script downloads and executes remote code",
    severity: "critical",
    rule: "SCRIPT_WGET_EXEC",
  },
  {
    name: "postinstall-node-e",
    pattern: "node\\s+-e\\s+[\"'].*(?:http|https|fetch|require)",
    description:
      "postinstall script executes inline Node.js with network access",
    severity: "high",
    rule: "SCRIPT_NODE_INLINE",
  },
  {
    name: "postinstall-encoded",
    pattern: "(?:atob|Buffer\\.from|base64)",
    description: "postinstall script contains encoding/decoding operations",
    severity: "high",
    rule: "SCRIPT_ENCODED",
  },
  {
    name: "preinstall-exec",
    pattern: "(?:exec|spawn|execSync)\\s*\\(",
    description: "preinstall script executes system commands",
    severity: "medium",
    rule: "SCRIPT_PREINSTALL_EXEC",
  },
];

// ---------------------------------------------------------------------------
// Known malicious npm package name patterns
// ---------------------------------------------------------------------------

/** Patterns matching known malicious or typosquatting package names */
export const MALICIOUS_PACKAGE_PATTERNS: string[] = [
  // Typosquatting common packages
  "^(lodas|1odash|l0dash|lodash-es-utils)$",
  "^(cros-env|cross-env-shell|crossenv)$",
  "^(bable-cli|babelcli)$",
  "^(event-streem|event_stream)$",

  // GlassWorm campaign packages (pattern: random-looking names)
  "^[a-z]{15,}$", // Very long single-word lowercase names

  // Suspicious scoped packages mimicking official ones
  "^@(?!types|babel|eslint|jest|rollup|vitejs|vue|angular|react|next|nuxt|svelte|reduxjs|tanstack|trpc).*\\/.*$",
];

// ---------------------------------------------------------------------------
// File extensions to scan
// ---------------------------------------------------------------------------

export const SCANNABLE_EXTENSIONS = new Set([
  ".js",
  ".ts",
  ".jsx",
  ".tsx",
  ".mjs",
  ".cjs",
  ".py",
  ".sh",
  ".bash",
  ".json",
  ".yml",
  ".yaml",
  ".toml",
]);

/** Maximum file size to scan (in bytes). Files larger than this are skipped. */
export const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
