/**
 * Dependency risk analyzer (v4.2).
 *
 * Levenshtein-based typosquat detection and namespace squatting.
 * Checks package names against popular packages to detect mimicry.
 */

import type { Finding } from "./types.js";

/** Top 80 most popular npm packages (targets for typosquatting) */
const POPULAR_PACKAGES: string[] = [
  "lodash", "chalk", "express", "react", "axios", "commander", "debug",
  "glob", "minimist", "semver", "uuid", "mkdirp", "rimraf", "yargs",
  "moment", "bluebird", "underscore", "async", "request", "inquirer",
  "colors", "path", "dotenv", "body-parser", "webpack", "typescript",
  "eslint", "prettier", "jest", "mocha", "chai", "sinon", "supertest",
  "mongoose", "sequelize", "pg", "mysql2", "redis", "ioredis",
  "socket.io", "cors", "helmet", "morgan", "cookie-parser", "jsonwebtoken",
  "bcrypt", "passport", "nodemailer", "multer", "sharp", "puppeteer",
  "cheerio", "node-fetch", "got", "superagent", "http-proxy-middleware",
  "ws", "next", "gatsby", "vue", "angular", "svelte", "tailwindcss",
  "postcss", "autoprefixer", "sass", "less", "babel", "esbuild",
  "rollup", "vite", "turbo", "nx", "lerna", "husky", "lint-staged",
  "cross-env", "concurrently", "nodemon", "pm2", "fastify", "koa",
  "hapi", "restify",
];

/** Patterns that suggest internal/private package names */
const INTERNAL_PATTERNS = [
  /^@[^/]+\/internal-/,
  /^@[^/]+\/private-/,
  /^@[^/]+\/.+-service$/,
  /^@[^/]+\/.+-api$/,
  /^@[^/]+\/.+-lib$/,
  /^@[^/]+\/.+-utils$/,
  /^@[^/]+\/.+-common$/,
  /^@[^/]+\/.+-core$/,
  /^@[^/]+\/.+-shared$/,
];

/**
 * Calculate Levenshtein distance between two strings.
 */
export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    Array.from({ length: n + 1 }, () => 0),
  );

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost,
      );
    }
  }

  return dp[m][n];
}

/**
 * Analyze dependencies for typosquatting and confusion risks.
 */
export function analyzeDependencyRisks(
  dependencies: Record<string, string>,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];
  const depNames = Object.keys(dependencies);

  for (const name of depNames) {
    // Skip scoped packages for Levenshtein (handled separately)
    if (name.startsWith("@")) {
      // Check internal name patterns on public registry
      for (const pattern of INTERNAL_PATTERNS) {
        if (pattern.test(name)) {
          findings.push({
            rule: "DEP_INTERNAL_NAME_PUBLIC",
            description: `Dependency "${name}" looks like an internal package name. If this is on a public registry, it may be a dependency confusion attack.`,
            severity: "critical",
            file: relativePath,
            confidence: 0.7,
            category: "supply-chain",
            recommendation: `Verify "${name}" is your organization's real package. If not, this is dependency confusion.`,
          });
          break;
        }
      }
      continue;
    }

    // Levenshtein check against popular packages
    for (const popular of POPULAR_PACKAGES) {
      if (name === popular) continue; // Exact match = legitimate
      if (Math.abs(name.length - popular.length) > 2) continue; // Quick skip

      const dist = levenshtein(name, popular);
      if (dist > 0 && dist <= 2) {
        findings.push({
          rule: "TYPOSQUAT_LEVENSHTEIN",
          description: `Dependency "${name}" is ${dist} edit(s) away from popular package "${popular}". Likely a typosquat.`,
          severity: "high",
          file: relativePath,
          confidence: dist === 1 ? 0.85 : 0.65,
          category: "supply-chain",
          recommendation: `Did you mean "${popular}"? Typosquatting replaces popular packages with malicious copies.`,
        });
        break; // One match per dep is enough
      }
    }

    // Check if name is similar to another direct dependency
    for (const otherName of depNames) {
      if (name === otherName) continue;
      if (name.startsWith("@") || otherName.startsWith("@")) continue;
      if (Math.abs(name.length - otherName.length) > 2) continue;

      const dist = levenshtein(name, otherName);
      if (dist > 0 && dist <= 1) {
        findings.push({
          rule: "TYPOSQUAT_SIMILAR_TO_DEP",
          description: `Dependencies "${name}" and "${otherName}" differ by only ${dist} character(s). One may be a typosquat of the other.`,
          severity: "high",
          file: relativePath,
          confidence: 0.7,
          category: "supply-chain",
          recommendation: `Review both "${name}" and "${otherName}". Only one should be in your dependencies.`,
        });
        break;
      }
    }
  }

  return findings;
}
