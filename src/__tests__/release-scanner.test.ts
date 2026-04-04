import { describe, it, expect } from "vitest";
import { scanReleaseArtifacts, hasPEMagic } from "../release-scanner.js";

describe("Release Scanner", () => {
  it("should detect double extensions", () => {
    const findings = scanReleaseArtifacts([{
      tagName: "v1.0", name: "Release", body: "", createdAt: "2026-01-01",
      assets: [{ name: "report.pdf.exe", size: 1024 }],
    }]);
    expect(findings.some((f) => f.rule === "RELEASE_DOUBLE_EXT")).toBe(true);
  });

  it("should detect LNK shortcuts", () => {
    const findings = scanReleaseArtifacts([{
      tagName: "v1.0", name: "Release", body: "", createdAt: "2026-01-01",
      assets: [{ name: "readme.lnk", size: 512 }],
    }]);
    expect(findings.some((f) => f.rule === "RELEASE_LNK_SHORTCUT")).toBe(true);
  });

  it("should detect script files in releases", () => {
    const findings = scanReleaseArtifacts([{
      tagName: "v1.0", name: "Release", body: "", createdAt: "2026-01-01",
      assets: [{ name: "install.ps1", size: 2048 }],
    }]);
    expect(findings.some((f) => f.rule === "RELEASE_SCRIPT_DROPPER")).toBe(true);
  });

  it("should detect password hints in release body", () => {
    const findings = scanReleaseArtifacts([{
      tagName: "v1.0", name: "Release", body: "Extract with password: infected123", createdAt: "2026-01-01",
      assets: [],
    }]);
    expect(findings.some((f) => f.rule === "RELEASE_PASSWORD_HINT")).toBe(true);
  });

  it("should detect tag/release date mismatch", () => {
    const findings = scanReleaseArtifacts([{
      tagName: "v1.0", name: "Release", body: "",
      createdAt: "2026-04-01", tagDate: "2026-01-01",
      assets: [],
    }]);
    expect(findings.some((f) => f.rule === "RELEASE_TAG_DATE_MISMATCH")).toBe(true);
  });

  it("should not flag clean releases", () => {
    const findings = scanReleaseArtifacts([{
      tagName: "v1.0.0", name: "v1.0.0", body: "Bug fixes and improvements",
      createdAt: "2026-04-01",
      assets: [
        { name: "package-1.0.0.tgz", size: 50000 },
        { name: "checksums.txt", size: 256 },
      ],
    }]);
    expect(findings).toHaveLength(0);
  });

  it("should include confidence scores", () => {
    const findings = scanReleaseArtifacts([{
      tagName: "v1.0", name: "Release", body: "", createdAt: "2026-01-01",
      assets: [{ name: "app.pdf.exe", size: 1024 }],
    }]);
    expect(findings[0]?.confidence).toBeGreaterThan(0);
  });

  it("should detect PE magic bytes", () => {
    expect(hasPEMagic("MZ\x90\x00")).toBe(true);
    expect(hasPEMagic("4D5A9000")).toBe(true);
    expect(hasPEMagic("PK\x03\x04")).toBe(false);
  });
});
