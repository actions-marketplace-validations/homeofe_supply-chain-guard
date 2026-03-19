# supply-chain-guard - Project Status

## Current Version: 2.0.0

### Published
- npm: @elvatis_com/supply-chain-guard@2.0.0
- GitHub: homeofe/supply-chain-guard (Apache-2.0)
- GitHub Marketplace: supply-chain-guard (GitHub Action)

### Features (v2.0.0)
- 65+ detection rules across 8 categories
- npm package scanning (install scripts, obfuscation, typosquatting)
- PyPI package scanning (14 Python-specific patterns)
- VS Code extension scanning (.vsix analysis)
- Dependency confusion detection
- Lockfile integrity verification
- Binary/native addon detection (30-entry whitelist)
- Network beacon + crypto miner + protestware detection
- 13 campaign signatures (XZ Utils, Codecov, SolarWinds, ua-parser-js, coa/rc)
- GitHub Action with branding (shield/red)
- 142 tests

### Architecture
- CLI entry: src/cli.ts (commander-based)
- Core scanner: src/scanner.ts
- Detection modules: src/detectors/*.ts
- GitHub Action: action.yml + src/action.ts

### Open Issues
- None currently open

### Known Limitations
- PyPI scanning requires local package download (no remote API)
- VS Code extension scanning needs .vsix file on disk
- No real-time monitoring (scan-based only)
