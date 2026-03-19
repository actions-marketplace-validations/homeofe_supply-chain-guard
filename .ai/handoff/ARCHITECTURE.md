# supply-chain-guard - Architecture

## Directory Structure
```
src/
  cli.ts          - CLI entry point (commander)
  index.ts        - Programmatic API
  scanner.ts      - Core scanning engine
  action.ts       - GitHub Action wrapper
  detectors/
    npm.ts        - npm-specific detection
    pypi.ts       - PyPI-specific detection
    vscode.ts     - VS Code extension detection
    lockfile.ts   - Lockfile integrity
    binary.ts     - Binary/native addon detection
    network.ts    - Network beacon detection
    campaigns.ts  - Known campaign signatures
    confusion.ts  - Dependency confusion
```

## Data Flow
1. CLI parses arguments (scan/npm/monitor)
2. Scanner loads relevant detectors based on target type
3. Each detector runs pattern matching against files/manifests
4. Results aggregated with severity scores
5. Output formatted as JSON, table, or sarif

## Key Design Decisions
- Zero runtime dependencies for core scanning
- Whitelisted binaries to reduce false positives
- Campaign signatures versioned independently
- SARIF output for GitHub Security tab integration
