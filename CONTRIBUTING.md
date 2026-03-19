# Contributing to supply-chain-guard

Thanks for your interest in contributing! This project aims to make supply-chain security accessible to everyone.

## How to Contribute

### Reporting New Malware Patterns

The most valuable contribution is adding new detection patterns. If you discover a new supply-chain attack or malware campaign:

1. Open an issue with the `new-pattern` label
2. Include IOCs (indicators of compromise) if available
3. Reference any public reports or advisories

### Adding Detection Rules

1. Fork the repository
2. Add patterns to `src/patterns.ts`
3. Add tests for your new patterns
4. Submit a pull request

Each pattern needs:
- A unique rule ID
- A regex pattern
- A description
- A severity level (critical/high/medium/low/info)
- Test coverage

### Code Contributions

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `npm test`
5. Run type check: `npm run lint`
6. Commit with a clear message
7. Push and open a PR

### Code Style

- TypeScript strict mode
- No `any` types (use `unknown` and type guards)
- No em dashes in comments or docs
- Keep functions focused and testable
- Add JSDoc comments for public APIs

### Testing

- All new features need tests
- All new patterns need test cases (both positive and negative)
- Run `npm test` before submitting

## Development Setup

```bash
git clone https://github.com/homeofe/supply-chain-guard.git
cd supply-chain-guard
npm install
npm run build
npm test
```

## Questions?

Open an issue or reach out at emre.kohler@elvatis.com.
