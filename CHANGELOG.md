# Changelog

The list of commits in this changelog is automatically generated in the release process.
The commits follow the Conventional Commit specification.

## [0.1.0] - 2025-12-02

### 🚀 Features

- Adjust workflow files and remove local config files (#24)
- Removed CLI from library (#25)
- Add git-cliff for changelog generation (#20)
- Added benchmarks for exposed library methods (#17)
- Updated CLI code so it can loop commands (#16)
- Added badge pointing at technical doc (#14)
- Architecture dependent support for tools task (#12)
- Provided ability to define subject through flag in test-app
- Added -h flag that displays usage string
- Add formatting and linting in Taskfile as tasks
- Code migration (#1)

### 🐛 Bug Fixes

- Remove additional sign request from test-sign task (#21)
- Updated verifyConnection logic so it do not use client methods (#15)
- Fixed typos in flags description
- Implemented missing PEM support
- Updated test app usage strings
- Adjust naming of deletion task
- Extend Taskfile with additional CI commands and update GitHub workflow file

### 💼 Other

- Updated documentation regarding benchmarks

### 🚜 Refactor

- Adjust sign certificate task for new CSR and CA cert
- Adjust signing command in taskfile to store certificate response (#19)
- Introduced CLI framework and changed sign command from args… (#18)
