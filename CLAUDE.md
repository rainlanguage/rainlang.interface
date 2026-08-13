# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Solidity interfaces for the Rainlang interpreter and utility libraries for implementing them. Part of the Rain Protocol ecosystem for onchain interpreted compute.

License: DecentraLicense 1.0 (DCL-1.0). REUSE 3.2 compliant — all files need SPDX headers and copyright notices.

## Build & Development

Requires the Nix package manager. **Only use the nix version of Foundry**, not a system-installed one.

```bash
nix develop                    # Enter dev shell
rainix-sol-prelude             # Setup (run before first build/test)
rainix-sol-test                # Run all tests
rainix-sol-static              # Static analysis (Slither)
rainix-sol-legal               # License/REUSE compliance check
```

Compiler: Solidity 0.8.25, EVM target: cancun, optimizer enabled (1M runs). Fuzz tests run 2048 iterations.

All reverts use custom errors — no `revert("string")` or `require()` with string messages.

Interfaces use `pragma solidity ^0.8.25`; libraries and errors use `^0.8.25`.

## Architecture

### Core Interfaces (`src/interface/`)

The current interface set (all in `src/interface/`):

- **IInterpreterV4** — Evaluates Rainlang bytecode. Stateless: returns stack results and state writes without persisting anything itself.
- **IInterpreterStoreV3** — Key-value state storage with namespace isolation per caller. `set()` for bulk writes, `get()` for reads.
- **IInterpreterCallerV4** — Defines `EvaluableV4` struct (interpreter + store + bytecode). Contracts that call the interpreter implement this.
- **IParserV2** — Converts Rainlang source text to bytecode (`parse2()`).
- **ISubParserV4** — Extension point for custom literals and words in parsers.
- **IInterpreterExternV4** — External function dispatch with integrity checking.
- **IParserPragmaV1** — Pragma support (e.g. `usingWordsFrom`).

Deprecated v1/v2 interfaces live in `src/interface/deprecated/`. Deprecated interfaces should not be modified unless undeprecating (moving back to `src/interface/`).

### Libraries (`src/lib/`)

- **LibBytecode** (`bytecode/`) — Parse and validate Rainlang bytecode structure (source counts, offsets, stack allocation, OOB checks).
- **LibContext** (`caller/`) — Build execution context arrays with signature verification (uses OZ SignatureChecker). Base context = `[msg.sender, calling_contract]`.
- **LibEvaluable** (`caller/`) — Hash utility for `EvaluableV4` structs.
- **LibNamespace** (`ns/`) — Qualifies state namespaces by hashing with sender address for caller isolation.
- **LibParseMeta** (`parse/`) — Bloom filter + fingerprint-based word lookup for parser metadata.
- **LibGenParseMeta** (`codegen/`) — Code generation for optimized parse metadata constants.

### Key Types

- `StackItem` — `bytes32`, the interpreter's stack value type
- `OperandV2` — `bytes32`, opcode operands
- `StateNamespace` / `FullyQualifiedNamespace` — `bytes32`, state isolation
- `SourceIndexV2` — `bytes32`, index into bytecode sources
- `EvaluableV4` — struct containing interpreter address, store address, and bytecode

### Security Model

Interpreters must be resilient to malicious expressions. Eval is read-only; state changes go through a separate `set()` call. Namespace qualification ensures caller isolation. If eval reverts, no state changes persist.

## Tests

Tests are in `test/src/lib/` mirroring the `src/lib/` structure. Test files use `.t.sol` suffix. Reference implementations used in differential testing append `Slow` to the library name, with no separating dot: `LibNamespaceSlow.sol`, `LibBytecodeSlow.sol`.

## Dependencies

Git submodules in `lib/`: forge-std, openzeppelin-contracts, and Rain Protocol libraries (rain.sol.codegen, rain.solmem, rain.lib.hash, rain.lib.typecast, rain.math.binary, rain.math.float, rain.intorastring). The `rain.sol.codegen` submodule has a remapping configured in `foundry.toml`.

## Branch Naming

Feature branches follow `YYYY-MM-DD-description` convention.
