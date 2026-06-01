# USC Security Thesis - Upgradeable Smart Contract Demo

A Foundry-based project demonstrating smart contract security vulnerabilities in upgradeable proxy patterns and their secure alternatives using UUPS (EIP-1822).

## Overview

This project provides practical demonstrations of:

1. **Secure UUPS Upgrade Pattern** - Proper implementation following OpenZeppelin best practices
2. **Storage Collision Attack** - How improper storage layout corrupts proxy contracts
3. **Uninitialized Implementation Attack** - How attackers can take over unprotected implementations
4. **Unauthorized Upgrade Attack** - How a missing access-control modifier on `_authorizeUpgrade` lets anyone hijack a UUPS proxy

### EADF Evaluation Benchmark

The [`eadf/`](eadf/) directory contains EADF (Evolution-Aware Detection Framework), a static analyzer for upgrade regressions. Its `eadf evaluate` command runs the full EADF pipeline and a Slither-only baseline over an offline synthetic benchmark of 18 V1→V2 upgrade pairs ([`eadf/benchmark/`](eadf/benchmark/)). Headline result: **EADF 100% F1 vs. the Slither-only baseline at 34.78% F1** (the baseline misses ~79% of upgrade-specific bugs). See [`eadf/README.md`](eadf/README.md#evaluation) for details.

### Project Structure

Convention: contracts under `src/secure/` are the "do it right" references; contracts under `src/vulnerable/` are attack demonstrations. Folder is decided by security posture, not by scenario.

```
usc-security-thesis/
├── src/
│   ├── secure/                     # Secure reference implementations
│   │   ├── SecureProxy.sol         # ERC1967 compliant proxy
│   │   ├── SecureLogicV1.sol       # Proper UUPS with all protections
│   │   ├── SecureLogicV2.sol       # Safe upgrade pattern
│   │   └── SecureUUPS.sol          # onlyOwner-gated _authorizeUpgrade (Scenario 3)
│   │
│   └── vulnerable/                 # Vulnerable contracts (for attack demos)
│       ├── BadProxy.sol            # Proxy with slot 0 storage (vulnerable)
│       ├── VulnerableLogicV1.sol   # Logic without _disableInitializers()
│       ├── VulnerableLogicV2.sol   # Logic causing storage collision
│       ├── VulnerableUUPS.sol      # _authorizeUpgrade with no access control (Scenario 3)
│       └── MaliciousImpl.sol       # Attacker payload with drainFunds (Scenario 3)
│
├── test/                           # Test scripts
│   ├── 1_StorageCollision.t.sol    # Storage collision attack tests
│   ├── 2_Uninitialized.t.sol       # Uninitialized implementation tests
│   ├── 3_GasComparison.t.sol       # Gas cost comparison
│   ├── 4_UpgradeFlow.t.sol         # Full upgrade flow verification
│   └── 5_UnauthorizedUpgrade.t.sol # Unauthorized upgrade attack tests
│
└── script/demo/                    # Presentation demo scripts
    ├── SecureUpgradeDemo.s.sol         # Normal UUPS upgrade flow
    ├── StorageCollisionDemo.s.sol      # Storage collision attack
    ├── UninitializedDemo.s.sol         # Uninitialized implementation attack
    └── UnauthorizedUpgradeDemo.s.sol   # Unauthorized upgrade attack
```

## Requirements

- [Foundry](https://book.getfoundry.sh/getting-started/installation) (forge, anvil)
- Solidity ^0.8.24

## Setup

### 1. Clone and Install Dependencies

```bash
cd /Users/viethoang/Documents/Personal/solidity/usc-security-thesis

# Install dependencies (if not already installed)
forge install
```

### 2. Build the Project

```bash
forge build
```

### 3. Run All Tests

```bash
forge test --summary
```

Expected output: **19/19 tests pass**

| Test Suite                      | Tests |
| ------------------------------- | ----- |
| StorageCollisionTest            | 3     |
| UninitializedImplementationTest | 4     |
| GasComparisonTest               | 4     |
| UpgradeFlowTest                 | 5     |
| UnauthorizedUpgradeTest         | 3     |

## How to Demo

### Start Local Blockchain

Open **Terminal 1** and run:

```bash
anvil
```

Keep this running. Open **Terminal 2** for demo commands.

---

### Demo 1: Secure UUPS Upgrade (Normal Flow)

Demonstrates the proper upgrade pattern: Deploy V1 → Interact → Upgrade to V2 → State preserved.

```bash
forge script script/demo/SecureUpgradeDemo.s.sol \
  --rpc-url http://localhost:8545 \
  --broadcast -vvv
```

**Expected Result:**

- Version changes: `1.0.0` → `2.0.0`
- Value preserved: `43` (from setValue(42) + increment())
- New function works: `getTotal() = 143`

---

### Demo 2: Storage Collision Attack

Demonstrates how storing implementation at slot 0 causes corruption.

```bash
forge script script/demo/StorageCollisionDemo.s.sol \
  --rpc-url http://localhost:8545 \
  --broadcast -vvv
```

**Expected Result:**

- `setCollisionVar(9999)` overwrites implementation address
- Proxy now points to invalid address `0x270f` (9999)
- **ATTACK SUCCESS: Proxy corrupted!**

---

### Demo 3: Uninitialized Implementation Attack

Demonstrates how attackers take over unprotected implementation contracts.

```bash
forge script script/demo/UninitializedDemo.s.sol \
  --rpc-url http://localhost:8545 \
  --broadcast -vvv
```

**Expected Result:**

- **Vulnerable:** Attacker calls `initialize()` directly → Becomes owner
- **Secure:** `_disableInitializers()` blocks the attack

---

### Demo 4: Unauthorized Upgrade Attack

Demonstrates how a missing `onlyOwner` on `_authorizeUpgrade` lets any caller upgrade a UUPS proxy to an attacker-controlled implementation and drain its ETH.

```bash
forge script script/demo/UnauthorizedUpgradeDemo.s.sol \
  --rpc-url http://localhost:8545 \
  --broadcast -vvv
```

**Expected Result:**

- **Vulnerable:** Attacker calls `upgradeToAndCall(MaliciousImpl, "")` → succeeds → `drainFunds(attacker)` → proxy emptied
- **Secure:** `onlyOwner` modifier on `_authorizeUpgrade` reverts non-owner attempts with `OwnableUnauthorizedAccount`

---

### Demo 5: Gas Comparison

Compare gas costs between vulnerable and secure patterns.

```bash
forge test --match-contract GasComparisonTest -vvv
```

---

### Run All Demos at Once

```bash
forge script script/AllDemo.s.sol \
  --rpc-url http://localhost:8545 \
  --broadcast -vvv
```

---

### Reset Blockchain Between Demos

In Terminal 1, press `Ctrl+C` to stop Anvil, then run `anvil` again.

## Security Patterns Demonstrated

### Secure Implementation Checklist

- ✅ `constructor() { _disableInitializers(); }`
- ✅ Use `Initializable` with `initializer` modifier
- ✅ Use `reinitializer(n)` for upgrades
- ✅ Store implementation at EIP-1967 slot (not slot 0)
- ✅ Include `uint256[50] __gap` for storage safety
- ✅ Use `UUPSUpgradeable` for upgrade authorization

### Vulnerabilities Demonstrated

- ❌ No `_disableInitializers()` → Implementation takeover
- ❌ Implementation at slot 0 → Storage collision
- ❌ New variables before inherited → Storage layout corruption
- ❌ `_authorizeUpgrade` without `onlyOwner` → Anyone can hijack the proxy

## License

MIT
