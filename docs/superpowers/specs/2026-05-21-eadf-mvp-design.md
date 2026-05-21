# EADF MVP — Design Spec

**Date:** 2026-05-21
**Author:** Trần Việt Hoàng (24210127)
**Reference:** `SPEC.md` (root) — Chapters 5, 6, 7
**Status:** Draft, awaiting review

---

## 1. Problem statement

The thesis (`SPEC.md`) defines a research framework, EADF (Evolution-Aware Detection Framework), that analyses proxy-based upgradeable Solidity contracts across versions and flags upgrade-induced security risks — most notably Storage Collision, Uninitialized Implementation, and Unauthorized Upgrade.

The current repository implements only part of Chapter 5 + Chapter 7:

- Two of three attack scenarios are present as Foundry contracts and tests (Storage Collision, Uninitialized Implementation).
- The third scenario (Unauthorized Upgrade — `VulnerableUUPS`, `SecureUUPS`, `MaliciousImpl` + test) is missing.
- The entire Python EADF framework (Modules 1–5 in `SPEC.md` §5–§6) is unbuilt.
- The evaluation pipeline (dataset of ~200 mainnet proxies, ground truth labels, Precision/Recall/F1 versus Slither and USCSA) is unbuilt.

This spec defines the **MVP** — a thin vertical slice that establishes the entire pipeline end-to-end, covers all three attack scenarios at the contract level, and produces a working JSON report plus Markdown checklist for at least one local contract pair. Dataset/evaluation work is deliberately out of scope.

## 2. Goals and non-goals

### Goals

1. Complete the Foundry side: add Scenario 3 (Unauthorized Upgrade) contracts, test, and demo script so `forge test` passes 3 scenarios + supporting suites.
2. Build a working Python EADF pipeline (Modules 1–5) that accepts either local `.sol` files or an Etherscan proxy address and produces `report.json` + `checklist.md`.
3. Implement the thesis's novel contribution — **Storage Slot Differential** (`SPEC.md` §5.3) and **S_slot** dimension in the confidence formula (`SPEC.md` §5.5) — in full.
4. Correctly detect the seeded storage collision when run on the local `SecureLogicV1` vs `VulnerableLogicV2` pair.
5. Architect the pipeline so each module's output is an inspectable JSON artifact (Approach B — stage-based), enabling thesis figures, debugging during evaluation, and re-runs from any stage.

### Non-goals (deferred)

- Full GumTree-based AST diff. MVP uses a `SimpleASTDiffer`; a `GumTreeDiffer` stub records the planned extension.
- Dataset collection of ~200 labeled mainnet proxies and Precision/Recall/F1 comparison against Slither and USCSA — this becomes the evaluation phase after the MVP is validated.
- Dynamic analysis. EADF remains a static analyser, consistent with `SPEC.md` §1.2.
- ML/embedding-based semantic scoring (CodeBERT etc.). MVP uses `rapidfuzz` + lookup tables for F1–F6, sufficient for the three known scenarios.
- Multi-version chains (analysing V1→V2→V3 transitively). MVP analyses a single pair (V_i, V_{i+1}).

## 3. Key design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Source ingestion | Dual `SourceProvider`: `LocalSource` + `EtherscanSource` | Local mode mirrors how the current Foundry project already works (`forge test` reads `.sol` from disk). Etherscan mode matches `SPEC.md` §5.2's stated input contract for the evaluation phase. Both providers produce the same `SourceBundle` so Modules 2–5 are source-agnostic. |
| AST diff for MVP | `SimpleASTDiffer` (Python, compares Slither AST node lists) | Avoids hard dependency on a Java runtime + GumTree jar mid-MVP, which is the largest integration risk in the spec. The novel contribution (Storage Slot Differential) does not require GumTree; only Module 4's change↔vuln matching does, and a simpler INSERT/DELETE/UPDATE diff is sufficient for the three known scenarios. |
| Dynamic confirmation | None — EADF stays static | Consistent with `SPEC.md` §1.2 ("Phân tích tĩnh, không phân tích động trên live network"). Keeps the framework comparable to Slither and USCSA in evaluation. Existing Anvil demos remain a separate, complementary proof-of-exploitability. |
| Data flow between modules | Stage-based — each module reads/writes JSON in a per-run work directory (Approach B) | Generates artifacts usable as thesis figures, supports re-running individual stages (cheap weight tuning for Module 4), simplifies debugging during evaluation when crashes on instance 87 of 200, and naturally decomposes the CLI into subcommands. |
| Scenario 3 contracts | Built inside this MVP | Small (~120 LOC + ~80 LOC test), follows existing patterns exactly, and gives EADF a third test contract pair for end-to-end pipeline validation. |
| Python packaging | `pyproject.toml`, package-installable, `typer`-based CLI | Standard modern Python layout. `typer` is chosen over `argparse` so subcommands per stage are ergonomic. |
| Test approach | Three-tier: unit (per module), integration (fixture JSON between stages), end-to-end (3 scenarios) | Decouples Slither/Etherscan from inner-loop testing; E2E tests double as the MVP's success criteria. |

## 4. Architecture overview

```
┌────────────────────────────────────────────────────────────────┐
│ CLI:  eadf run | collect | diff | detect | match | report      │
└────────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        │                                               │
        ▼                                               ▼
┌────────────────┐                                 ┌──────────────┐
│  workdir.py    │  manages work/{run_id}/         │  config.py   │
│  (paths, IO)   │  stage{N}_*.json                │  (weights)   │
└────────────────┘                                 └──────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│  Module 1  Collector                                             │
│  SourceProvider ── LocalSource (★ MVP path)                      │
│                ── EtherscanSource (built, off critical path)     │
│  → stage1_sources/v1/, v2/, metadata.json                        │
└──────────────────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│  Module 2  AST + Storage Slot Differential                       │
│  slither_ast        → AST + state-variable list per version      │
│  ASTDiffer ── SimpleASTDiffer (★ MVP)                            │
│            ── GumTreeDiffer (stub, NotImplementedError)          │
│  slot_mapper        → compute slot mapping per Solidity rules    │
│  → stage2_ast_diff.json + stage2_slot_diff.json                  │
└──────────────────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│  Module 3  Vulnerability Detection                               │
│  slither_runner            → run 7 detectors per SPEC §5.4       │
│  storage_collision_detector → inject custom finding from slot diff│
│  behavior_classifier        → Introduce/Fix/Smooth/Invalid        │
│  → stage3_vulnerabilities.json                                   │
└──────────────────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│  Module 4  Change–Vulnerability Matching                         │
│  pos_scorer + pattern_scorer + semantic_scorer                   │
│  + type_scorer + slot_scorer (★ novelty)                         │
│  confidence_scorer  → C = Σ wᵢ·Sᵢ, threshold 0.6                 │
│  → stage4_matched_pairs.json                                     │
└──────────────────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│  Module 5  Reporting                                             │
│  json_reporter      → merges stages 1–4                          │
│  risk_classifier    → Critical/High/Medium/Low                   │
│  checklist_generator → Markdown per SPEC §5.6                    │
│  → stage5_report.json + checklist.md                             │
└──────────────────────────────────────────────────────────────────┘
```

## 5. Repository layout

```
usc-security-thesis/
├── src/
│   ├── secure/                       (existing)
│   └── vulnerable/
│       ├── BadProxy.sol              (existing)
│       ├── VulnerableLogicV1.sol     (existing)
│       ├── VulnerableLogicV2.sol     (existing)
│       ├── VulnerableUUPS.sol        ← NEW
│       ├── SecureUUPS.sol            ← NEW
│       └── MaliciousImpl.sol         ← NEW
├── test/
│   ├── 1_StorageCollision.t.sol      (existing)
│   ├── 2_Uninitialized.t.sol         (existing)
│   ├── 3_GasComparison.t.sol         (existing)
│   ├── 4_UpgradeFlow.t.sol           (existing)
│   └── 5_UnauthorizedUpgrade.t.sol   ← NEW
├── script/
│   ├── AllDemo.s.sol                 (extend to include Scenario 3)
│   └── demo/
│       └── UnauthorizedUpgradeDemo.s.sol  ← NEW
├── docs/superpowers/specs/
│   └── 2026-05-21-eadf-mvp-design.md ← this file
└── eadf/                             ← NEW Python package
    ├── pyproject.toml
    ├── README.md
    ├── .env.example
    ├── scripts/setup.sh
    ├── eadf/
    │   ├── __init__.py
    │   ├── cli.py
    │   ├── config.py
    │   ├── workdir.py
    │   ├── models.py
    │   ├── module1_collector/
    │   │   ├── source_provider.py    (Protocol)
    │   │   ├── local_source.py       (★ MVP)
    │   │   └── etherscan_source.py
    │   ├── module2_ast_diff/
    │   │   ├── slither_ast.py
    │   │   ├── simple_differ.py      (★ MVP)
    │   │   ├── gumtree_differ.py     (stub)
    │   │   └── slot_mapper.py        (★ novelty)
    │   ├── module3_vuln_detector/
    │   │   ├── slither_runner.py
    │   │   ├── storage_collision_detector.py
    │   │   └── behavior_classifier.py
    │   ├── module4_matcher/
    │   │   ├── confidence_scorer.py
    │   │   ├── pos_scorer.py
    │   │   ├── pattern_scorer.py
    │   │   ├── semantic_scorer.py
    │   │   ├── type_scorer.py
    │   │   └── slot_scorer.py        (★ novelty)
    │   └── module5_reporter/
    │       ├── json_reporter.py
    │       ├── checklist_generator.py
    │       └── risk_classifier.py
    ├── tests/
    │   ├── fixtures/
    │   ├── test_slot_mapper.py
    │   ├── test_simple_differ.py
    │   ├── test_confidence_scorer.py
    │   ├── test_risk_classifier.py
    │   └── test_pipeline_e2e.py
    └── work/                         (gitignored)
        └── {run_id}/stage{N}_*.json
```

## 6. CLI surface

```bash
# Default: run all stages
eadf run --local-v1 <path> --local-v2 <path> [--run-id <name>]
eadf run --proxy 0xABC... [--from-stage N]

# Individual stages (debug, re-run after tuning)
eadf collect --local-v1 <path> --local-v2 <path>
eadf diff    --run-id <id>
eadf detect  --run-id <id>
eadf match   --run-id <id> [--config <toml>]
eadf report  --run-id <id>

# Utilities
eadf list
eadf show <run_id>
```

Exit codes: `0` success, `1` fatal pipeline error, `2` invalid CLI args, `3` success but no findings.

## 7. Module interfaces

```python
# module1_collector/source_provider.py
class SourceProvider(Protocol):
    def fetch(self, workdir: Path) -> SourceBundle: ...

@dataclass
class SourceBundle:
    v1_dir: Path
    v2_dir: Path
    metadata: SourceMetadata

# module2_ast_diff
class ASTDiffer(Protocol):
    def diff(self, v1: SlitherAST, v2: SlitherAST) -> ASTDiffSet: ...

def compute_slot_mapping(state_vars: list[StateVar]) -> dict[int, SlotEntry]: ...
def diff_slot_maps(v1: dict, v2: dict) -> SlotDiff: ...

# module3_vuln_detector
def run_slither(source_dir: Path) -> list[Finding]: ...
def detect_storage_collision(slot_diff: SlotDiff) -> list[Finding]: ...
def classify_behavior(v1_findings, v2_findings) -> UpgradeBehavior: ...

# module4_matcher
def compute_confidence(change: Change, vuln: Finding, slot_diff: SlotDiff) -> ConfidenceBreakdown: ...
def match(ast_diff, vuln_v2, slot_diff, threshold: float = 0.6) -> list[MatchedPair]: ...

# module5_reporter
def build_report(workdir: Path) -> Report: ...
def render_checklist(report: Report) -> str: ...
def classify_risk(report: Report) -> RiskLevel: ...
```

All input/output objects are `@dataclass` (defined in `eadf/models.py`), serialised by `dataclasses.asdict` + `json.dumps(indent=2)`.

## 8. Stage data contracts

### 8.1 Stage 1 — `stage1_sources/`

Directory tree plus `metadata.json`:

```json
{
  "source_type": "local | etherscan",
  "v1": {"path_or_address": "...", "label": "SecureLogicV1", "compiler": "0.8.24"},
  "v2": {"path_or_address": "...", "label": "SecureLogicV2", "compiler": "0.8.24"},
  "fetched_at": "ISO-8601",
  "proxy_address": "LOCAL_TEST | 0xABC...",
  "upgrade_block": null
}
```

### 8.2 Stage 2 — AST diff + slot diff

`stage2_ast_diff.json`:

```json
{
  "changes": [
    {
      "id": "c001",
      "op": "INSERT | DELETE | UPDATE",
      "node_kind": "StateVariable | Function | Modifier",
      "node_name": "collisionVar",
      "node_signature": "uint256 collisionVar",
      "v1_location": null,
      "v2_location": {"file": "LogicV2_Bad.sol", "line": 6, "col": 5},
      "extra": {"type": "uint256", "visibility": "public"}
    }
  ],
  "summary": {"insert": 2, "delete": 0, "update": 0}
}
```

`stage2_slot_diff.json` (★ novelty):

```json
{
  "v1_slots": {"0": {"name": "value", "type": "uint256", "size": 32, "offset": 0}},
  "v2_slots": {
    "0": {"name": "collisionVar", "type": "uint256", "size": 32, "offset": 0},
    "1": {"name": "value", "type": "uint256", "size": 32, "offset": 0}
  },
  "collisions": [
    {
      "slot": 0,
      "v1_var": "value",
      "v2_var": "collisionVar",
      "severity": "Critical",
      "reason": "user-balance/owner-like variable overwritten"
    }
  ]
}
```

### 8.3 Stage 3 — `stage3_vulnerabilities.json`

```json
{
  "v1": [
    {"detector_id": "uninitialized-state", "severity": "High",
     "location": {"file": "...", "line": 42}, "description": "..."}
  ],
  "v2": [
    {"detector_id": "storage-collision-cross-version", "severity": "Critical",
     "affected_slots": [0], "v1_variable": "value", "v2_variable": "collisionVar",
     "location": {"file": "LogicV2_Bad.sol", "line": 6}}
  ],
  "upgrade_behavior": "Introduce Vulnerability"
}
```

### 8.4 Stage 4 — `stage4_matched_pairs.json`

```json
{
  "threshold": 0.6,
  "weights": {"pos": 0.25, "pattern": 0.20, "semantic": 0.25, "type": 0.15, "slot": 0.15},
  "pairs": [
    {
      "change_id": "c001",
      "vuln_id": "v002",
      "scores": {"pos": 1.0, "pattern": 0.6, "semantic": 0.8, "type": 1.0, "slot": 1.0},
      "confidence": 0.91,
      "root_cause": "INSERT VarDecl collisionVar at position 0 shifts existing slot layout"
    }
  ],
  "unmatched_changes": ["c003"],
  "unmatched_vulns": []
}
```

### 8.5 Stage 5 — `stage5_report.json` + `checklist.md`

Schema and Markdown template follow `SPEC.md` §5.6 verbatim.

## 9. Key algorithms

### 9.1 `compute_slot_mapping` (Module 2)

Implements Solidity storage packing rules per `SPEC.md` §5.3:

```python
def compute_slot_mapping(state_vars: list[StateVar]) -> dict[int, SlotEntry]:
    slot, offset, mapping = 0, 0, {}
    for v in state_vars:
        size = size_of(v.type)
        if v.type in DYNAMIC_TYPES:
            if offset > 0: slot += 1; offset = 0
            mapping[slot] = SlotEntry(v.name, v.type, 32, 0)
            slot += 1
        elif size == 32 or offset + size > 32:
            if offset > 0: slot += 1; offset = 0
            mapping[slot] = SlotEntry(v.name, v.type, size, 0)
            slot += 1 if size == 32 else 0
            offset = 0 if size == 32 else size
        else:
            mapping[slot] = SlotEntry(v.name, v.type, size, offset)   # first var in slot only
            offset += size
    return mapping
```

`DYNAMIC_TYPES = {"mapping", "array_dynamic"}`. `size_of` returns 32 for `uint256`/`bytes32`/dynamic types, 20 for `address`, 1 for `bool`, etc.

### 9.2 `diff_slot_maps` severity heuristic

```
Critical   if V1 slot name matches /owner|implementation|admin|proxy/i
High       if V1 type startswith "mapping(" or name matches /balance|allow/i
Medium     otherwise
```

### 9.3 Confidence formula (Module 4)

```
C(c, v) = min(1.0, 0.25·S_pos + 0.20·S_pattern + 0.25·S_semantic + 0.15·S_type + 0.15·S_slot)
```

Weights and threshold live in `config.py` and are overridable via `--config <toml>`.

### 9.4 `S_slot` (★ novelty)

```python
def calc_slot_score(change, vuln, slot_diff):
    if vuln.detector_id != "storage-collision-cross-version":
        return 0.0
    if change.op == "INSERT" and any(c.slot <= change.first_affected_slot
                                     for c in slot_diff.collisions):
        return 1.0
    if change.op in {"UPDATE", "MOVE"} and overlaps_collision(change, slot_diff):
        return 1.0
    if affects_adjacent_slot(change, slot_diff):
        return 0.5
    return 0.0
```

### 9.5 `S_semantic` (6 features F1–F6, MVP implementation)

| Feature | MVP implementation |
|---|---|
| F1 fuzzy name similarity (0.30) | `rapidfuzz.ratio(change.node_name, vuln.location.function_name)` |
| F2 AST-node ↔ vuln type (0.20) | Lookup `OPERATION_VULN_MAP` (e.g. `INSERT VarDecl → storage-collision`) |
| F3 keyword overlap in description (0.15) | Count common terms in ±5-line context vs vuln description |
| F4 change-operation similarity (0.15) | Lookup table |
| F5 common-vulnerability-trait match (0.10) | Lookup table |
| F6 change-impact area (0.10) | Lookup table |

A `data/semantic_tables.toml` file holds F2/F4/F5/F6 lookup data so it can be revised without code edits.

## 10. Foundry Scenario 3 — Unauthorized Upgrade

### 10.1 Contracts (~120 LOC total, follow existing pattern)

`src/vulnerable/VulnerableUUPS.sol`:

```solidity
contract VulnerableUUPS is Initializable, UUPSUpgradeable {
    function initialize() public initializer { __UUPSUpgradeable_init(); }
    // Intentionally missing onlyOwner — anyone can upgrade
    function _authorizeUpgrade(address) internal override {}
}
```

`src/vulnerable/MaliciousImpl.sol`:

```solidity
contract MaliciousImpl {
    function drainFunds(address payable recipient) public {
        recipient.transfer(address(this).balance);
    }
    uint256[50] private __gap;
}
```

`src/vulnerable/SecureUUPS.sol`:

```solidity
contract SecureUUPS is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    constructor() { _disableInitializers(); }
    function initialize() public initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
    }
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
```

### 10.2 Test — `test/5_UnauthorizedUpgrade.t.sol` (~80 LOC, 3 cases)

- `testVulnerable_AnyoneCanUpgrade` — Bob (non-owner) calls `upgradeToAndCall(MaliciousImpl, "")` on a `VulnerableUUPS` proxy holding 10 ETH; then `drainFunds(bob)`; assert Bob's balance increased by 10 ETH.
- `testSecure_NonOwnerUpgradeReverts` — Bob calls `upgradeToAndCall` on a `SecureUUPS` proxy; expect revert `OwnableUnauthorizedAccount`.
- `testSecure_OwnerCanUpgrade` — Alice (owner) upgrades successfully.

### 10.3 Demo — `script/demo/UnauthorizedUpgradeDemo.s.sol`

Follows the existing `StorageCollisionDemo.s.sol` pattern: deploy, run attack, print before/after state.

### 10.4 Orchestrator

`script/AllDemo.s.sol` extended to invoke the new demo as a fourth step.

## 11. Dependencies

### Python — `eadf/pyproject.toml`

```toml
[project]
name = "eadf"
requires-python = ">=3.10"
dependencies = [
    "slither-analyzer>=0.10.4",
    "solc-select>=1.0.4",
    "web3>=6.15.0",
    "requests>=2.31.0",
    "python-dotenv>=1.0.0",
    "rapidfuzz>=3.6.0",
    "typer>=0.12.0",
]
[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-cov", "ruff", "mypy"]

[project.scripts]
eadf = "eadf.cli:app"
```

Solc pinned to `0.8.24` via `solc-select` (matches the Foundry contracts). `eadf/scripts/setup.sh` installs Solc and runs a smoke test.

### Foundry

No new dependencies. Scenario 3 reuses `openzeppelin-contracts-upgradeable` already vendored.

## 12. Error handling

Each stage returns:

```python
@dataclass
class StageResult:
    status: Literal["ok", "skipped", "failed"]
    output_path: Path | None
    errors: list[StageError]      # non-fatal
    fatal: StageError | None
```

Principles:

1. **Fatal vs non-fatal explicit.** A Slither parse failure on a target contract is fatal; one detector throwing is logged and skipped.
2. **Etherscan failures degrade gracefully.** Unverified source → skip instance, log warning, no crash (`SPEC.md` §5.2).
3. **No silent catches.** Every error is recorded in `stage{N}_errors.json` for post-hoc inspection across batch runs.

## 13. Testing strategy

| Tier | Files | Purpose |
|---|---|---|
| Unit | `tests/test_slot_mapper.py` (~8 cases), `test_simple_differ.py` (~4), `test_confidence_scorer.py` (~6), `test_risk_classifier.py` (~4) | Pure-function correctness; no Slither/Etherscan |
| Integration | `tests/test_stage_io.py` (~5) | Feed fixture JSON for stage{N}, assert stage{N+1} output |
| End-to-end | `tests/test_pipeline_e2e.py` (3) | Full pipeline on the three local scenarios — these double as MVP success checkpoints |

E2E assertions:

- **Storage Collision E2E:** `SecureLogicV1` vs `VulnerableLogicV2` → report contains `storage-collision-cross-version` with `severity=Critical`, `risk_level=Critical`.
- **Uninitialized E2E:** `VulnerableLogicV1` vs `SecureLogicV1` → `uninitialized-state` detected in V1; `behavior=Fix Vulnerability`.
- **Unauthorized Upgrade E2E:** `VulnerableUUPS` vs `SecureUUPS` → access-control finding in V1; `behavior=Fix Vulnerability`.

## 14. Build sequence

Spec-approved order; full implementation steps are deferred to the implementation plan produced by `writing-plans`.

1. Foundry Scenario 3 contracts + test + demo + `AllDemo` update (~½ day)
2. `eadf/` skeleton — pyproject, CLI stub, `workdir.py`, `models.py`, `config.py` (~½ day)
3. Module 1 — `SourceProvider` + `LocalSource` (Etherscan deferred to step 9) (~½ day)
4. Module 2 — Slither AST extraction + `SimpleASTDiffer` + `slot_mapper` (★) (~1–2 days)
5. Module 3 — `slither_runner` + `storage_collision_detector` + `behavior_classifier` (~1 day)
6. Module 4 — 5 sub-scorers, `slot_scorer` first (★) (~1–2 days)
7. Module 5 — `json_reporter` + `risk_classifier` + `checklist_generator` (~½ day)
8. E2E tests on three scenarios passing (~½ day)
9. `EtherscanSource` implementation to complete the dual-provider design (~½ day)

Total: ~7–10 working days.

## 15. Success criteria (recap)

- `forge test` passes all three scenario test suites (existing + new Scenario 3).
- `eadf run --local-v1 src/secure/SecureLogicV1.sol --local-v2 src/vulnerable/VulnerableLogicV2.sol` completes without crashing and produces `work/<run_id>/stage5_report.json` plus `checklist.md`.
- The report flags `storage-collision-cross-version` at slot 0 with `severity=Critical` and a matched pair with `confidence > 0.6`.
- Three E2E pytest tests pass.

## 16. Out of scope (explicit)

- ~200-instance mainnet dataset, ground-truth labelling, Precision/Recall/F1 versus Slither and USCSA — evaluation phase, post-MVP.
- `GumTreeDiffer` real implementation — interface present, behaviour deferred.
- Multi-hop upgrade chains (V1→V2→V3 transitive analysis).
- Dynamic confirmation by deploying to Anvil and observing storage.
- Web UI / dashboard.
- Comparing against bytecode-level (compiled) storage layout — MVP works at AST level only.
