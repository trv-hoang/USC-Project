# SPEC.md — Evolution-Aware Security Risk Analysis and Automated Detection Framework for Proxy-Based Upgradeable Smart Contracts

> **Sinh viên:** Trần Việt Hoàng | **MSSV:** 24210127  
> **GVHD:** ThS. Phan Thế Duy | **Trường:** UIT – ĐHQG TP.HCM  
> **Tên EN:** Evolution-Aware Security Risk Analysis and Automated Detection Framework for Proxy-Based Upgradeable Smart Contracts

---

## 1. TỔNG QUAN ĐỀ TÀI

### 1.1. Mục tiêu nghiên cứu

1. Phân tích kiến trúc proxy-based upgradeable smart contract ở mức EVM, bao gồm cơ chế delegatecall và storage layout.
2. Xây dựng các kịch bản tấn công mô phỏng (Proof-of-Concept) tái hiện lỗ hổng Storage Collision, Uninitialized Proxy và Unauthorized Upgrade.
3. Đánh giá mức độ nguy hiểm của từng nhóm rủi ro dựa trên khả năng khai thác và tác động.
4. Thiết kế và xây dựng framework EADF (Evolution-Aware Detection Framework) tích hợp AST differential analysis và thuật toán ánh xạ thay đổi–lỗ hổng đa chiều.
5. Đánh giá hiệu năng framework qua Precision/Recall/F1-score, so sánh với Slither và USCSA.

### 1.2. Phạm vi

- Ngôn ngữ: Solidity, EVM bytecode
- Mô hình proxy: Transparent Proxy, UUPS (EIP-1822)
- Phân tích tĩnh (không phân tích động trên live network)
- Dataset: Proxy contracts từ Ethereum mainnet qua Etherscan API

---

## 2. NỀN TẢNG LÝ THUYẾT

### 2.1. Cơ chế delegatecall

- `delegatecall` cho phép hợp đồng thực thi code của hợp đồng khác trên storage của chính mình
- `msg.sender` và `msg.value` được giữ nguyên
- Mọi thao tác đọc/ghi trên storage của Proxy

### 2.2. Các mô hình Proxy

**Transparent Proxy:**
- Admin → gọi hàm quản trị của Proxy (không delegatecall)
- User → luôn delegatecall tới Implementation
- Ngăn Function Selector Clashing

**UUPS (EIP-1822):**
- Logic nâng cấp nằm trong Implementation (không phải Proxy)
- Proxy tối giản, chỉ delegatecall
- Slot lưu địa chỉ: `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`
- Rủi ro: nếu Implementation lỗi → Proxy bị khóa vĩnh viễn

### 2.3. Storage Layout trong EVM

- Mỗi biến trạng thái ánh xạ vào slot 32-byte, bắt đầu từ slot 0
- Biến kích thước < 32 bytes → packing vào cùng slot
- Mapping và dynamic array → `keccak256`-based slot
- Storage gap: `uint256[50] private __gap` để dự trữ slot

### 2.4. EIP-1967 Unstructured Storage

```
IMPLEMENTATION_SLOT = keccak256("eip1967.proxy.implementation") - 1
ADMIN_SLOT = keccak256("eip1967.proxy.admin") - 1
```

---

## 3. MÔ HÌNH RỦI RO BẢO MẬT TIẾN HÓA

### 3.1. Phân loại hành vi nâng cấp

| Hành vi | S(Vᵢ) | S(Vᵢ₊₁) | Ý nghĩa |
|---|---|---|---|
| Introduce Vulnerability | 0 | 1 | Nâng cấp đưa vào lỗ hổng mới |
| Fix Vulnerability | 1 | 0 | Bảo mật cải thiện |
| Smooth Upgrade | 0 | 0 | Không ảnh hưởng bảo mật |
| Invalid Upgrade | 1 | 1 | Cần phân tích sâu |

Trong đó: S(Vᵢ) = 1 nếu phiên bản có lỗ hổng, S(Vᵢ) = 0 nếu không.

### 3.2. Bề mặt tấn công động

- **Bề mặt tĩnh tại V(i):** Phát hiện bằng tool thông thường
- **Bề mặt chuyển đổi V(i)→V(i+1):** Storage Collision liên phiên bản, Selector Clashing mới, Logic thay đổi nguy hiểm — **TRỌNG TÂM ĐỀ TÀI**
- **Bề mặt tích lũy:** Rủi ro tích lũy qua nhiều lần nâng cấp

### 3.3. Tám nhóm rủi ro

| Nhóm rủi ro | Nguồn gốc | Phát sinh tại | Tool tĩnh phát hiện | Mức độ |
|---|---|---|---|---|
| Storage Collision | Thay đổi storage layout | Upgrade | Một phần | Rất cao |
| Uninitialized Proxy/Impl | Sơ suất triển khai | Initialization | Có | Cao |
| Unauthorized Upgrade | Thiếu kiểm soát quyền | Upgrade | Có | Cao |
| Function Selector Clashing | Hash 4-byte xung đột | Upgrade | Một phần | Trung bình |
| Governance Centralization | Thiết kế quản trị | Vận hành | Không | Cao |
| Reentrancy mới phát sinh | Thay đổi logic | Post-upgrade | Khó | Cao |
| Integer Overflow | Thay đổi kiểu dữ liệu | Post-upgrade | Một phần | Trung bình |
| Unsynchronized State | Thiếu reinitializer | Post-upgrade | Khó | Trung bình |

---

## 4. THIẾT KẾ HỆ THỐNG THỰC NGHIỆM (Chương 5)

### 4.1. Kiến trúc ba lớp

```
Proxy Contract (ERC-1967)
    ↕ delegatecall
Implementation Contract V1/V2 (UUPS)
    ↑ upgrade controlled by
Admin/Upgrade Controller
```

### 4.2. Lý do chọn UUPS

- Tối ưu gas: Không có logic kiểm tra quyền trong Proxy
- Linh hoạt: Có thể xóa hàm upgrade trong version cuối
- Rủi ro cao hơn → tốt cho thực nghiệm

### 4.3. Yêu cầu kỹ thuật Implementation Contract

```solidity
// 1. Thay constructor bằng initialize()
function initialize() public initializer {
    __Ownable_init();
    __UUPSUpgradeable_init();
}

// 2. Bảo vệ Logic Contract
constructor() {
    _disableInitializers();
}

// 3. Kiểm soát quyền upgrade
function _authorizeUpgrade(address newImplementation)
    internal override onlyOwner {}

// 4. Storage gap
uint256[50] private __gap;
```

### 4.4. Quy trình triển khai thực nghiệm

```
Bước 1: Deploy LogicV1
Bước 2: Deploy ERC1967Proxy → trỏ tới LogicV1 + gọi initialize()
Bước 3: User gọi setValue(42) → ghi vào Slot 0 của Proxy
Bước 4: Deploy LogicV2 (có thêm getValueV2())
Bước 5: Gọi upgradeTo(LogicV2_address)
Bước 6: Gọi getValueV2() → trả về 42 ✓ (state được bảo toàn)
```

### 4.5. Môi trường thực nghiệm

- Framework: Foundry
- Thư viện: `@openzeppelin/foundry-upgrades`
- Mạng: Foundry Localhost

---

## 5. FRAMEWORK EADF (Chương 6)

### 5.1. Kiến trúc tổng thể

```
Input: Địa chỉ Proxy Contract
    ↓
[Module 1] Thu thập & Chuẩn hóa
    ↓ (V1_src, V2_src)
[Module 2] AST Differential ─────────────────────────┐
    ↓ (AST DiffSet + Slot Diff)                       │
[Module 3] Phát hiện lỗ hổng tĩnh                    │
    ↓ (VulnSet V1, V2)                                │
[Module 4] Ánh xạ Thay đổi–Lỗ hổng ←────────────────┘
    ↓ (Matched Pairs + Confidence Scores)
[Module 5] Sinh báo cáo & Checklist
    ↓
Output: JSON Report + Security Checklist (Markdown)
```

### 5.2. Module 1 — Thu thập và Chuẩn hóa Dữ liệu

**Mục tiêu:** Xây dựng upgrade path, truy xuất source code V(i) và V(i+1)

**Upgrade Path từ Event Logs:**
```
ProxyAddress → query Etherscan getLogs(topic: Upgraded) 
             → [ImplV1, ImplV2, ..., ImplVn] (theo thứ tự block)
             → tạo upgrade instances: [(V1,V2), (V2,V3), ...]
```

**Truy xuất Source Code:**
```
GET https://api.etherscan.io/api
    ?module=contract
    &action=getsourcecode
    &address={impl_address}
    &apikey={API_KEY}
```
- Nếu chưa verified → skip instance, log warning
- Nếu multi-file contract → tách file, xác định file chính

**Chuẩn hóa:**
```
Normalize encoding → UTF-8
Save to: {proxy_address}/{block_number}/v1/ và v2/
```

### 5.3. Module 2 — Phân tích AST Differential

**Xây dựng AST:**
- Engine chính: Slither
- Engine dự phòng: ANTLR4 (khi Slither gặp lỗi compilation)
- Đánh giá chất lượng: node integrity, structural integrity, semantic integrity

**So sánh AST bằng GumTree:**
```
GumTree(AST_V1, AST_V2) → AST DiffSet
```

Các thao tác trong DiffSet:
- `INSERT`: Thêm node mới (biến, hàm, modifier)
- `DELETE`: Xóa node cũ
- `UPDATE`: Thay đổi giá trị node (kiểu dữ liệu, tên)
- `MOVE`: Di chuyển node (thay đổi thứ tự khai báo)

**Storage Slot Differential (★ Điểm mới so với USCSA):**

```python
# Bước 1: Trích xuất danh sách biến từ AST
variables_v1 = extract_state_variables(AST_V1)  # [(name, type, size), ...]
variables_v2 = extract_state_variables(AST_V2)

# Bước 2: Tính slot index theo Solidity storage packing rules
slot_mapping_v1 = compute_slot_mapping(variables_v1)
# {slot_index: {variable_name, type, size}}
slot_mapping_v2 = compute_slot_mapping(variables_v2)

# Bước 3: So sánh
for slot in range(max(slots)):
    var_v1 = slot_mapping_v1.get(slot)
    var_v2 = slot_mapping_v2.get(slot)
    if var_v1 != var_v2:
        collision = StorageCollision(slot, var_v1, var_v2)
        classify_severity(collision)

# Bước 4: Phân loại mức độ
# Critical: slot chứa owner, implementation address bị ghi đè
# High: slot chứa user balances bị thay đổi
# Medium: slot chứa config bị thay đổi
```

**Solidity Storage Packing Rules:**
```python
def compute_slot_mapping(variables):
    slot = 0
    offset = 0  # bytes used in current slot
    mapping = {}
    
    for var in variables:
        size = get_size_bytes(var.type)  # uint256=32, address=20, bool=1, etc.
        
        if var.type in ['mapping', 'array_dynamic']:
            # New slot, keccak256-based
            slot += 1 if offset > 0 else 0
            offset = 0
            mapping[slot] = var
            slot += 1
        elif size == 32 or offset + size > 32:
            # Needs full slot or doesn't fit
            slot += 1 if offset > 0 else 0
            offset = 0
            mapping[slot] = var
            if size == 32:
                slot += 1
            else:
                offset = size
        else:
            # Packing
            mapping[slot] = var  # simplified: track first var in slot
            offset += size
    
    return mapping
```

### 5.4. Module 3 — Phát hiện Lỗ hổng Tĩnh

**Slither Detectors áp dụng:**
```python
DETECTORS = [
    'uninitialized-local',
    'uninitialized-state',
    'controlled-delegatecall',
    'suicidal',
    'missing-zero-check',
    'reentrancy-eth',
    'reentrancy-no-eth',
]
```

**Output chuẩn hóa JSON:**
```json
{
  "detector_id": "uninitialized-state",
  "severity": "High",
  "location": {
    "file": "LogicV2.sol",
    "line": 42
  },
  "description": "..."
}
```

**Custom Detector — Storage Collision Cross-Version:**
```python
class StorageCollisionDetector:
    """
    Nhận slot_diff từ Module 2, sinh Slither-compatible warning
    """
    def detect(self, slot_diff):
        findings = []
        for collision in slot_diff.collisions:
            findings.append({
                "detector_id": "storage-collision-cross-version",
                "severity": collision.severity,  # Critical/High/Medium
                "affected_slots": collision.slots,
                "v1_variable": collision.var_v1,
                "v2_variable": collision.var_v2,
                "location": collision.location
            })
        return findings
```

**Phân loại hành vi nâng cấp:**
```python
def classify_upgrade_behavior(vuln_set_v1, vuln_set_v2):
    if len(vuln_set_v1) == 0 and len(vuln_set_v2) > 0:
        return "Introduce Vulnerability"
    elif len(vuln_set_v1) > 0 and len(vuln_set_v2) == 0:
        return "Fix Vulnerability"
    elif len(vuln_set_v1) == 0 and len(vuln_set_v2) == 0:
        return "Smooth Upgrade"
    else:
        return "Invalid Upgrade"
```

### 5.5. Module 4 — Ánh xạ Thay đổi–Lỗ hổng

**Công thức Confidence Score:**
```
C(cᵢ, vⱼ) = min(1.0, w₁·S_pos + w₂·S_pattern + w₃·S_semantic + w₄·S_type + w₅·S_slot)
```

| Chiều | Trọng số | Mô tả |
|---|---|---|
| S_pos | w₁ = 0.25 | Khoảng cách vật lý (dòng code) |
| S_pattern | w₂ = 0.20 | Keyword overlap ±5 dòng |
| S_semantic | w₃ = 0.25 | Tương đồng ngữ nghĩa 6 đặc trưng |
| S_type | w₄ = 0.15 | Ánh xạ AST operation → vulnerability type |
| S_slot | w₅ = 0.15 | Storage slot collision score (★ MỚI) |

**Position Score:**
```python
def calc_pos_score(change_line, vuln_line):
    dist = abs(change_line - vuln_line)
    if dist == 0:   return 1.0
    if dist <= 2:   return 0.8
    if dist <= 5:   return 0.5
    if dist <= 10:  return 0.2
    return 0.1
```

**Pattern Score:**
```python
def calc_pattern_score(change, vuln, source_code):
    context = get_context_lines(source_code, change.line, window=5)
    vuln_keywords = get_vulnerability_keywords(vuln.detector_id)
    common = count_common_keywords(context, vuln_keywords)
    return min(1.0, common * 0.1)
```

**Semantic Score (6 đặc trưng):**
```python
def calc_semantic_score(change, vuln):
    F1 = fuzzy_function_name_similarity(change, vuln)      # 0.30
    F2 = ast_node_type_relevance(change, vuln)             # 0.20
    F3 = keyword_overlap_description(change, vuln)         # 0.15
    F4 = change_operation_type_similarity(change, vuln)    # 0.15
    F5 = common_vulnerability_trait_matching(change, vuln) # 0.10
    F6 = change_impact_area(change, vuln)                  # 0.10
    return min(1.0, 0.30*F1 + 0.20*F2 + 0.15*F3 + 0.15*F4 + 0.10*F5 + 0.10*F6)
```

**Storage Slot Score (★ Điểm mới):**
```python
def calc_slot_score(change, vuln, slot_diff):
    if vuln.detector_id != "storage-collision-cross-version":
        return 0.0
    
    if change_directly_causes_collision(change, slot_diff):
        return 1.0  # change INSERT/MOVE variable → collision
    elif change_affects_adjacent_slot(change, slot_diff):
        return 0.5
    return 0.0
```

**Matching:**
```python
CONFIDENCE_THRESHOLD = 0.6

matched_pairs = []
for change in ast_diff_set:
    for vuln in vuln_set_v2:
        score = compute_confidence(change, vuln, slot_diff)
        if score > CONFIDENCE_THRESHOLD:
            matched_pairs.append({
                "change": change,
                "vulnerability": vuln,
                "confidence": score
            })

# Sort by confidence descending
matched_pairs.sort(key=lambda x: x["confidence"], reverse=True)
```

### 5.6. Module 5 — Sinh Báo cáo và Checklist

**JSON Report Structure:**
```json
{
  "proxy_address": "0x...",
  "upgrade_block": 12345678,
  "impl_v1": "0x...",
  "impl_v2": "0x...",
  "upgrade_behavior": "Introduce Vulnerability",
  "storage_collision": {
    "detected": true,
    "severity": "Critical",
    "affected_slots": [0, 1],
    "details": "Slot 0: value (V1) → newVar (V2)"
  },
  "vulnerabilities": {
    "v1": [...],
    "v2": [...],
    "introduced": [...],
    "fixed": [...]
  },
  "matched_pairs": [
    {
      "change": {"type": "INSERT", "node": "VarDecl newVar", "line": 5},
      "vulnerability": {"detector_id": "storage-collision-cross-version", "severity": "Critical"},
      "confidence": 0.92,
      "root_cause": "Inserting newVar at position 0 shifts all existing variables"
    }
  ],
  "risk_level": "Critical"
}
```

**Risk Level Classification:**
```python
def classify_risk_level(report):
    if report["storage_collision"]["severity"] == "Critical":
        return "Critical"
    
    high_vulns = [v for v in report["vulnerabilities"]["introduced"]
                  if v["severity"] in ["High", "Critical"]]
    
    if len(high_vulns) > 0:
        return "High"
    
    if report["upgrade_behavior"] == "Introduce Vulnerability":
        return "Medium"
    
    return "Low"
```

**Security Checklist Output (Markdown):**
```markdown
## EADF Security Checklist — {proxy_address}
Generated: {timestamp}

### 1. Storage Layout Compatibility
- [ ] Storage slot mapping V1 vs V2 đã được kiểm tra
- [ ] Không có biến mới chèn vào giữa danh sách khai báo
- [ ] Kiểu dữ liệu của biến hiện có không bị thu hẹp
- [!] CẢNH BÁO: Phát hiện collision tại slot 0 — xem chi tiết

### 2. Initialization Security
- [ ] _disableInitializers() được gọi trong constructor
- [ ] Hàm initialize() có modifier initializer
- [ ] Reinitializer được dùng đúng cách nếu thêm biến mới

### 3. Access Control
- [ ] Hàm upgradeTo/upgradeToAndCall có kiểm tra quyền
- [ ] Owner/Admin không phải EOA duy nhất
- [ ] Timelock được áp dụng cho upgrade quan trọng

### 4. Post-Upgrade Logic
- [ ] Thứ tự external call không thay đổi nguy hiểm
- [ ] Kiểu dữ liệu mới không gây overflow với dữ liệu cũ
- [ ] Biến trạng thái mới được khởi tạo đúng cách

### 5. Governance
- [ ] Multisig được sử dụng cho quyền nâng cấp
- [ ] Upgrade event được emit đầy đủ để theo dõi

---
Risk Level: 🔴 CRITICAL
```

### 5.7. Pseudo-code Algorithms

Năm thuật toán dưới đây mô tả lõi xử lý của EADF. Ký hiệu: `⊥` = không tồn tại,
`τ` = ngưỡng confidence (mặc định 0.6), `×` = tích Descartes.

**Algorithm 1 — EADF Main Pipeline.** Điều phối 5 stage: collect → diff → detect → match → report.

```
Input : proxy_address  HOẶC  (local_v1, local_v2)
Output: report.json, checklist.md

 1: # Stage 1 — Collection
 2: if proxy_address đưa vào:
 3:     (src_v1, src_v2, meta) ← EtherscanSource.fetch(proxy_address)  # parse Upgraded events, lấy 2 impl cuối
 4: else:
 5:     (src_v1, src_v2, meta) ← LocalSource.fetch(local_v1, local_v2)
 6: lưu src_v1, src_v2, meta vào stage1/
 7:
 8: # Stage 2 — AST + Storage Slot Differential
 9: ast_v1 ← BuildAST(src_v1);  ast_v2 ← BuildAST(src_v2)
10: vars_v1 ← ExtractStateVars(ast_v1);  vars_v2 ← ExtractStateVars(ast_v2)
11: ast_diff ← SimpleASTDiffer(ast_v1, ast_v2)        # INSERT/DELETE/UPDATE/MOVE trên biến trạng thái + hàm
12: slot_v1 ← ComputeSlotMapping(vars_v1)             # Algorithm 2
13: slot_v2 ← ComputeSlotMapping(vars_v2)
14: slot_diff ← CompareSlotMappings(slot_v1, slot_v2) # Algorithm 3
15: lưu ast_diff, slot_diff vào stage2/
16:
17: # Stage 3 — Vulnerability Detection
18: F1 ← RunSlither(src_v1) ∪ CustomDetectors(ast_v1)
19: F2 ← RunSlither(src_v2) ∪ CustomDetectors(ast_v2) ∪ StorageCollisionDetector(slot_diff)
20: behavior ← ClassifyBehavior(F1, F2)               # Algorithm 5
21: lưu F1, F2, behavior vào stage3/
22:
23: # Stage 4 — Change ↔ Vulnerability Matching
24: candidates ← []
25: for each (change, vuln) in ast_diff.changes × F2:
26:     conf ← ComputeConfidence(change, vuln, slot_diff, src_v2)   # Algorithm 4
27:     if conf > τ:  thêm (conf, change, vuln) vào candidates
28: sắp xếp candidates theo conf giảm dần
29: pairs ← []; used_c ← ∅; used_v ← ∅                # gán 1:1 tham lam
30: for each (conf, change, vuln) in candidates:
31:     if change.id ∉ used_c and vuln.id ∉ used_v:
32:         thêm pair(change, vuln, conf) vào pairs; used_c += change.id; used_v += vuln.id
33: lưu pairs vào stage4/
34:
35: # Stage 5 — Reporting
36: risk ← ClassifyRiskLevel(slot_diff, F1, F2, behavior)
37: ghi report.json, checklist.md vào stage5/
38: return report.json, checklist.md
```

**Algorithm 2 — ComputeSlotMapping.** Ánh xạ biến trạng thái sang chỉ số storage slot theo
quy tắc packing của Solidity.

```
Input : state_vars — danh sách (name, type) theo đúng thứ tự khai báo
Output: M : slot_index → SlotEntry(name, type, size, offset)

 1: slot ← 0; offset ← 0; M ← {}
 2: for v in state_vars:
 3:     size ← SizeOf(v.type)               # số byte trong 1 slot; dynamic → 32
 4:     if IsDynamic(v.type):               # mapping, T[], string, bytes
 5:         if offset > 0: slot ← slot+1; offset ← 0
 6:         M[slot] ← (v, 32, 0);  slot ← slot+1; offset ← 0
 7:     else if size > 32:                  # mảng cố định trải nhiều slot
 8:         if offset > 0: slot ← slot+1; offset ← 0
 9:         M[slot] ← (v, size, 0);  slot ← slot + size/32; offset ← 0
10:     else if size == 32:                 # biến chiếm trọn slot
11:         if offset > 0: slot ← slot+1; offset ← 0
12:         M[slot] ← (v, 32, 0);  slot ← slot+1; offset ← 0
13:     else if offset + size > 32:         # không vừa slot hiện tại
14:         slot ← slot+1; offset ← 0
15:         M[slot] ← (v, size, 0);  offset ← size
16:     else:                               # pack chung slot hiện tại
17:         if slot ∉ M: M[slot] ← (v, size, offset)   # MVP: chỉ ghi biến đầu tiên
18:         offset ← offset + size
19: return M

# Giới hạn MVP: mỗi packed slot chỉ ghi biến đầu tiên; cờ packed_slots_present
# báo hiệu những lần chạy mà giới hạn này làm mất thông tin.
```

**Algorithm 3 — CompareSlotMappings (Storage Slot Differential).** So sánh hai ánh xạ slot,
phát hiện collision và gán mức độ. Đây là một trong hai đóng góp mới của đề tài.

```
Input : M1, M2 — ánh xạ slot của V1, V2
Output: collisions — danh sách (slot, v1_var, v2_var, severity, reason)

 1: collisions ← []
 2: for s in sort(keys(M1) ∪ keys(M2)):
 3:     a ← M1[s];  b ← M2[s]
 4:     if a = ⊥ or b = ⊥: continue              # slot chỉ tồn tại ở một phiên bản
 5:     if (a.name, a.type) ≠ (b.name, b.type):  # cùng slot, khác biến → collision
 6:         (sev, reason) ← ClassifySeverity(a, b, s)
 7:         thêm (s, a.name, b.name, sev, reason) vào collisions
 8: return collisions

ClassifySeverity(a, b, s):                        # match đầu tiên thắng
 9:  if a.name khớp /owner|implementation|admin|proxy/i:                  return Critical
10:  if s = 0 and a.type ∈ {address, address payable, uint256, bytes32}:  return Critical
11:  if a.type bắt đầu "mapping(" or a.name khớp /balance|allow|allowance/i: return High
12:  if s = 0:                                                            return High
13:  return Medium
```

**Algorithm 4 — ComputeConfidence (5-dimensional scoring).** Hợp nhất 5 chiều điểm thành một
giá trị confidence; trọng số `w = (pos .25, pattern .20, semantic .25, type .15, slot .15)`.

```
Input : change, vuln, slot_diff, src_v2_lines
Output: confidence ∈ [0, 1]

 1: line_c ← (change.v2_loc ?? change.v1_loc).line;  line_v ← vuln.loc.line
 2: # S_pos — độ gần dòng
 3: d ← |line_c − line_v|
 4: S_pos ← 1.0 nếu d=0; 0.8 nếu d≤2; 0.5 nếu d≤5; 0.2 nếu d≤10; ngược lại 0.1
 5: # S_pattern — từ khóa detector trong cửa sổ ±5 dòng
 6: ctx ← src_v2_lines[line_c−5 .. line_c+5]
 7: S_pattern ← min(1.0, 0.1 × |{kw ∈ Keywords(vuln.detector) : kw ∈ ctx}|)
 8: # S_semantic — pha trộn 6 đặc trưng có trọng số
 9: f1 ← FuzzRatio(change.node_name, vuln.target_name) / 100        # rapidfuzz
10: f2 ← Table[ast_node_relevance][op.kind.detector]
11: f3 ← 1 nếu change.node_name ⊆ vuln.description else 0
12: f4 ← Table[op_detector][op.detector]
13: f5 ← Table[trait][kind.detector]
14: f6 ← Table[impact][kind.detector]
15: S_semantic ← min(1, .30·f1 + .20·f2 + .15·f3 + .15·f4 + .10·f5 + .10·f6)
16: # S_type — tra cứu (op × node_kind × detector)
17: S_type ← OpVulnMap[(change.op, change.node_kind)][vuln.detector]  (mặc định 0)
18: # S_slot — chiều nhận biết storage collision (chiều mới của đề tài)
19: S_slot ← CalcSlotScore(change, vuln, slot_diff)
20: confidence ← w.pos·S_pos + w.pattern·S_pattern + w.semantic·S_semantic
21:                + w.type·S_type + w.slot·S_slot
22: return confidence

CalcSlotScore(change, vuln, slot_diff):
23:  if vuln.detector ≠ "storage-collision-cross-version": return 0.0
24:  if change.first_affected_slot = ⊥: return 0.0
25:  N ← change.first_affected_slot
26:  if change.op = INSERT and ∃ collision c: c.slot ≥ N:  return 1.0   # INSERT đẩy mọi slot ≥ N
27:  if change.op ∈ {UPDATE, MOVE} and ∃ collision c: c.slot = N: return 1.0  # trùng khít
28:  if ∃ collision c: |c.slot − N| = 1:  return 0.5                    # slot kề
29:  return 0.0
```

**Algorithm 5 — ClassifyBehavior.** Phân loại hành vi nâng cấp từ tập lỗ hổng hai phiên bản
(theo §3.1).

```
Input : F1 (lỗ hổng trong V1), F2 (lỗ hổng trong V2)
Output: behavior ∈ {Introduce, Fix, Smooth, Invalid}

 1: if F1 = ∅ and F2 ≠ ∅:  return "Introduce Vulnerability"
 2: if F1 ≠ ∅ and F2 = ∅:  return "Fix Vulnerability"
 3: if F1 = ∅ and F2 = ∅:  return "Smooth Upgrade"
 4: return "Invalid Upgrade"        # cả hai phiên bản đều còn lỗ hổng
```

---

## 6. THỰC NGHIỆM TẤN CÔNG (Chương 7)

### 6.1. Kịch bản 1 — Storage Collision

**Setup:**
```solidity
// LogicV1.sol — SAFE
contract LogicV1 is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    uint256 public value;  // Slot 0
    
    function setValue(uint256 _val) public { value = _val; }
    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// LogicV2_Bad.sol — VULNERABLE
contract LogicV2_Bad is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    uint256 public collisionVar;  // Slot 0 ← CHÈN VÀO TRƯỚC → COLLISION
    uint256 public value;         // Slot 1
    
    function setCollisionVar(uint256 _val) public { collisionVar = _val; }
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
```

**Attack Flow:**
```
1. Deploy Proxy → LogicV1
2. setValue(100)        → Slot 0 = 100
3. upgradeTo(LogicV2_Bad)
4. setCollisionVar(999) → ghi vào Slot 0
5. getValue()           → trả về 999 (không phải 100) ✗ BUG
```

**Expected Result:** `value` bị ghi đè thành 999 → Storage Collision confirmed

### 6.2. Kịch bản 2 — Uninitialized Implementation

**Setup:**
```solidity
// VulnerableLogic.sol — KHÔNG có _disableInitializers()
contract VulnerableLogic is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    function initialize() public initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
    }
    function destroy() public onlyOwner { selfdestruct(payable(msg.sender)); }
    function _authorizeUpgrade(address) internal override onlyOwner {}
    // THIẾU: constructor() { _disableInitializers(); }
}

// SecureLogic.sol — CÓ _disableInitializers()
contract SecureLogic is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    constructor() { _disableInitializers(); }  // ← BẢO VỆ
    function initialize() public initializer { ... }
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
```

**Attack Flow:**
```
1. Attacker phát hiện địa chỉ VulnerableLogic trên mạng
2. Attacker gọi: VulnerableLogic.initialize()  → chiếm Owner
3. Attacker gọi: VulnerableLogic.destroy()     → selfdestruct
4. Proxy trỏ vào địa chỉ rỗng → Proxy tê liệt hoàn toàn
```

**Expected Result:**
- VulnerableLogic: Tấn công thành công, contract bị hủy
- SecureLogic: `initialize()` revert → Tấn công thất bại

### 6.3. Kịch bản 3 — Unauthorized Upgrade

**Setup:**
```solidity
// VulnerableUUPS.sol — Thiếu kiểm tra quyền
contract VulnerableUUPS is Initializable, UUPSUpgradeable {
    function initialize() public initializer { __UUPSUpgradeable_init(); }
    
    // THIẾU onlyOwner → BẤT KỲ AI CŨNG GỌI ĐƯỢC
    function _authorizeUpgrade(address) internal override {}
}

// MaliciousImpl.sol
contract MaliciousImpl {
    function drainFunds(address payable recipient) public {
        recipient.transfer(address(this).balance);
    }
}

// SecureUUPS.sol — Có kiểm tra quyền
contract SecureUUPS is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    constructor() { _disableInitializers(); }
    function initialize() public initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
    }
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
```

**Attack Flow:**
```
1. Deploy Proxy → VulnerableUUPS, owner = Alice
2. Nạp 10 ETH vào Proxy
3. Attacker Bob deploy MaliciousImpl
4. Bob gọi: Proxy.upgradeTo(MaliciousImpl_address)  ← KHÔNG BỊ REVERT
5. Bob gọi: Proxy.drainFunds(Bob_address)
6. Proxy mất toàn bộ 10 ETH
```

**Expected Result:**
- VulnerableUUPS: Tấn công thành công, 10 ETH bị rút
- SecureUUPS: `upgradeTo()` revert do `onlyOwner` → Tấn công thất bại

### 6.4. Chi phí Gas (kết quả thực nghiệm)

| Thành phần | Vulnerable | Secure Pattern | Chênh lệch |
|---|---|---|---|
| Implementation deploy | 352,883 | 1,017,433 | +664,550 |
| Proxy deploy | 207,792 | 152,957 | -54,835 |
| Tổng | 560,675 | 1,170,390 | +108% |

| Contract | Kích thước (bytes) |
|---|---|
| VulnerableLogicV1 | 1,600 |
| SecureLogicV1 | 4,795 |
| BadProxy | 763 |
| SecureProxy (ERC1967) | 212 |

| Thao tác | Gas |
|---|---|
| BadProxy.upgradeTo() | 1,229 |
| UUPS.upgradeToAndCall() | 5,782 |
| UUPS với reinitializer | 31,396 |

### 6.5. Dataset Description and EDA

Đánh giá EADF dựa trên hai tập dữ liệu bổ trợ: **Dataset A** (3 cặp cục bộ, ground truth
thủ công, dùng làm acceptance gate của MVP — §6.5.1) và **Dataset B** (benchmark tổng hợp
ngoại tuyến 18 cặp, dùng để đo Precision/Recall/F1 ở §7 — §6.5.2). Vì không dùng Etherscan
trong phạm vi đồ án, Dataset B là benchmark tổng hợp thay cho dữ liệu mainnet (xem §7.3).

#### 6.5.1. Dataset A — Local Upgrade Instances (ground truth)

Ba cặp nâng cấp được xây dựng thủ công, mỗi cặp tương ứng một kịch bản tấn công ở §6.1–6.3.
Cột "Hành vi (chủ đích)" là nhãn thiết kế; cột "Detector-level invariant" là bất biến
được kiểm chứng end-to-end trong `eadf/tests/test_pipeline_e2e.py`.

| # | Instance | V1 → V2 | Hành vi (chủ đích) | Lỗ hổng chính | Severity | Detector-level invariant (V1 → V2) |
|---|----------|---------|--------------------|---------------|----------|------------------------------------|
| A1 | Storage Collision | `VulnerableLogicV1` → `VulnerableLogicV2` | Introduce Vulnerability | `storage-collision-cross-version` (slot 0: `value` → `collisionVar`) | Critical | risk_level = **Critical** |
| A2 | Uninitialized Implementation | `VulnerableLogicV1` → `SecureLogicV1` | Fix Vulnerability | `missing-disable-initializers` | High | có ở V1 → **không còn** ở V2 |
| A3 | Unauthorized Upgrade | `VulnerableUUPS` → `SecureUUPS` | Fix Vulnerability | `missing-upgrade-authorization` | Critical | có ở V1 → **không còn** ở V2 (gated `onlyOwner`) |

> **Lưu ý trung thực về A2/A3:** phiên bản secure (`SecureLogicV1`, `SecureUUPS`) kế thừa
> thêm contract OpenZeppelin (Ownable/UUPS), làm thay đổi storage layout và phát sinh
> finding phụ trên V2 (`storage-collision-cross-version`). Do V2 vẫn còn finding,
> `ClassifyBehavior` (Algorithm 5) xếp tổng thể là **Invalid Upgrade** thay vì *Fix
> Vulnerability*. Đây là *fixture-pair artifact* (storage của OwnableUpgradeable là cố ý
> trong thiết kế secure), không phải false-positive. Bất biến cốt lõi được kiểm chứng là
> việc đóng đúng lỗ hổng mục tiêu giữa V1 và V2 (cột cuối).

#### 6.5.2. Dataset B — Offline Synthetic Benchmark (EDA)

Vì không sử dụng Etherscan trong phạm vi đồ án (xem §7.3), Dataset B là một **benchmark
tổng hợp ngoại tuyến** gồm 18 cặp nâng cấp V1→V2 xây dựng thủ công tại `eadf/benchmark/`,
mỗi cặp có ground truth chính xác theo thiết kế và được kiểm chứng end-to-end qua lệnh
`eadf evaluate`. Benchmark phủ cả 4 hành vi nâng cấp và 6 lớp lỗ hổng (3 detector chuyên
biệt của EADF + 3 detector stock của Slither), kèm các cặp âm tính (append/xóa biến cuối,
refactor thuần) để đo precision. Các bảng dưới đây được sinh tự động từ
`eadf/benchmark/results/spec_tables.md`.

**B.1 — Phân bố hành vi nâng cấp** (theo Algorithm 5)

| Hành vi nâng cấp | Số lượng | Tỷ lệ |
|---|---|---|
| Introduce Vulnerability | 8 | 44.4% |
| Fix Vulnerability | 3 | 16.7% |
| Smooth Upgrade | 4 | 22.2% |
| Invalid Upgrade | 3 | 16.7% |
| **Tổng** | 18 | 100% |

**B.2 — Thống kê quy mô mã nguồn (LOC mỗi implementation)**

| Chỉ số | Giá trị |
|---|---|
| Min | 10 |
| Trung vị (median) | 15.5 |
| Trung bình (mean) | 17.5 |
| Max | 30 |
| Độ lệch chuẩn (std) | 6.8 |

**B.3 — Thống kê biến trạng thái (state variables)**

| Chỉ số | Giá trị |
|---|---|
| Số biến trạng thái trung bình / contract | 2.72 |
| Số storage slot trung bình / contract | 2.72 |
| Tỷ lệ contract có packed slot | 0.0% |
| Tỷ lệ contract dùng dynamic type | 0.0% |

**B.4 — Phân bố loại lỗ hổng** (theo `detector_id`, ground truth)

| detector_id | Số lượng | Tỷ lệ |
|---|---|---|
| `storage-collision-cross-version` | 5 | 29.4% |
| `missing-upgrade-authorization` | 5 | 29.4% |
| `missing-disable-initializers` | 3 | 17.6% |
| `suicidal` | 2 | 11.8% |
| `controlled-delegatecall` | 1 | 5.9% |
| `missing-zero-check` | 1 | 5.9% |

**B.5 — Phân bố mẫu Proxy (proxy pattern)**

| Proxy pattern | Số lượng | Tỷ lệ |
|---|---|---|
| UUPS | 12 | 66.7% |
| Transparent | 6 | 33.3% |
| **Tổng** | 18 | 100% |

---

## 7. ĐÁNH GIÁ FRAMEWORK

### 7.1. Chỉ số đánh giá

```
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 × Precision × Recall / (Precision + Recall)
```

### 7.2. Baseline so sánh

Đo trên benchmark tổng hợp ngoại tuyến 18 cặp (§6.5.2). Phạm vi chấm điểm giới hạn ở 6
detector xuất hiện trong ground truth; dự đoán nằm ngoài phạm vi này bị bỏ qua (quy ước
chấm điểm, xem thiết kế).

| Phương pháp | Precision | Recall | F1-score |
|---|---|---|---|
| Slither đơn thuần | 100.00% | 21.05% | 34.78% |
| USCSA (Li et al., 2026) | 92.26% | 89.67% | 90.95% |
| **EADF (đề tài)** | 100.00% | 100.00% | 100.00% |

Độ chính xác phân loại hành vi nâng cấp (Algorithm 5): **EADF 100.0% (18/18)**, Slither
đơn thuần **38.9% (7/18)**.

> **Diễn giải trung thực:** EADF đạt 100% trên benchmark này vì tập dữ liệu được xây dựng
> có kiểm soát — ground truth phản ánh đúng các lỗ hổng thực sự tồn tại trong mỗi cặp và
> mọi cặp đã được xác minh end-to-end bằng pipeline. Do đó 100% là **cận trên trong điều
> kiện kiểm soát**, không phải bằng chứng về khả năng tổng quát hóa; hiệu năng trên các bản
> nâng cấp mainnet thực tế chưa được đo và thuộc hướng phát triển (§7.3). Ý nghĩa của so
> sánh nằm ở **khoảng
> cách recall**: Slither đơn thuần bỏ sót ~79% lỗ hổng (recall 21.05%) vì không có detector
> cho 3 lớp lỗ hổng đặc thù nâng cấp (storage collision xuyên phiên bản, thiếu
> `_disableInitializers()`, thiếu kiểm soát quyền trên `_authorizeUpgrade`); nó chỉ bắt được
> các lỗ hổng generic (`suicidal`, `controlled-delegatecall`, `missing-zero-check`). Con số
> USCSA trích từ bài báo gốc đo trên tập mainnet, nên chỉ mang tính tham chiếu, không trực
> tiếp so sánh được với benchmark tổng hợp này.

### 7.3. Dataset

- **Đã dùng trong đồ án:** benchmark tổng hợp ngoại tuyến 18 cặp (§6.5.2), khai báo tại
  `eadf/benchmark/manifest.toml`, chạy bằng `eadf evaluate`. Ground truth chính xác theo
  thiết kế, phủ 4 hành vi nâng cấp và 6 lớp lỗ hổng.
- **Hướng phát triển (future work):** mở rộng sang dữ liệu Ethereum mainnet qua Etherscan
  API (`EtherscanSource` đã được hiện thực nhưng nằm ngoài phạm vi đồ án). Tiêu chí dự kiến:
  verified source code + có `Upgraded` event + cả V(i) và V(i+1) đều verified; mục tiêu
  ~200 instance gán nhãn thủ công.

---

## 8. CẤU TRÚC PROJECT ĐỀ XUẤT

```
eadf/
├── README.md
├── SPEC.md                          ← file này
│
├── contracts/                       ← Foundry project (Chương 5 + 7)
│   ├── foundry.toml
│   ├── src/
│   │   ├── secure/
│   │   │   ├── LogicV1.sol          ← UUPS chuẩn
│   │   │   ├── LogicV2.sol          ← upgrade an toàn
│   │   │   └── SecureProxy.sol
│   │   └── vulnerable/
│   │       ├── VulnerableLogic.sol  ← Kịch bản 1: Storage Collision
│   │       ├── UninitLogic.sol      ← Kịch bản 2: Uninitialized
│   │       ├── VulnerableUUPS.sol   ← Kịch bản 3: Unauthorized Upgrade
│   │       └── MaliciousImpl.sol
│   └── test/
│       ├── StorageCollisionTest.t.sol
│       ├── UninitializedTest.t.sol
│       └── UnauthorizedUpgradeTest.t.sol
│
└── eadf/                            ← Python framework (Chương 6)
    ├── requirements.txt
    ├── config.py                    ← API keys, thresholds
    ├── main.py                      ← Entry point: python main.py --proxy 0x...
    │
    ├── module1_collector/
    │   ├── __init__.py
    │   ├── etherscan_client.py      ← Etherscan API wrapper
    │   ├── upgrade_path_tracer.py   ← Parse Upgraded events
    │   └── source_normalizer.py     ← Chuẩn hóa source code
    │
    ├── module2_ast_diff/
    │   ├── __init__.py
    │   ├── ast_builder.py           ← Slither + ANTLR4 fallback
    │   ├── gumtree_differ.py        ← GumTree wrapper
    │   └── storage_slot_mapper.py   ← ★ Storage Slot Differential
    │
    ├── module3_vuln_detector/
    │   ├── __init__.py
    │   ├── slither_runner.py        ← Slither integration
    │   ├── custom_detector.py       ← Storage Collision Cross-Version detector
    │   └── behavior_classifier.py   ← Introduce/Fix/Smooth/Invalid
    │
    ├── module4_matcher/
    │   ├── __init__.py
    │   ├── confidence_scorer.py     ← 5-dimensional scoring
    │   ├── pos_scorer.py
    │   ├── pattern_scorer.py
    │   ├── semantic_scorer.py
    │   └── slot_scorer.py           ← ★ S_slot computation
    │
    ├── module5_reporter/
    │   ├── __init__.py
    │   ├── json_reporter.py         ← JSON output
    │   ├── checklist_generator.py   ← Markdown checklist
    │   └── risk_classifier.py       ← Critical/High/Medium/Low
    │
    └── evaluation/
        ├── dataset_builder.py       ← Thu thập dataset từ mainnet
        ├── ground_truth_labeler.py  ← Gán nhãn thủ công
        └── metrics_calculator.py    ← Precision/Recall/F1
```

---

## 9. DEPENDENCIES

### Contracts (Foundry)
```toml
# foundry.toml
[dependencies]
openzeppelin-contracts-upgradeable = "5.0.0"
openzeppelin/foundry-upgrades = "0.3.0"
```

### Python Framework
```
# requirements.txt
slither-analyzer>=0.10.0
web3>=6.0.0
requests>=2.28.0
gumtree-python>=0.1.0    # hoặc subprocess call GumTree jar
antlr4-python3-runtime>=4.13.0
python-dotenv>=1.0.0
```

### Env Variables
```
# .env
ETHERSCAN_API_KEY=your_key_here
```

---

## 10. CÁCH CHẠY

### Contracts
```bash
cd contracts
forge build
forge test -vvv
forge test --match-test testStorageCollision -vvv
forge test --match-test testUninitializedImpl -vvv
forge test --match-test testUnauthorizedUpgrade -vvv
```

### EADF Framework
```bash
cd eadf
pip install -r requirements.txt
cp .env.example .env  # điền ETHERSCAN_API_KEY

# Phân tích một proxy
python main.py --proxy 0xYourProxyAddress

# Phân tích nhiều proxy từ file
python main.py --input proxies.txt --output reports/

# Đánh giá trên dataset
python evaluation/metrics_calculator.py --dataset data/labeled_200.json
```

---

## 11. TÀI LIỆU THAM KHẢO KỸ THUẬT

1. Li et al., "USCSA: Evolution-aware security analysis for proxy-based upgradeable smart contracts," arXiv:2512.08372v3, 2026
2. Bodell et al., "Proxy Hunting," USENIX Security 2023
3. Zhang et al., "SmartUpdater," IEEE TSE 2025
4. EIP-1967: https://eips.ethereum.org/EIPS/eip-1967
5. EIP-1822: https://eips.ethereum.org/EIPS/eip-1822
6. OpenZeppelin Upgrades: https://docs.openzeppelin.com/upgrades-plugins
7. Slither: https://github.com/crytic/slither
8. GumTree: https://github.com/GumTreeDiff/gumtree
9. Foundry: https://book.getfoundry.sh
10. Ruaro et al., "Not your type!" NDSS 2024
