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

---

## 7. ĐÁNH GIÁ FRAMEWORK

### 7.1. Chỉ số đánh giá

```
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 × Precision × Recall / (Precision + Recall)
```

### 7.2. Baseline so sánh

| Phương pháp | Precision | Recall | F1-score |
|---|---|---|---|
| Slither đơn thuần | (cập nhật sau thực nghiệm) | | |
| USCSA (Li et al., 2026) | 92.26% | 89.67% | 90.95% |
| **EADF (đề tài)** | (cập nhật sau thực nghiệm) | | |

### 7.3. Dataset

- Nguồn: Ethereum mainnet qua Etherscan API
- Tiêu chí: Verified source code + có `Upgraded` event + cả V(i) và V(i+1) đều verified
- Ground truth: 200 instance được gán nhãn thủ công

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
