<!-- ===== SPEC §7.2 baseline table ===== -->

| Phương pháp | Precision | Recall | F1-score |
|---|---|---|---|
| Slither đơn thuần | 100.00% | 21.05% | 34.78% |
| USCSA (Li et al., 2026) | 92.26% | 89.67% | 90.95% |
| **EADF (đề tài)** | 100.00% | 100.00% | 100.00% |


EADF behavior accuracy: 100.0% (18/18); baseline: 38.9% (7/18)

<!-- ===== SPEC §6.5.2 EDA tables ===== -->

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