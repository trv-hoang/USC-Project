"""Render the EADF Security Checklist as Markdown.

Spec: thesis SPEC.md §5.6 (Markdown template), design spec §8.5.
"""
from __future__ import annotations
from datetime import datetime, timezone

from ..models import Report, RiskLevel


_RISK_BANNER = {
    RiskLevel.CRITICAL: "🔴 CRITICAL",
    RiskLevel.HIGH: "🟠 HIGH",
    RiskLevel.MEDIUM: "🟡 MEDIUM",
    RiskLevel.LOW: "🟢 LOW",
}


def render_checklist(report: Report, *, now: datetime | None = None) -> str:
    """Return the EADF Security Checklist Markdown for `report`."""
    timestamp = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")

    sc = report.storage_collision or {}
    storage_warning_line = ""
    if sc.get("detected"):
        slots = ", ".join(str(s) for s in sc.get("affected_slots", []))
        storage_warning_line = (
            f"- [!] CẢNH BÁO: Phát hiện collision tại slot {slots} — {sc.get('details', '')}\n"
        )

    banner = _RISK_BANNER.get(report.risk_level, str(report.risk_level.value))

    return (
        f"## EADF Security Checklist — {report.proxy_address}\n"
        f"Generated: {timestamp}\n"
        f"\n"
        f"### 1. Storage Layout Compatibility\n"
        f"- [ ] Storage slot mapping V1 vs V2 đã được kiểm tra\n"
        f"- [ ] Không có biến mới chèn vào giữa danh sách khai báo\n"
        f"- [ ] Kiểu dữ liệu của biến hiện có không bị thu hẹp\n"
        f"{storage_warning_line}"
        f"\n"
        f"### 2. Initialization Security\n"
        f"- [ ] _disableInitializers() được gọi trong constructor\n"
        f"- [ ] Hàm initialize() có modifier initializer\n"
        f"- [ ] Reinitializer được dùng đúng cách nếu thêm biến mới\n"
        f"\n"
        f"### 3. Access Control\n"
        f"- [ ] Hàm upgradeTo/upgradeToAndCall có kiểm tra quyền\n"
        f"- [ ] Owner/Admin không phải EOA duy nhất\n"
        f"- [ ] Timelock được áp dụng cho upgrade quan trọng\n"
        f"\n"
        f"### 4. Post-Upgrade Logic\n"
        f"- [ ] Thứ tự external call không thay đổi nguy hiểm\n"
        f"- [ ] Kiểu dữ liệu mới không gây overflow với dữ liệu cũ\n"
        f"- [ ] Biến trạng thái mới được khởi tạo đúng cách\n"
        f"\n"
        f"### 5. Governance\n"
        f"- [ ] Multisig được sử dụng cho quyền nâng cấp\n"
        f"- [ ] Upgrade event được emit đầy đủ để theo dõi\n"
        f"\n"
        f"---\n"
        f"Risk Level: {banner}\n"
    )
