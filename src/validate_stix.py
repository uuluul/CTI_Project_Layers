#這邊是參考open source 修改的 https://github.com/oasis-open/cti-stix-validator
from __future__ import annotations
from collections import Counter
from typing import Any, Dict, List, Tuple

from stix2validator import ValidationOptions, validate_string


def _issue_to_dict(issue: Any) -> Dict[str, Any]:
    """
    stix2-validator 的 issue 物件在不同版本欄位可能會有差異
    這裡是用 getattr 安全擷取常見欄位。
    """
    return {
        "severity": getattr(issue, "severity", None),   # e.g., "error" / "warning"
        "code": getattr(issue, "code", None),
        "message": getattr(issue, "message", None),
        "path": getattr(issue, "path", None),
        "id": getattr(issue, "id", None),              # 有些版本會有
    }

def validate_stix_json(stix_json_string: str) -> Tuple[bool, Dict[str, Any]]:
    """
    回傳 (is_valid, payload)
    payload 會包含 errors + warnings（用 severity 區分）
    """
    options = ValidationOptions(strict=True, version="2.1")
    results = validate_string(stix_json_string, options)

    issues: List[Dict[str, Any]] = [_issue_to_dict(i) for i in getattr(results, "results", [])]

    errors = [i for i in issues if (i.get("severity") or "").lower() == "error"]
    warnings = [i for i in issues if (i.get("severity") or "").lower() == "warning"]
    unknown = [i for i in issues if i not in errors and i not in warnings]

    # 這邊會統計最常出現的 issue 類型：然後優先用 code 接著才是用 message
    key_list = [(i.get("code") or i.get("message") or "UNKNOWN") for i in issues]
    top_types = Counter(key_list).most_common(15)

    payload: Dict[str, Any] = {
        "stix_version": "2.1",
        "strict": True,
        "is_valid": bool(getattr(results, "is_valid", False)),
        "counts": {
            "total": len(issues),
            "errors": len(errors),
            "warnings": len(warnings),
            "unknown_severity": len(unknown),
        },
        "top_issue_types": top_types,
        "issues": issues,          # 全部 issues（含 warnings）
        "errors": errors,          # 直接看 error
        "warnings": warnings,      # 直接看 warning
        "unknown": unknown,
    }

    return payload["is_valid"], payload

