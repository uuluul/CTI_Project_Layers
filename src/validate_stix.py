#這邊是參考open source 修改的 https://github.com/oasis-open/cti-stix-validator
from __future__ import annotations
from collections import Counter
from typing import Any, Dict, List, Tuple

from stix2validator import ValidationOptions, validate_string


def _issue_to_dict(issue: Any) -> Dict[str, Any]:
    return {
        "severity": getattr(issue, "severity", None),
        "code": getattr(issue, "code", None),
        "message": getattr(issue, "message", None),
        "path": getattr(issue, "path", None),
        "id": getattr(issue, "id", None),    
    }

def validate_stix_json(stix_json_string: str) -> Tuple[bool, Dict[str, Any]]:
    """
    payload 包含 errors + warnings
    """
    options = ValidationOptions(strict=True, version="2.1")
    results = validate_string(stix_json_string, options)

    issues: List[Dict[str, Any]] = [_issue_to_dict(i) for i in getattr(results, "results", [])]

    errors = [i for i in issues if (i.get("severity") or "").lower() == "error"]
    warnings = [i for i in issues if (i.get("severity") or "").lower() == "warning"]
    unknown = [i for i in issues if i not in errors and i not in warnings]

    # 這邊會統計最常出現的 issue 類型
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
        "issues": issues,        
        "errors": errors,        
        "warnings": warnings,      
        "unknown": unknown,
    }

    return payload["is_valid"], payload

