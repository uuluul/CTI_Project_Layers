from __future__ import annotations

import json

from dotenv import load_dotenv

from .extract_schema import DEFAULT_SYSTEM_PROMPT, EXTRACTION_SCHEMA_DESCRIPTION
from .llm_client import LLMClient
from .to_stix import build_stix_bundle
from .validate_stix import validate_stix_json
from .utils import ensure_dir, read_text_file, write_json, write_text


def build_user_prompt(cti_text: str) -> str:
    return f"""{EXTRACTION_SCHEMA_DESCRIPTION}

CTI_REPORT_TEXT:
{cti_text}
"""


def main() -> None:
    load_dotenv()

    in_path = "data/sample_cti.txt"
    out_dir = "out"
    ensure_dir(out_dir)

    cti_text = read_text_file(in_path)

    llm = LLMClient()
    extracted = llm.extract_json(
        system_prompt=DEFAULT_SYSTEM_PROMPT,
        user_prompt=build_user_prompt(cti_text),
    )
    write_json(f"{out_dir}/extracted.json", extracted)

    stix_json_str = build_stix_bundle(extracted)
    write_text(f"{out_dir}/bundle_stix21.json", stix_json_str)

    ok, val_payload = validate_stix_json(stix_json_str)
    write_json(f"{out_dir}/validator_report.json", val_payload)

    report = {
        "input_file": in_path,
        "validator_pass": ok,
        "validator_counts": (val_payload.get("counts") if isinstance(val_payload, dict) else None),
        "validator_top_issue_types": (val_payload.get("top_issue_types") if isinstance(val_payload, dict) else None),
        "confidence": extracted.get("confidence"),
        "num_indicators": sum(
            len((extracted.get("indicators", {}) or {}).get(k, []))
            for k in ["ipv4", "ipv6", "domains", "urls"]
        ),
        "num_sha256": len((((extracted.get("indicators", {}) or {}).get("hashes", {}) or {}).get("sha256", []))),
        "num_ttps": len(extracted.get("ttps", []) or []),
    }
    write_json(f"{out_dir}/report.json", report)

    print("\n=== PIPELINE DONE ===")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
