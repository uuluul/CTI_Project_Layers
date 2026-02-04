from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# STIX 2.1 的物件類別
from stix2.v21 import (
    Bundle,
    Identity,
    Indicator,
    Malware,
    Tool,
    AttackPattern,
    Relationship,
    MarkingDefinition,
    ExternalReference,
    TLP_AMBER,
)

def _now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def _make_tlp_marking(tlp: str = "TLP:AMBER") -> MarkingDefinition:
    # 直接回傳 stix2 內建的標準 TLP:AMBER 物件
    # 這樣 ID 就會是正確的 (marking-definition--f88d31f6...)
    return TLP_AMBER

def _mitre_external_ref(technique_id: str) -> ExternalReference:
    # MITRE ATT&CK technique 的標準外部參考
    return ExternalReference(
        source_name="mitre-attack",
        external_id=technique_id,
        url=f"https://attack.mitre.org/techniques/{technique_id}/",
    )

def _stix_indicators(ind: Dict[str, Any], created_by_ref: str, marking_id: str, confidence: Optional[int]) -> List[Indicator]:
    indicators: List[Indicator] = []

    def _add_indicator(name: str, pattern: str) -> None:
        indicators.append(
            Indicator(
                name=name,
                pattern_type="stix",
                pattern=pattern,
                valid_from=_now(),
                created_by_ref=created_by_ref,
                object_marking_refs=[marking_id],
                confidence=confidence,
                labels=["cti", "llm-generated"],
            )
        )

    # IPs
    for ip in (ind.get("ipv4", []) or []) + (ind.get("ipv6", []) or []):
        if ":" in ip:
            _add_indicator(f"IP indicator {ip}", f"[ipv6-addr:value = '{ip}']")
        else:
            _add_indicator(f"IP indicator {ip}", f"[ipv4-addr:value = '{ip}']")

    # Domains
    for d in ind.get("domains", []) or []:
        _add_indicator(f"Domain indicator {d}", f"[domain-name:value = '{d}']")

    # URLs
    for u in ind.get("urls", []) or []:
        _add_indicator(f"URL indicator {u}", f"[url:value = '{u}']")

    # Hashes
    hashes = ind.get("hashes", {}) or {}
    for algo in ["md5", "sha1", "sha256"]:
        for h in hashes.get(algo, []) or []:
            key = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[algo]
            _add_indicator(f"File hash {key} {h[:12]}...", f"[file:hashes.'{key}' = '{h}']")

    return indicators

def build_stix_bundle(extracted: Dict[str, Any]) -> str:
    # 抽取 JSON 裡的 confidence（0-100）
    conf = extracted.get("confidence")
    confidence = int(conf) if isinstance(conf, int) else None

    # Producer identity：代表誰產生這份 STIX
    producer = Identity(
        name="LLM CTI-to-STIX PoC",
        identity_class="organization",
        created=_now(),
        modified=_now(),
    )
    # 這邊先加 TLP，這樣後面的 SOC 也可以用得到
    marking = _make_tlp_marking("TLP:AMBER")

    objects: List[Any] = [producer, marking]

    # Indicators
    indicators_block = extracted.get("indicators", {}) or {}
    indicators = _stix_indicators(
        indicators_block,
        created_by_ref=producer.id,
        marking_id=marking.id,
        confidence=confidence,
    )
    objects.extend(indicators)

    # Malware/Tools
    for name in extracted.get("malware_or_tool", []) or []:
        lower = name.lower()
        if "malware" in lower:
            objects.append(
                Malware(
                    name=name,
                    is_family=False,
                    created_by_ref=producer.id,
                    object_marking_refs=[marking.id],
                    confidence=confidence,
                    labels=["cti", "llm-generated"],
                )
            )
        else:
            objects.append(
                Tool(
                    name=name,
                    created_by_ref=producer.id,
                    object_marking_refs=[marking.id],
                    confidence=confidence,
                    labels=["cti", "llm-generated"],
                )
            )

    # Attack Patterns（TTPs）
    ttp_objs: List[AttackPattern] = []
    for t in extracted.get("ttps", []) or []:
        tech_id = t.get("mitre_technique_id")
        ext_refs = []
        if isinstance(tech_id, str) and tech_id.strip():
            ext_refs.append(_mitre_external_ref(tech_id.strip()))

        ap = AttackPattern(
            name=t.get("name") or "Attack Pattern",
            description=t.get("description") or "",
            created_by_ref=producer.id,
            object_marking_refs=[marking.id],
            confidence=confidence,
            labels=["ttp", "cti", "llm-generated"],
            external_references=ext_refs if ext_refs else None,
        )
        ttp_objs.append(ap)
        objects.append(ap)

    # Relationships
    for ind_obj in indicators:
        for ap in ttp_objs[:3]:
            objects.append(
                Relationship(
                    relationship_type="indicates",
                    source_ref=ind_obj.id,
                    target_ref=ap.id,
                    created_by_ref=producer.id,
                    object_marking_refs=[marking.id],
                    confidence=confidence,
                )
            )

    bundle = Bundle(objects=objects, allow_custom=False)
    return bundle.serialize(pretty=True)
