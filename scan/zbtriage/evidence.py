"""Explain matched indicator provenance and link existing evidence conservatively.

No scoring, verdict escalation, attribution inference or time-only causal links.
"""
import json
import datetime
import os
import re

from .contract import sanitize_untrusted


def _ev_modified_key(value):
    """Order validated UTC timestamps without losing fractional precision.

    Date-only values are retained for legacy publisher metadata. Unparseable
    values cannot establish that a withdrawal is newer than an active version.
    """
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2})(?:T(\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z)?", value)
    if not match:
        return None
    whole = match[1] + "T" + (match[2] or "00:00:00")
    try:
        when = datetime.datetime.fromisoformat(whole)
    except ValueError:
        return None
    # Fractions sort lexically once trailing zeroes are removed; equal instants
    # remain equal even when publishers use different decimal precision.
    return when, (match[3] or "").rstrip("0")


def _withdrawn_only(records):
    """True only when every publisher that lists the indicator has withdrawn it.

    Records are grouped by publisher, or by source when no publisher is named,
    and within that by STIX object id. Versions belong to one object, so one
    publisher revoking an object leaves its other, still active objects for the
    same value in force. Records without an id (plain lists) group as before.
    Within a group the newest version decides, by STIX `modified`, so a stale
    cached copy of a publisher's active bundle loaded beside that same
    publisher's later withdrawal no longer keeps the indicator live. STIX
    requires a newer `modified` on a revoked version, so the newest one is the
    version the publisher intends. A copy that cannot be dated and is not revoked
    keeps the indicator live, and so does a tie at the newest date unless every
    tied copy is revoked. Different publishers still disagree honestly: one
    current active listing anywhere keeps the match actionable.
    """
    groups = {}
    for record in records:
        key = (record.get("publisher") or record.get("source") or "", record.get("id") or "")
        groups.setdefault(key, []).append(record)
    if not groups:
        return False
    for group in groups.values():
        versions = [(_ev_modified_key(r.get("modified")), r) for r in group]
        dated = [(key, r) for key, r in versions if key is not None]
        undated = [r for key, r in versions if key is None]
        if any(r.get("revoked") is not True for r in undated):
            return False
        if dated:
            newest = max(key for key, _ in dated)
            if not all(r.get("revoked") is True for key, r in dated if key == newest):
                return False
    return True


def evidence_enrich(module_dicts, iocs):
    lookup = {}
    for ind in iocs.indicators:
        lookup.setdefault(ind.value, []).append(ind)
    for md in module_dicts.values():
        for hit in md.get("hits", []):
            contexts, cautions, withdrawals, all_records = [], [], [], []
            for ind in lookup.get(hit["indicator"], []):
                if not hit.get("kind") and ind.type not in ("domain", "ip", "sha256"):
                    continue
                if hit.get("kind") and hit["kind"] != ind.type:
                    continue
                hit["kind"] = ind.type
                records = [json.loads(raw) for raw in ind.contexts] if ind.contexts else [
                    {"source": ind.source, "artifact_type": ind.type, "role": ind.tier}]
                for record in records:
                    withdrawals.append(record.get("revoked") is True)
                    all_records.append(record)
                    clean = {k: [sanitize_untrusted(v) for v in value] if isinstance(value, list)
                             else sanitize_untrusted(value) for k, value in record.items()}
                    if clean not in contexts:
                        contexts.append(clean)
                    if record.get("revoked"):
                        cautions.append("A publisher withdrew this indicator. This is a historical match, not confirmation of a current threat.")
                    if record.get("valid_until"):
                        cautions.append("A publisher supplied an end date. Compare it with the artifact time; current ownership is unverified.")
                if ind.type == "ip":
                    cautions.append("IP addresses can be reassigned or shared; a match does not establish who operated the endpoint at the time.")
                if ind.tier == "historical":
                    cautions.append("Historical campaign indicator; present-day malicious use is not established.")
                if ind.tier == "reclaimable":
                    cautions.append("This name may have passed to someone else since the report; only a match "
                                    "dated to the campaign period is meaningful.")
            hit["indicator_context"] = contexts
            hit["context_cautions"] = list(dict.fromkeys(cautions))
            hit["withdrawn_only"] = _withdrawn_only(all_records)
            hit["withdrawal_present"] = any(withdrawals)


def evidence_correlations(module_dicts):
    groups = {}
    for module, md in module_dicts.items():
        for n, hit in enumerate(md.get("hits", [])):
            key = (hit.get("kind", ""), hit["indicator"])
            # Readers often report several rows from one physical artifact.
            # A row is supporting detail, never another independent source.
            location = re.sub(r":record \d+$|:\d+$", "", str(hit.get("artifact") or hit.get("location") or ""))
            artifact = os.path.normcase(os.path.normpath(location))
            entry = groups.setdefault(key, {"artifacts": {}, "seen": set()})
            record = (artifact, hit.get("observed", ""), hit.get("evidence", ""), hit.get("detail", ""))
            if record in entry["seen"]:
                continue
            entry["seen"].add(record)
            entry["artifacts"].setdefault(artifact, []).append({
                "module": module, "hit_index": n, "observed": hit.get("observed", ""),
                "evidence": hit.get("evidence", ""), "location": hit.get("location", ""),
                "stage": {"received": "message", "contacted": "contact", "on-disk": "file presence",
                          "ran-command": "command", "execution-record": "historical execution record",
                          "inventory-record": "historical file inventory", "persistence": "startup configuration"}.get(hit.get("evidence"), "other record")})
    out = []
    for (kind, indicator), entry in groups.items():
        if len(entry["artifacts"]) < 2:
            continue
        records = [record for records in entry["artifacts"].values() for record in records]
        def time_key(record):
            try:
                return datetime.datetime.fromisoformat(str(record["observed"] or "").replace("Z", "+00:00")).astimezone(datetime.timezone.utc).timestamp()
            except (ValueError, TypeError, OverflowError, OSError, AttributeError):
                return float("inf")
        records.sort(key=time_key)
        out.append({"indicator": indicator, "kind": kind,
                    "relationship": "same published indicator in multiple artifacts",
                    "artifact_count": len(entry["artifacts"]),
                    "records": records, "ordering": "dated records oldest first; undated records last; no causal inference",
                    "interpretation": "Supporting records, not proof of a causal sequence, independent confirmation or infection. Duplicate records do not strengthen the verdict. Times can be missing or inconsistent. Evidence grades are unchanged."})
    return out
