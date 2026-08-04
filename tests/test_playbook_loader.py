# pyrefly: ignore  # suppress pyrefly in-memory virtual fragment false positives
"""
tests/test_playbook_loader.py
==============================
Verification tests for the Phase 2 playbook loader and action vocabulary.

Covers:
  • Valid playbook loads successfully without exception.
  • Playbook with unknown action name (not in action_vocabulary.py) fails
    loudly at load time with a clear PlaybookValidationError.
  • Playbook with a missing required field fails loudly at load time.
  • asset_criticality_restrictions correctly excludes an action for a
    Critical asset when queried via is_action_permitted().
  • All four production category playbooks load successfully — regression guard.
  • Unmapped MITRE technique (T9999) resolves to the DEFAULT fallback.
  • Explicit sub-technique matching (T1110.002) routes to CREDENTIAL_ACCESS.
  • Exact-string matching does NOT over-match (T1110.999 unlisted → DEFAULT).
  • All Tier 3 / Tier 4 actions across every playbook have
    requires_approval: true (safety invariant).
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from playbooks.loader import (
    PlaybookValidationError,
    is_action_permitted,
    load_all_playbooks,
    load_playbook,
    playbook_for_technique,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PLAYBOOKS_DIR = Path(__file__).resolve().parents[1] / "playbooks"


def _write_temp_playbook(tmp_path: Path, content: str) -> Path:
    """Write a YAML string to a temp file and return its path."""
    p = tmp_path / "test_playbook.yaml"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# 1. Valid playbook loads successfully
# ---------------------------------------------------------------------------


def test_valid_playbook_loads() -> None:
    """A well-formed category playbook should load without raising any exception."""
    playbook_path = PLAYBOOKS_DIR / "credential_access.yaml"
    data = load_playbook(playbook_path)

    assert data["mitre_technique_id"] == "CREDENTIAL_ACCESS"
    assert isinstance(data["applies_to_techniques"], list)
    assert "T1110" in data["applies_to_techniques"]
    assert "T1110.001" in data["applies_to_techniques"]
    assert isinstance(data["actions"], list)
    assert len(data["actions"]) > 0

    # Every action must have the required fields
    for action in data["actions"]:
        assert "name" in action
        assert "risk_tier" in action
        assert "requires_approval" in action
        assert "reversible" in action
        assert "asset_criticality_restrictions" in action


# ---------------------------------------------------------------------------
# 2. Unknown action name → fails loudly
# ---------------------------------------------------------------------------


def test_invalid_action_name_raises(tmp_path: Path) -> None:
    """
    A playbook containing an action name that is NOT in action_vocabulary.py
    must raise PlaybookValidationError at load time, not silently pass.
    """
    bad_yaml = """
        mitre_technique_id: T9999
        mitre_technique_name: "Test Technique"
        applies_to_techniques: []
        actions:
          - name: HACK_THE_PLANET          # not in VALID_ACTION_NAMES
            risk_tier: 2
            requires_approval: false
            reversible: true
            asset_criticality_restrictions: []
    """
    p = _write_temp_playbook(tmp_path, bad_yaml)

    with pytest.raises(PlaybookValidationError, match="HACK_THE_PLANET"):
        load_playbook(p)


# ---------------------------------------------------------------------------
# 3. Missing required field → fails loudly
# ---------------------------------------------------------------------------


def test_missing_required_field_raises(tmp_path: Path) -> None:
    """
    A playbook action missing a required field (e.g. 'reversible') must
    raise PlaybookValidationError at load time.
    """
    bad_yaml = """
        mitre_technique_id: T9998
        mitre_technique_name: "Test Technique"
        applies_to_techniques: []
        actions:
          - name: NOTIFY_SOC
            risk_tier: 1
            requires_approval: false
            # reversible is intentionally omitted
            asset_criticality_restrictions: []
    """
    p = _write_temp_playbook(tmp_path, bad_yaml)

    with pytest.raises(PlaybookValidationError, match="reversible"):
        load_playbook(p)


def test_missing_top_level_field_raises(tmp_path: Path) -> None:
    """
    A playbook missing a top-level required key (e.g. 'mitre_technique_id')
    must raise PlaybookValidationError at load time.
    """
    bad_yaml = """
        mitre_technique_name: "Test Technique"
        applies_to_techniques: []
        actions:
          - name: NOTIFY_SOC
            risk_tier: 1
            requires_approval: false
            reversible: true
            asset_criticality_restrictions: []
    """
    p = _write_temp_playbook(tmp_path, bad_yaml)

    with pytest.raises(PlaybookValidationError, match="mitre_technique_id"):
        load_playbook(p)


def test_invalid_risk_tier_raises(tmp_path: Path) -> None:
    """
    A playbook with risk_tier outside {1,2,3,4} must fail loudly.
    """
    bad_yaml = """
        mitre_technique_id: T9997
        mitre_technique_name: "Test Technique"
        applies_to_techniques: []
        actions:
          - name: NOTIFY_SOC
            risk_tier: 99           # invalid tier
            requires_approval: false
            reversible: true
            asset_criticality_restrictions: []
    """
    p = _write_temp_playbook(tmp_path, bad_yaml)

    with pytest.raises(PlaybookValidationError, match="risk_tier"):
        load_playbook(p)


# ---------------------------------------------------------------------------
# 4. asset_criticality_restrictions correctly excludes actions
# ---------------------------------------------------------------------------


def test_criticality_restriction_blocks_action() -> None:
    """
    ISOLATE_ENDPOINT has asset_criticality_restrictions: [High, Critical]
    in credential_access.yaml.  is_action_permitted() must return False
    for a Critical asset and True for a Low asset.
    """
    playbook = load_playbook(PLAYBOOKS_DIR / "credential_access.yaml")

    # Should be blocked for Critical assets
    assert is_action_permitted(playbook, "ISOLATE_ENDPOINT", "Critical") is False

    # Should be permitted for Low assets
    assert is_action_permitted(playbook, "ISOLATE_ENDPOINT", "Low") is True


def test_criticality_restriction_ransomware_isolate() -> None:
    """
    In ransomware.yaml, ISOLATE_ENDPOINT is restricted for Critical.
    Verify it is blocked for Critical and permitted for Medium.
    """
    playbook = load_playbook(PLAYBOOKS_DIR / "ransomware.yaml")

    assert is_action_permitted(playbook, "ISOLATE_ENDPOINT", "Critical") is False
    assert is_action_permitted(playbook, "ISOLATE_ENDPOINT", "Medium") is True


def test_unrestricted_action_always_permitted() -> None:
    """
    NOTIFY_SOC has no asset_criticality_restrictions in any playbook.
    It must be permitted for all criticality levels.
    """
    playbook = load_playbook(PLAYBOOKS_DIR / "credential_access.yaml")

    for criticality in ("Low", "Medium", "High", "Critical"):
        assert is_action_permitted(playbook, "NOTIFY_SOC", criticality) is True


def test_unknown_action_not_permitted() -> None:
    """
    Querying an action that doesn't exist in the playbook returns False.
    This guards against the Planner accidentally proposing actions that
    are not in the playbook's allowed set.
    """
    playbook = load_playbook(PLAYBOOKS_DIR / "phishing.yaml")

    # KILL_PROCESS is not listed in phishing.yaml
    assert is_action_permitted(playbook, "KILL_PROCESS", "Low") is False


# ---------------------------------------------------------------------------
# 5. All three production playbooks load successfully
# ---------------------------------------------------------------------------


def test_all_production_playbooks_load() -> None:
    """
    Load all YAML files in the playbooks directory and assert none raise.
    This is a regression guard: editing a production YAML must not
    silently break the vocabulary contract.
    """
    playbooks = load_all_playbooks(PLAYBOOKS_DIR)

    # All four category playbooks + DEFAULT must be present
    assert "CREDENTIAL_ACCESS" in playbooks  # credential_access.yaml
    assert "RANSOMWARE" in playbooks          # ransomware.yaml
    assert "PHISHING" in playbooks            # phishing.yaml
    assert "DEFAULT" in playbooks             # default.yaml (fallback)

    # Spot-check: each has at least one action
    for technique_id, pb in playbooks.items():
        assert len(pb["actions"]) > 0, f"{technique_id} has no actions"


# ---------------------------------------------------------------------------
# 6. Unmapped technique resolves to default
# ---------------------------------------------------------------------------


def test_unmapped_technique_resolves_to_default() -> None:
    """
    A MITRE technique ID not covered by any specific playbook must resolve
    to the DEFAULT fallback playbook, never raise, and never return None.
    """
    playbooks = load_all_playbooks(PLAYBOOKS_DIR)

    result = playbook_for_technique("T9999", playbooks)

    assert result is not None
    assert result["mitre_technique_id"] == "DEFAULT"
    # Default must only contain Tier 1 actions (safety invariant)
    for action in result["actions"]:
        assert action["risk_tier"] == 1, (
            f"Default playbook action '{action['name']}' has "
            f"risk_tier={action['risk_tier']} — only Tier 1 allowed"
        )


def test_known_technique_resolves_to_correct_playbook() -> None:
    """
    A known parent technique ID routes to its category playbook.
    """
    playbooks = load_all_playbooks(PLAYBOOKS_DIR)

    result_cred = playbook_for_technique("T1110", playbooks)
    assert result_cred["mitre_technique_id"] == "CREDENTIAL_ACCESS"

    result_ransomware = playbook_for_technique("T1486", playbooks)
    assert result_ransomware["mitre_technique_id"] == "RANSOMWARE"

    result_phishing = playbook_for_technique("T1566", playbooks)
    assert result_phishing["mitre_technique_id"] == "PHISHING"


# ---------------------------------------------------------------------------
# 7. Tier 3 / Tier 4 safety invariant: requires_approval must be True
# ---------------------------------------------------------------------------


def test_tier3_tier4_actions_always_require_approval() -> None:
    """
    Safety invariant: every action with risk_tier >= 3 across ALL production
    playbooks MUST have requires_approval=True.

    This is not a style preference — Tier 3 (host containment) and Tier 4
    (identity/process termination) actions on healthcare assets can disrupt
    clinical operations or patient care.  They must never run without a
    human explicitly approving them.

    If this test fails, fix the offending playbook entry.
    """
    playbooks = load_all_playbooks(PLAYBOOKS_DIR)
    violations: list[str] = []

    for technique_id, playbook in playbooks.items():
        for action in playbook["actions"]:
            if action["risk_tier"] >= 3 and not action["requires_approval"]:
                violations.append(
                    f"[{technique_id}] action '{action['name']}' "
                    f"has risk_tier={action['risk_tier']} but "
                    f"requires_approval=False"
                )

    assert violations == [], (
        "The following Tier 3/4 actions are missing requires_approval=True:\n"
        + "\n".join(f"  - {v}" for v in violations)
    )


# ---------------------------------------------------------------------------
# 8. Exact-string matching: sub-technique routing and no-overreach tests
# ---------------------------------------------------------------------------


def test_explicitly_listed_subtechnique_routes_correctly() -> None:
    """
    Matching is exact-string-in-list only (no prefix/glob/wildcard).

    T1110.002 (Password Cracking) is explicitly listed in
    credential_access.yaml.  It must route to CREDENTIAL_ACCESS,
    not DEFAULT.

    T1566.003 (Spearphishing via Service) is explicitly listed in
    phishing.yaml. It must route to PHISHING.
    """
    playbooks = load_all_playbooks(PLAYBOOKS_DIR)

    # T1110.002 is explicitly in credential_access.yaml applies_to_techniques
    result = playbook_for_technique("T1110.002", playbooks)
    assert result["mitre_technique_id"] == "CREDENTIAL_ACCESS", (
        "T1110.002 should route to CREDENTIAL_ACCESS (explicitly listed)"
    )

    # T1566.003 is explicitly in phishing.yaml applies_to_techniques
    result = playbook_for_technique("T1566.003", playbooks)
    assert result["mitre_technique_id"] == "PHISHING", (
        "T1566.003 should route to PHISHING (explicitly listed)"
    )

    # T1489 is explicitly in ransomware.yaml applies_to_techniques
    result = playbook_for_technique("T1489", playbooks)
    assert result["mitre_technique_id"] == "RANSOMWARE", (
        "T1489 should route to RANSOMWARE (explicitly listed)"
    )


def test_unlisted_subtechnique_falls_to_default() -> None:
    """
    Exact-string matching must NOT over-match via prefix/pattern inference.

    T1110.999 is NOT in any playbook's applies_to_techniques list.
    Despite sharing the T1110 prefix with CREDENTIAL_ACCESS entries,
    it must fall through to DEFAULT — proving there is no implicit
    prefix matching.

    This test enforces the "explicit is safer than implicit" matching
    design decision documented in each playbook's YAML header.
    """
    playbooks = load_all_playbooks(PLAYBOOKS_DIR)

    # T1110.999 is unlisted everywhere — must not match CREDENTIAL_ACCESS
    result = playbook_for_technique("T1110.999", playbooks)
    assert result["mitre_technique_id"] == "DEFAULT", (
        "T1110.999 is not explicitly listed; must fall through to DEFAULT "
        "proving exact-string matching with no prefix over-reach."
    )

    # T1566.999 is unlisted — must not match PHISHING
    result = playbook_for_technique("T1566.999", playbooks)
    assert result["mitre_technique_id"] == "DEFAULT", (
        "T1566.999 is not listed; must fall through to DEFAULT."
    )
