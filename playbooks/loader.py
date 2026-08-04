"""
playbooks/loader.py
===================
Validates and loads playbook YAML files at startup.

Design intent
-------------
Every playbook is validated eagerly when load_playbook() or
load_all_playbooks() is called.  Invalid playbooks raise a clear,
descriptive PlaybookValidationError immediately — they are NEVER
silently accepted.  This mirrors the "fail-loudly at load, not silently
at runtime" principle required for healthcare incident response systems
where a misconfigured playbook discovered mid-incident is unacceptable.

Schema contract (per YAML action entry)
----------------------------------------
Required fields:
  name                          : str  — must be in VALID_ACTION_NAMES
  risk_tier                     : int  — must be in {1, 2, 3, 4}
  requires_approval             : bool
  reversible                    : bool
  asset_criticality_restrictions: list[str] — subset of VALID_CRITICALITIES

Required top-level keys:
  mitre_technique_id            : str  (e.g. "T1110", or "DEFAULT")
  mitre_technique_name          : str
  applies_to_techniques         : list[str] — MITRE IDs this playbook handles;
                                  empty list [] for the default fallback.
  actions                       : list (non-empty)

Helper API
----------
  is_action_permitted(playbook, action_name, asset_criticality)
    -> bool
    Returns True only when the named action exists in the playbook AND
    asset_criticality is not listed in that action's
    asset_criticality_restrictions.  Used by the Phase 3 Planner.

  playbook_for_technique(technique_id, playbooks)
    -> dict
    Returns the playbook whose applies_to_techniques list contains
    technique_id. Falls back to the DEFAULT playbook when no match is
    found. NEVER raises or returns None — unknown techniques are always
    handled by the default fallback.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from playbooks.action_vocabulary import VALID_ACTION_NAMES

# ---------------------------------------------------------------------- #
#  Constants                                                               #
# ---------------------------------------------------------------------- #

VALID_RISK_TIERS: frozenset[int] = frozenset({1, 2, 3, 4})
VALID_CRITICALITIES: frozenset[str] = frozenset({"Low", "Medium", "High", "Critical"})
REQUIRED_ACTION_FIELDS: tuple[str, ...] = (
    "name",
    "risk_tier",
    "requires_approval",
    "reversible",
    "asset_criticality_restrictions",
)
REQUIRED_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "mitre_technique_id",
    "mitre_technique_name",
    "applies_to_techniques",
    "actions",
)

# ---------------------------------------------------------------------- #
#  Exception                                                               #
# ---------------------------------------------------------------------- #


class PlaybookValidationError(ValueError):
    """
    Raised when a playbook YAML fails schema validation.

    Always includes the source file path and the specific field /
    action entry that caused the failure so analysts can fix it quickly.
    """


# ---------------------------------------------------------------------- #
#  Internal validator                                                       #
# ---------------------------------------------------------------------- #


def _validate_playbook(data: dict[str, Any], source_path: str) -> None:
    """
    Raises PlaybookValidationError on the first schema violation found.
    Does not silently skip or warn — caller must fix the playbook.
    """
    # 1. Top-level required keys
    for field in REQUIRED_TOP_LEVEL_FIELDS:
        if field not in data:
            raise PlaybookValidationError(
                f"[{source_path}] Missing required top-level field: '{field}'"
            )

    # 1b. applies_to_techniques must be a list of strings
    applies_to = data["applies_to_techniques"]
    if not isinstance(applies_to, list):
        raise PlaybookValidationError(
            f"[{source_path}] 'applies_to_techniques' must be a list "
            f"(use [] for the default fallback), got {type(applies_to).__name__}"
        )
    for tech in applies_to:
        if not isinstance(tech, str) or not tech.strip():
            raise PlaybookValidationError(
                f"[{source_path}] 'applies_to_techniques' entries must be "
                f"non-empty strings, got {tech!r}"
            )

    actions = data["actions"]

    if not isinstance(actions, list) or len(actions) == 0:
        raise PlaybookValidationError(
            f"[{source_path}] 'actions' must be a non-empty list."
        )

    # 2. Per-action validation
    for idx, action in enumerate(actions):
        entry_id = f"action[{idx}] in [{source_path}]"

        if not isinstance(action, dict):
            raise PlaybookValidationError(
                f"{entry_id}: each action must be a mapping, got {type(action).__name__}"
            )

        # 2a. Required fields present
        for field in REQUIRED_ACTION_FIELDS:
            if field not in action:
                raise PlaybookValidationError(
                    f"{entry_id}: missing required field '{field}'"
                )

        # 2b. name in VALID_ACTION_NAMES
        name = action["name"]
        if name not in VALID_ACTION_NAMES:
            raise PlaybookValidationError(
                f"{entry_id}: action name '{name}' is not in the approved "
                f"vocabulary (action_vocabulary.py).  "
                f"Known names: {sorted(VALID_ACTION_NAMES)}"
            )

        # 2c. risk_tier is integer in {1,2,3,4}
        risk_tier = action["risk_tier"]
        if not isinstance(risk_tier, int) or risk_tier not in VALID_RISK_TIERS:
            raise PlaybookValidationError(
                f"{entry_id}: 'risk_tier' must be an integer in {{1, 2, 3, 4}}, "
                f"got {risk_tier!r}"
            )

        # 2d. requires_approval and reversible are booleans
        for bool_field in ("requires_approval", "reversible"):
            if not isinstance(action[bool_field], bool):
                raise PlaybookValidationError(
                    f"{entry_id}: '{bool_field}' must be a bool (true/false), "
                    f"got {action[bool_field]!r}"
                )

        # 2e. asset_criticality_restrictions is a list of valid criticalities
        restrictions = action["asset_criticality_restrictions"]
        if not isinstance(restrictions, list):
            raise PlaybookValidationError(
                f"{entry_id}: 'asset_criticality_restrictions' must be a list, "
                f"got {type(restrictions).__name__}"
            )
        for r in restrictions:
            if r not in VALID_CRITICALITIES:
                raise PlaybookValidationError(
                    f"{entry_id}: asset_criticality_restrictions contains invalid "
                    f"value '{r}'.  Valid values: {sorted(VALID_CRITICALITIES)}"
                )


# ---------------------------------------------------------------------- #
#  Public API                                                              #
# ---------------------------------------------------------------------- #


def load_playbook(path: str | Path) -> dict[str, Any]:
    """
    Load and validate a single playbook YAML file.

    Returns the validated playbook dict on success.
    Raises PlaybookValidationError if any schema rule is violated.
    Raises FileNotFoundError if the file does not exist.
    """
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        raise PlaybookValidationError(
            f"[{path}] YAML root must be a mapping, got {type(data).__name__}"
        )

    _validate_playbook(data, str(path))
    data.setdefault("playbook_id", path.stem)
    data.setdefault("playbook_version", "v1")
    data["_source_path"] = str(path)
    return data


def load_all_playbooks(directory: str | Path) -> dict[str, dict[str, Any]]:
    """
    Load and validate every *.yaml file in *directory*.

    Returns a dict keyed by MITRE technique ID (e.g. "T1110").
    Raises PlaybookValidationError on the first invalid playbook — all
    playbooks must be valid for the system to start.
    """
    directory = Path(directory)
    playbooks: dict[str, dict[str, Any]] = {}

    for yaml_file in sorted(directory.glob("*.yaml")):
        playbook = load_playbook(yaml_file)
        technique_id = playbook["mitre_technique_id"]
        playbooks[technique_id] = playbook

    return playbooks


def playbook_for_technique(
    technique_id: str,
    playbooks: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """
    Return the playbook that handles *technique_id*.

    Search order:
      1. Scan all loaded playbooks for one whose applies_to_techniques
         list contains *technique_id* (exact string match).
      2. If no match is found, return the DEFAULT playbook.

    Guarantees:
      - NEVER raises on an unmapped technique.
      - NEVER returns None — an unknown technique always gets the
        safe default (Tier 1-only) playbook.

    The DEFAULT playbook is identified by mitre_technique_id == "DEFAULT".
    If it is somehow absent from the loaded set, raises RuntimeError so
    the misconfiguration is visible at startup rather than silently
    returning an empty response plan.
    """
    for playbook in playbooks.values():
        if technique_id in playbook.get("applies_to_techniques", []):
            return playbook

    # Fall back to the DEFAULT playbook
    default = playbooks.get("DEFAULT")
    if default is None:
        raise RuntimeError(
            "DEFAULT playbook is missing from the loaded playbook set. "
            "Ensure playbooks/default.yaml is present and valid."
        )
    return default


def playbook_by_id(
    playbook_id: str,
    playbooks: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """
    Return the playbook with the given stable playbook_id.

    This is used after deterministic playbook resolution has already written
    matched_playbook into IncidentState. It does not perform technique routing.
    """
    for playbook in playbooks.values():
        if playbook.get("playbook_id") == playbook_id:
            return playbook
    return None


def is_action_permitted(
    playbook: dict[str, Any],
    action_name: str,
    asset_criticality: str,
) -> bool:
    """
    Check whether *action_name* is eligible for *asset_criticality*
    according to *playbook*.

    Returns True only when:
      1. The action exists in the playbook's action list.
      2. *asset_criticality* is NOT listed in that action's
         asset_criticality_restrictions.

    This is the gate the Phase 3 Planner must call before proposing
    any action — it must not propose restricted actions automatically.
    A human can still override via the Human Approval Gate.
    """
    for action in playbook.get("actions", []):
        if action["name"] == action_name:
            return asset_criticality not in action["asset_criticality_restrictions"]
    # Action not in playbook at all
    return False
