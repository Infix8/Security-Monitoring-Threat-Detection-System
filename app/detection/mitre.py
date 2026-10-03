"""MITRE ATT&CK technique catalog used by our detection rules.

Only the techniques we actually reference are listed. IDs and names are
copied from ATT&CK Enterprise v14.
"""
from __future__ import annotations

from typing import TypedDict


class Technique(TypedDict):
    id: str
    name: str
    tactic: str


CATALOG: dict[str, Technique] = {
    "T1110":     {"id": "T1110",     "name": "Brute Force",                       "tactic": "Credential Access"},
    "T1110.001": {"id": "T1110.001", "name": "Brute Force: Password Guessing",    "tactic": "Credential Access"},
    "T1110.003": {"id": "T1110.003", "name": "Brute Force: Password Spraying",    "tactic": "Credential Access"},
    "T1046":     {"id": "T1046",     "name": "Network Service Discovery",         "tactic": "Discovery"},
    "T1078":     {"id": "T1078",     "name": "Valid Accounts",                    "tactic": "Defense Evasion"},
}


def describe(ids: list[str]) -> list[Technique]:
    """Return catalog entries for the given IDs, dropping unknown ones."""
    return [CATALOG[i] for i in ids if i in CATALOG]


def all_techniques() -> list[Technique]:
    return sorted(CATALOG.values(), key=lambda t: t["id"])
