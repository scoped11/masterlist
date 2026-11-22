#!/usr/bin/env python3
"""Validate MasterlistLiveViewer players.json shape (no game required)."""
import json
import sys
from pathlib import Path

REQUIRED_TOP = {"schema", "players"}
PLAYER_KEYS = {"username", "x", "y", "z"}


def validate(doc):
    if not isinstance(doc, dict):
        raise ValueError("root must be object")
    missing = REQUIRED_TOP - set(doc.keys())
    if missing:
        raise ValueError(f"missing keys: {missing}")
    if doc["schema"] != 1:
        raise ValueError("schema must be 1")
    players = doc["players"]
    if not isinstance(players, list):
        raise ValueError("players must be array")
    for i, p in enumerate(players):
        if not isinstance(p, dict):
            raise ValueError(f"players[{i}] not object")
        if not PLAYER_KEYS.issubset(p.keys()):
            raise ValueError(f"players[{i}] missing fields")
    return True


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "../fixtures/sample_players.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    validate(data)
    print(f"OK: {path} ({len(data['players'])} players)")


if __name__ == "__main__":
    main()