"""
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
"""

from __future__ import annotations

from pathlib import Path

from app.demo_tui import load_demo_state, reset_demo_state, run_assisted_demo


def test_demo_reset_initializes_state(tmp_path: Path) -> None:
    state_file = tmp_path / "demo_state.json"
    reset_demo_state(state_file)
    state = load_demo_state(state_file)
    assert state.step == "welcome"
    assert state.completed is False


def test_assisted_demo_advances_to_complete(tmp_path: Path) -> None:
    state_file = tmp_path / "demo_state.json"
    answers = iter([
        "yes",  # start demo
        "",  # step1 enter
        "validate",  # step2 validate
        "",  # step3 enter
        "",  # step4 enter
        "",  # step5 enter
        "validate",  # step6 validate
    ])
    out: list[str] = []

    def prompt(message: str) -> str:
        out.append(message)
        return next(answers)

    state = run_assisted_demo(state_path=state_file, prompt_fn=prompt, output_fn=out.append)
    assert state.step == "complete"
    assert state.completed is True

    persisted = load_demo_state(state_file)
    assert persisted.step == "complete"
    assert persisted.completed is True
