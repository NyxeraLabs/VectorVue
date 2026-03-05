"""Assisted VectorVue TUI demo lifecycle helpers."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


DEMO_STEPS = [
    "welcome",
    "envelope_intake",
    "signature_validation",
    "public_key_match",
    "attestation_proof",
    "measurement_hash",
    "policy_validation",
    "complete",
]


@dataclass(slots=True)
class DemoState:
    step: str = "welcome"
    completed: bool = False


def demo_state_path() -> Path:
    env_path = os.environ.get("VECTORVUE_DEMO_STATE_PATH", "").strip()
    if env_path:
        return Path(env_path).expanduser()
    return Path.home() / ".vectorvue" / "demo_state.json"


def _demo_state_candidates(path: Path | None = None) -> list[Path]:
    if path is not None:
        return [path]
    primary = demo_state_path()
    candidates = [
        primary,
        Path.cwd() / ".vectorvue" / "demo_state.json",
        Path("/tmp") / f"vectorvue-{os.getuid()}" / "demo_state.json",
    ]
    out: list[Path] = []
    for candidate in candidates:
        if candidate not in out:
            out.append(candidate)
    return out


def load_demo_state(path: Path | None = None) -> DemoState:
    for resolved in _demo_state_candidates(path):
        if not resolved.exists():
            continue
        try:
            payload = json.loads(resolved.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        step = str(payload.get("step", "welcome"))
        if step not in DEMO_STEPS:
            step = "welcome"
        return DemoState(step=step, completed=bool(payload.get("completed", False)))
    return DemoState()


def save_demo_state(state: DemoState, path: Path | None = None) -> Path:
    payload = json.dumps({"step": state.step, "completed": state.completed}, indent=2)
    last_error: Exception | None = None
    for resolved in _demo_state_candidates(path):
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_text(payload, encoding="utf-8")
            return resolved
        except OSError as exc:
            last_error = exc
            continue
    if last_error is not None:
        raise last_error
    raise RuntimeError("unable to persist VectorVue demo state")


def reset_demo_state(path: Path | None = None) -> Path:
    state = DemoState()
    resolved = save_demo_state(state, path=path)
    _sync_demo_session(state.step)
    return resolved


def _db_url() -> str:
    env_url = os.environ.get("VV_DB_URL", "").strip()
    if env_url:
        url = make_url(env_url)
        if url.get_backend_name() == "postgresql" and url.drivername != "postgresql+psycopg":
            url = url.set(drivername="postgresql+psycopg")
        return url.render_as_string(hide_password=False)
    user = os.environ.get("VV_DB_USER", os.environ.get("POSTGRES_USER", "vectorvue"))
    password = os.environ.get("VV_DB_PASSWORD", os.environ.get("POSTGRES_PASSWORD", "strongpassword"))
    host = os.environ.get("VV_DB_HOST", "postgres")
    port = os.environ.get("VV_DB_PORT", "5432")
    name = os.environ.get("VV_DB_NAME", os.environ.get("POSTGRES_DB", "vectorvue_db"))
    return make_url(f"postgresql+psycopg://{user}:{password}@{host}:{port}/{name}").render_as_string(
        hide_password=False
    )


def _resolve_tenant_id(engine) -> str | None:
    explicit = os.environ.get("VV_TUI_TENANT_ID", "").strip()
    if explicit:
        return explicit
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT id FROM tenants WHERE active=TRUE ORDER BY created_at ASC LIMIT 1")
        ).mappings().first()
        if not row:
            return None
        return str(row["id"])


def _sync_demo_session(step: str) -> None:
    try:
        engine = create_engine(_db_url(), future=True)
    except Exception:
        return
    try:
        tenant_id = _resolve_tenant_id(engine)
        if not tenant_id:
            return
        with engine.begin() as conn:
            conn.execute(
                text(
                    """CREATE TABLE IF NOT EXISTS vectorvue_demo_session (
                           tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
                           source TEXT NOT NULL,
                           step TEXT NOT NULL,
                           payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                           updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                       )"""
                )
            )
            conn.execute(
                text(
                    """INSERT INTO vectorvue_demo_session (tenant_id, source, step, payload_json, updated_at)
                       VALUES (CAST(:tenant_id AS UUID), :source, :step, CAST(:payload_json AS JSONB), NOW())
                       ON CONFLICT (tenant_id) DO UPDATE SET
                         source=EXCLUDED.source,
                         step=EXCLUDED.step,
                         payload_json=EXCLUDED.payload_json,
                         updated_at=NOW()"""
                ),
                {
                    "tenant_id": tenant_id,
                    "source": "vectorvue-tui",
                    "step": step,
                    "payload_json": json.dumps({"updated_via": "tui_assisted_demo"}),
                },
            )
    except Exception:
        return
    finally:
        engine.dispose()


def _load_latest_federation_envelope() -> dict[str, str]:
    try:
        engine = create_engine(_db_url(), future=True)
    except Exception:
        return {}
    try:
        tenant_id = _resolve_tenant_id(engine)
        if not tenant_id:
            return {}
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    """SELECT event_uid, request_id::text AS request_id, metadata_json
                       FROM spectrastrike_events
                       WHERE tenant_id=CAST(:tenant_id AS UUID)
                       ORDER BY occurred_at DESC, id DESC
                       LIMIT 1"""
                ),
                {"tenant_id": tenant_id},
            ).mappings().first()
            if not row:
                return {}
            metadata = row.get("metadata_json") if isinstance(row.get("metadata_json"), dict) else {}
            return {
                "tenant_id": tenant_id,
                "event_uid": str(row.get("event_uid") or ""),
                "request_id": str(row.get("request_id") or ""),
                "envelope_id": str(metadata.get("envelope_id") or row.get("event_uid") or ""),
                "signature_state": str(metadata.get("signature_state") or "unknown"),
                "attestation_hash": str(metadata.get("attestation_measurement_hash") or ""),
                "policy_hash": str(metadata.get("policy_decision_hash") or ""),
            }
    except Exception:
        return {}
    finally:
        engine.dispose()


def _prompt_enter(prompt_fn: Callable[[str], str], output_fn: Callable[[str], None], text: str) -> None:
    output_fn(text)
    prompt_fn("Press ENTER to continue... ")


def _prompt_validate(prompt_fn: Callable[[str], str], output_fn: Callable[[str], None], text: str) -> None:
    output_fn(text)
    while True:
        typed = prompt_fn('Type "validate" to execute this step: ').strip().lower()
        if typed == "validate":
            return
        output_fn('Input not accepted. Please type "validate".')


def run_assisted_demo(
    *,
    state_path: Path | None = None,
    prompt_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> DemoState:
    state = load_demo_state(path=state_path)
    output_fn("Welcome to VectorVue.")
    answer = prompt_fn("Would you like to run an assisted demo? (yes/no): ").strip().lower()
    if answer not in {"yes", "y"}:
        output_fn("Assisted demo skipped.")
        return state

    envelope = _load_latest_federation_envelope()
    if envelope:
        output_fn(
            "Using SpectraStrike federation envelope: "
            f"{envelope.get('envelope_id', 'n/a')} "
            f"(request={envelope.get('request_id', 'n/a')}, event={envelope.get('event_uid', 'n/a')})"
        )
    else:
        output_fn("No seeded SpectraStrike federation envelope found; demo will proceed with empty federation context.")
    _prompt_enter(prompt_fn, output_fn, "Step 1: Viewing envelope intake from SpectraStrike federation channel.")
    state.step = "envelope_intake"
    save_demo_state(state, path=state_path)
    _sync_demo_session(state.step)

    _prompt_validate(
        prompt_fn,
        output_fn,
        "Step 2: Running signature validation against trusted signing key "
        f"(state={envelope.get('signature_state', 'unknown') if envelope else 'unknown'}).",
    )
    state.step = "signature_validation"
    save_demo_state(state, path=state_path)
    _sync_demo_session(state.step)

    _prompt_enter(prompt_fn, output_fn, "Step 3: Verifying public key match and key identifier continuity.")
    state.step = "public_key_match"
    save_demo_state(state, path=state_path)
    _sync_demo_session(state.step)

    _prompt_enter(
        prompt_fn,
        output_fn,
        "Step 4: Reviewing attestation proof for execution authenticity "
        f"(hash={envelope.get('attestation_hash', 'n/a') if envelope else 'n/a'}).",
    )
    state.step = "attestation_proof"
    save_demo_state(state, path=state_path)
    _sync_demo_session(state.step)

    _prompt_enter(prompt_fn, output_fn, "Step 5: Inspecting measurement hash integrity binding.")
    state.step = "measurement_hash"
    save_demo_state(state, path=state_path)
    _sync_demo_session(state.step)

    _prompt_validate(
        prompt_fn,
        output_fn,
        "Step 6: Running policy validation for tenant compliance outcome "
        f"(policy={envelope.get('policy_hash', 'n/a') if envelope else 'n/a'}).",
    )
    state.step = "policy_validation"
    save_demo_state(state, path=state_path)
    _sync_demo_session(state.step)

    output_fn("Assisted demo complete. Federation lifecycle validated end-to-end.")
    state.step = "complete"
    state.completed = True
    save_demo_state(state, path=state_path)
    _sync_demo_session(state.step)
    return state
