#!/usr/bin/env python3
import subprocess
import sys
import os
import shutil
import argparse
from collections import Counter
from datetime import datetime

# ==========================================
# CONFIGURATION MAP (The "Plan")
# ==========================================
# Mapped from git_history.txt (chronological order, oldest -> newest),
# grouped to align with docs/ROADMAP.md phase naming.
PROJECT_CONFIG = [
    {
        "phase_name": "PHASE 0-2: Foundation, Operational Intelligence, Advanced Runtime",
        "features": [
            {
                "name": "feat/phase0-2-foundation-runtime",
                "commits": [
                    "53eed69",  # Initial commit
                    "23123d1",  # Added all the project structure and files and readme
                    "901cbc9",  # Corrected the file names
                    "e2e9439",  # v1.3 Implemented with a python interactive shell and full database, directories and PDF generation
                    "b513722",  # README UPDATED
                    "f8b8013",  # implement finding lifecycle management and golden library v1.6
                    "7f942ff",  # Corrected usage function
                    "657eaa2",  # Corrected splashscreen
                    "0ad2801",  # Corrected the splash part2
                    "c954a89",  # Readme correction
                    "adc63a5",  # Readme correction part2 splashscreen
                    "7985fce",  # Corrected mistypo in README.md
                    "f612e8f",  # Adding PDF Look improvements in progress
                    "d011203",  # Updated README
                    "d9a57d9",  # VectorVue v2.1 Released
                    "fce81a2",  # Updated user guide manuals
                    "c28399d",  # Updated README
                    "1a72059",  # Updated README
                    "900e77f",  # Updated v2.1
                    "f858b7e",  # MITRE INTEL implemented
                    "78cbc9a",  # SHUTDOWN functionality improved
                    "38ea8ff",  # v2.5 implemented
                    "68d688b",  # v2.5 updated
                    "dbef3ce",  # v3.0 first upgrades
                ]
            }
        ],
        "qa_fixes": [],
        "release_tag": "v-roadmap-phase0-2"
    },
    {
        "phase_name": "PHASE 3: Reporting & Export Engine",
        "features": [
            {
                "name": "feat/phase3-reporting-export",
                "commits": [
                    "ac23756",  # Phase 3.4 done
                    "32d69b9",  # Phase 3.5 Done
                    "55b2757",  # Updated Documentation, Readme and Roadmap
                    "2c186d6",  # Updated README
                    "141b084",  # Updated README fixed banner ASCII art
                    "db6fc0c",  # Phase3 from Roadmap done
                    "2a10238",  # Phase3 fixed vv_core.py two warnings
                ]
            }
        ],
        "qa_fixes": [],
        "release_tag": "v-roadmap-phase3"
    },
    {
        "phase_name": "PHASE 4: Multi-Team & Federation",
        "features": [
            {
                "name": "feat/phase4-multi-team-federation",
                "commits": [
                    "216bcf1",  # Phase4 Done
                ]
            }
        ],
        "qa_fixes": [],
        "release_tag": "v-roadmap-phase4"
    },
    {
        "phase_name": "PHASE 5: Advanced Threat Intelligence",
        "features": [
            {
                "name": "feat/phase5-threat-intelligence",
                "commits": [
                    "0d77fda",  # Phase-5 Done
                ]
            }
        ],
        "qa_fixes": [],
        "release_tag": "v-roadmap-phase5"
    },
    {
        "phase_name": "PHASE 5.5: Operational Cognition & Decision Layer",
        "features": [
            {
                "name": "feat/phase5-5-operational-cognition",
                "commits": [
                    "f0b0b0c",  # Phase 5.5 Very Important 10 new modules are implemented
                    "b2155f6",  # Architecture_Spec Doc updated
                    "26b6c34",  # Updated ROADMAP
                    "636d714",  # Updated README
                    "c03d284",  # Updated bad LICENSE BADGE in README
                    "219c048",  # Update README license notice
                    "ba5d9f5",  # Update LICENSE and source/docs headers and PHASE 5.5 DONE
                    "55a43cc",  # Version 3.7.1 published
                    "596ec14",  # Updated docs
                    "36e02b9",  # Updated ROADMAP
                    "af05379",  # Phase 5.5 and v3.8 fully implemented under testing
                    "550a2ce",  # Improved the TUI, GROUPS and TABS and also improved docs
                    "589d679",  # Improved the TUI, GROUPS and TABS and also improved docs
                    "4fe14aa",  # Added toughs for each phase of the ROADMAP
                    "03f78c5",  # Adjusted Login/Register View
                ]
            }
        ],
        "qa_fixes": [],
        "release_tag": "v-roadmap-phase5-5"
    },
    {
        "phase_name": "PHASE 5.6: PostgreSQL Migration & Container Baseline",
        "features": [
            {
                "name": "feat/phase5-6-postgres-container-baseline",
                "commits": [
                    "cfb38fe",  # Phase 5.6 PostGreSQL Dockerized Migration DONE
                    "3aa75c3",  # Added License Headers to all files to reflect the License migration from version 3.8
                    "0f9e115",  # Updated license header too loock minimal in documentation files
                    "65306c3",  # Updated license header too look minimal in documentation files but visible
                ]
            }
        ],
        "qa_fixes": [],
        "release_tag": "v-roadmap-phase5-6"
    },
    {
        "phase_name": "PHASE 6: Deployment & Hardening",
        "features": [
            {
                "name": "feat/phase6-deployment-hardening",
                "commits": [
                    "57dd8fc",  # Phase-6 of roadmap done and version 3.9 officialy released
                    "138df92",  # Updated ROADMAP
                ]
            }
        ],
        "qa_fixes": [],
        "release_tag": "v-roadmap-phase6"
    },
    {
        "phase_name": "PHASE 6.5: Client Isolation & Pre-Portal Preparation",
        "features": [
            {
                "name": "feat/phase6-5-client-isolation-api",
                "commits": [
                    "b8a6988",  # Phase 6.5 DONE v4.0
                ]
            }
        ],
        "qa_fixes": [],
        "release_tag": "v-roadmap-phase6-5"
    },
    {
        "phase_name": "PHASE 7 / 7.5.0: Client Portal + Usage Telemetry",
        "features": [
            {
                "name": "feat/phase7-7-5-client-portal-telemetry",
                "commits": [
                    "2f6894e",  # Phase-7a DONE
                    "dcd4331",  # Phase-7b DONE
                    "41af863",  # Phase-7c-7d DONE v4.1
                    "73c03d2",  # Phase-7 Client Portal Overview Dashboard implemented
                    "4f4526c",  # Phase-7e DONE and Fully documentation updated
                    "9fa2790",  # ROADMAP updated
                    "076cf6b",  # ROADMAP updated
                ]
            }
        ],
        "qa_fixes": [],
        "release_tag": "v-roadmap-phase7-7-5"
    },
    {
        "phase_name": "PHASE 8: Advanced ML / Analytics",
        "features": [
            {
                "name": "feat/phase8-ml-analytics",
                "commits": [
                    "82516db",  # Phase-8 DONE - updated documentation and roadmap
                ]
            }
        ],
        "qa_fixes": [],
        "release_tag": "v-roadmap-phase8"
    },
    {
        "phase_name": "PHASE 9: Continuous Compliance & Regulatory Assurance",
        "features": [
            {
                "name": "feat/phase9-compliance-assurance",
                "commits": [
                    "edc6854",  # Added phase-9 to roadmap
                    "21e769e",  # Phase 9 in progress, added missing license headers and updated documentatin
                ]
            }
        ],
        "qa_fixes": [],
        "release_tag": "v-roadmap-phase9"
    },
    {
        "phase_name": "Post-Phase 9: Legal, Branding, CI/CD, QA, and Mainline Sync",
        "features": [
            {
                "name": "feat/post-phase9-hardening-and-governance",
                "commits": [
                    "bc5f51d",  # Implemented Help and customer wizard functionalities
                    "3f40511",  # QA Testing Suite
                    "03a18db",  # Transfer Ownership of IP to NyxeraLabs Organization. Author still remain the same: Jose Maria Micoli
                    "fe48e76",  # Updated README
                    "7c49263",  # Updated README
                    "c5d0865",  # .obsidian untracked
                    "8f2f6a5",  # Resolve merge: stop tracking .obsidian
                    "0b35749",  # feat(integrations): add SpectraStrike ingest API with idempotency, status tracking, audits, tests, and docs
                    "9c87b58",  # ci(cicd): add Python, portal, and Docker validation with automated main release tagging
                    "4f68b12",  # fix(ci): add httpx dependency required by FastAPI TestClient in unit tests
                    "122b679",  # fix(ci): fallback to npm install when portal lockfile is missing
                    "acabf8b",  # fix(ci): skip interactive Next.js lint when portal ESLint config is absent
                    "ebfb923",  # feat(integrations): add SpectraStrike ingest API, docs, tests, and CI/CD hardening
                    "2f25131",  # fix(ci): trigger workflow on uppercase QA branch name
                    "155fa19",  # chore(ci): resolve workflow conflict and keep QA branch triggers
                    "e5d5ab7",  # fix:Makefile
                    "dd3833b",  # feat(compliance): enforce legal acceptance across install, TUI, API, and portal with hash/version revalidation
                    "d9d22da",  # feat(branding): enforce immutable Nyxera/VectorVue attribution while preserving tenant theme customization
                    "ce60f65",  # Merge branch 'dev' into QA
                    "38360e5",  # chore(qa): squash-sync dev into QA
                    "189ef44",  # chore(qa): add legal/branding validation checklist and portal builder QA profile
                    "df19ec8",  # Merge branch 'QA' into dev
                    "55b412b",  # Merge branch 'dev'
                    "8fdd6ff",  # Merge branch 'dev' into main
                    "c80e232",  # Sync dev into main (squash)
                ]
            }
        ],
        "qa_fixes": [],
        "release_tag": "v-roadmap-post-phase9"
    },
]


# ==========================================
# CORE UTILITIES
# ==========================================

RUN_ID = datetime.now().strftime("%Y%m%d-%H%M%S")
LOG_FILE = f"git_reconstruction_{RUN_ID}.log"
BACKUP_REFS = {}
PROCESS_BACKUP_REFS = {}
DRY_RUN = False
USE_SIGNING = True
FORCE_TAGS = False
ALLOW_UNTRACKED = False
SHELVED_ROOT = f"/tmp/git_recon_shelved_{RUN_ID}"
SHELVED_PATHS = []


def log_event(message):
    print(message)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")


def print_restore_instructions():
    if not BACKUP_REFS:
        return
    log_event("\n[!] Recovery commands (if you need rollback):")
    for branch_name, backup_ref in BACKUP_REFS.items():
        log_event(f"    git branch -f {branch_name} {backup_ref}")
    if PROCESS_BACKUP_REFS:
        log_event("[!] Process backup refs (script-use snapshots):")
        for branch_name, backup_ref in PROCESS_BACKUP_REFS.items():
            log_event(f"    {branch_name}: {backup_ref}")
    log_event("    git checkout main")


def fail_critical(message):
    log_event(message)
    print_restore_instructions()
    log_event(f"[!] Execution log: {LOG_FILE}")
    sys.exit(1)


def run_git(args, env=None, description=None):
    """
    Executes a git command using subprocess.
    - inherits stdin/stdout/stderr for GPG interactivity.
    - checks for errors and halts execution if non-zero exit.
    """
    if description:
        log_event(f"\n[+] Action: {description}")
    log_event(f"    Command: git {' '.join(args)}")

    if DRY_RUN:
        return

    run_git_once(args, env=env, description=description)


def run_git_once(args, env=None, description=None):
    """Single-attempt git command runner that raises on failure."""
    final_env = os.environ.copy()
    if env:
        final_env.update(env)

    subprocess.run(
        ["git"] + args,
        check=True,
        env=final_env
    )


def cherry_pick_with_fallback(commit_hash, env_dates, description):
    """
    Cherry-pick with automatic conflict fallback:
    1) normal cherry-pick
    2) abort and retry with -X theirs
    """
    base_args = ["cherry-pick"] + signing_flag_or_empty() + ["-x", commit_hash]

    if DRY_RUN:
        run_git(base_args, env=env_dates, description=description)
        return

    def cherry_pick_in_progress():
        return os.path.exists(".git/CHERRY_PICK_HEAD")

    def cherry_pick_has_no_changes():
        idx_clean = subprocess.run(
            ["git", "diff", "--cached", "--quiet"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        ).returncode == 0
        wt_clean = subprocess.run(
            ["git", "diff", "--quiet"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        ).returncode == 0
        return idx_clean and wt_clean

    def maybe_skip_empty_cherry_pick():
        if cherry_pick_in_progress() and cherry_pick_has_no_changes():
            log_event(f"[~] Empty cherry-pick for {commit_hash}; skipping.")
            subprocess.run(["git", "cherry-pick", "--skip"], check=True)
            return True
        return False

    def try_force_theirs_continue():
        """
        For conflict classes not handled by -X theirs (e.g. modify/delete),
        force resolve by checking out theirs for all paths, staging, and continuing.
        """
        if not cherry_pick_in_progress():
            return False
        log_event(f"[~] Attempting forced conflict resolution for {commit_hash} via checkout --theirs + continue")
        subprocess.run(["git", "checkout", "--theirs", "--", "."], check=False)
        subprocess.run(["git", "add", "-A"], check=False)
        try:
            subprocess.run(["git", "cherry-pick", "--continue"], check=True)
            return True
        except subprocess.CalledProcessError:
            if maybe_skip_empty_cherry_pick():
                return True
            return False

    try:
        run_git_once(base_args, env=env_dates, description=description)
        return
    except subprocess.CalledProcessError:
        if maybe_skip_empty_cherry_pick():
            return
        log_event(f"[~] Conflict/failed cherry-pick for {commit_hash}; retrying with -X theirs")
        subprocess.run(["git", "cherry-pick", "--abort"], check=False)
        retry_args = ["cherry-pick"] + signing_flag_or_empty() + ["-X", "theirs", "-x", commit_hash]
        try:
            run_git_once(retry_args, env=env_dates, description=f"{description} (retry -X theirs)")
            return
        except subprocess.CalledProcessError as e:
            if maybe_skip_empty_cherry_pick():
                return
            if try_force_theirs_continue():
                return
            fail_critical(
                f"\n[!] CRITICAL ERROR during: {description}\n"
                f"[!] Command failed with exit code {e.returncode} even after -X theirs retry.\n"
                "[!] Please resolve manually and re-run."
            )


def run_git_capture(args):
    try:
        result = subprocess.run(
            ["git"] + args,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        fail_critical(f"[!] Failed command: git {' '.join(args)}")
        return ""


def get_untracked_paths():
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True
    )
    paths = []
    for line in result.stdout.splitlines():
        if line.startswith("?? "):
            paths.append(line[3:])
    return paths


def get_commit_touched_paths(commit_hash):
    output = run_git_capture(["show", "--pretty=format:", "--name-only", commit_hash])
    return {line.strip() for line in output.splitlines() if line.strip()}


def get_commit_tree_paths(commit_hash):
    """
    Returns all file paths present in the commit tree.
    This catches collisions where git reports overwrite-by-merge even when
    the path is not listed as directly touched by the commit diff.
    """
    output = run_git_capture(["ls-tree", "-r", "--name-only", commit_hash])
    return {line.strip() for line in output.splitlines() if line.strip()}


def shelve_conflicting_untracked(commit_hash):
    """
    Moves untracked files that would collide with a cherry-pick into /tmp.
    This preserves operator files while allowing deterministic replay.
    """
    untracked = set(get_untracked_paths())
    if not untracked:
        return

    touched = get_commit_touched_paths(commit_hash)
    tree_paths = get_commit_tree_paths(commit_hash)
    candidate_paths = touched.union(tree_paths)

    conflicts = []
    for rel_path in sorted(untracked):
        rel_norm = rel_path.rstrip("/")
        is_dir = rel_path.endswith("/") or os.path.isdir(rel_norm)
        if is_dir:
            prefix = rel_norm + "/"
            if any(p == rel_norm or p.startswith(prefix) for p in candidate_paths):
                conflicts.append(rel_norm)
        elif rel_norm in candidate_paths:
            conflicts.append(rel_norm)

    if not conflicts:
        return

    os.makedirs(SHELVED_ROOT, exist_ok=True)
    for rel_path in conflicts:
        if not os.path.lexists(rel_path):
            continue
        dest_path = os.path.join(SHELVED_ROOT, rel_path)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.move(rel_path, dest_path)
        SHELVED_PATHS.append(rel_path)
        log_event(f"[~] Shelved conflicting untracked path: {rel_path} -> {dest_path}")


def branch_exists(branch_name):
    result = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch_name}"]
    )
    return result.returncode == 0


def tag_exists(tag_name):
    result = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", f"refs/tags/{tag_name}"]
    )
    return result.returncode == 0


def commit_exists(commit_hash):
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{commit_hash}^{{commit}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


def commit_already_in_head(commit_hash):
    """Returns True if commit is already reachable from HEAD."""
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit_hash, "HEAD"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


def get_commit_date(commit_hash):
    """
    Retrieves the strictly formatted ISO-8601 Author Date from a specific commit.
    Used to spoof the Committer Date during cherry-picks.
    """
    return run_git_capture(["show", "-s", "--format=%aI", commit_hash])


def get_current_branches():
    """Returns a list of local branch names."""
    output = run_git_capture(["branch", "--format=%(refname:short)"])
    return output.splitlines() if output else []


def is_working_directory_clean(allow_untracked=False):
    """Checks if there are uncommitted changes."""
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True
    )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if allow_untracked:
        lines = [line for line in lines if not line.startswith("?? ")]
    return len(lines) == 0


def parse_args():
    parser = argparse.ArgumentParser(description="Forensic GitFlow reconstruction")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print commands without changing git refs")
    parser.add_argument("--yes", action="store_true", help="Skip destructive operation confirmation prompt")
    parser.add_argument("--no-sign", action="store_true", help="Disable GPG signing (-S / -s)")
    parser.add_argument("--force-tags", action="store_true", help="Delete existing release tags before creating them")
    parser.add_argument("--allow-untracked", action="store_true", help="Allow untracked files in working tree")
    parser.add_argument("--log-file", default=LOG_FILE, help="Path to execution log file")
    return parser.parse_args()


def preflight_validate():
    all_commits = []
    all_tags = []

    for phase in PROJECT_CONFIG:
        all_tags.append(phase["release_tag"])
        for feat in phase["features"]:
            all_commits.extend(feat["commits"])
        for fix in phase["qa_fixes"]:
            all_commits.extend(fix["commits"])

    duplicate_hashes = [h for h, count in Counter(all_commits).items() if count > 1]
    if duplicate_hashes:
        fail_critical(f"[!] Duplicate commit hashes found in PROJECT_CONFIG: {duplicate_hashes}")

    invalid_hashes = [h for h in all_commits if len(h) != 7 or any(c not in "0123456789abcdef" for c in h)]
    if invalid_hashes:
        fail_critical(f"[!] Invalid short hash format found: {invalid_hashes}")

    missing_hashes = [h for h in all_commits if not commit_exists(h)]
    if missing_hashes:
        fail_critical(f"[!] Missing commits in repository history: {missing_hashes}")

    duplicate_tags = [t for t, count in Counter(all_tags).items() if count > 1]
    if duplicate_tags:
        fail_critical(f"[!] Duplicate release tags in PROJECT_CONFIG: {duplicate_tags}")

    colliding_tags = [t for t in all_tags if tag_exists(t)]
    if colliding_tags and not FORCE_TAGS:
        fail_critical(
            f"[!] These tags already exist: {colliding_tags}\n"
            "[!] Re-run with --force-tags if you explicitly want to replace them."
        )

    if USE_SIGNING and shutil.which("gpg") is None:
        fail_critical("[!] GPG signing requested but 'gpg' binary was not found. Use --no-sign if needed.")

    log_event("[+] Preflight validation passed.")


def maybe_confirm_or_exit():
    if DRY_RUN or os.environ.get("GIT_RECON_AUTO_YES") == "1":
        return

    log_event(
        "\n[!] This script will rewrite local branches (main/dev/QA).\n"
        "[!] Backups are created first, but this operation is destructive."
    )
    answer = input("Type RECONSTRUCT to proceed: ").strip()
    if answer != "RECONSTRUCT":
        fail_critical("[!] Confirmation failed. Aborted by operator.")


def create_branch_backups(existing_branches):
    log_event(">>> Performing backups...")
    for branch_name in ("main", "dev", "QA"):
        if branch_name not in existing_branches:
            continue

        immutable_backup = f"{branch_name}-backup-{RUN_ID}"
        process_backup = f"{branch_name}-backup"

        if branch_exists(immutable_backup):
            fail_critical(f"[!] Backup branch collision: {immutable_backup} already exists.")

        run_git(
            ["branch", immutable_backup, branch_name],
            description=f"Creating immutable backup {immutable_backup} from {branch_name}"
        )
        run_git(
            ["branch", "-f", process_backup, immutable_backup],
            description=f"Updating process backup {process_backup} pointer"
        )
        BACKUP_REFS[branch_name] = immutable_backup
        PROCESS_BACKUP_REFS[branch_name] = process_backup

    if not BACKUP_REFS:
        fail_critical("[!] No source branches found to back up (expected at least 'main').")


def signing_flag_or_empty():
    return ["-S"] if USE_SIGNING else []


def unique_work_branch(base_name):
    return f"{base_name}-{RUN_ID}"


def verify_backups_persist():
    """
    Ensures immutable backup branches created at startup still exist when the
    run completes. This is a hard safety guarantee.
    """
    if DRY_RUN:
        log_event("[~] Dry-run mode: skipping backup persistence enforcement.")
        return

    missing_immutable = []
    for _, backup_ref in BACKUP_REFS.items():
        if not branch_exists(backup_ref):
            missing_immutable.append(backup_ref)

    missing_process = []
    for _, backup_ref in PROCESS_BACKUP_REFS.items():
        if not branch_exists(backup_ref):
            missing_process.append(backup_ref)

    if missing_immutable or missing_process:
        fail_critical(
            "[!] Backup integrity failure: missing backups detected.\n"
            f"    Immutable missing: {missing_immutable}\n"
            f"    Process missing: {missing_process}"
        )

    log_event("[+] Backup integrity check passed. Immutable backups still exist:")
    for _, backup_ref in BACKUP_REFS.items():
        log_event(f"    - {backup_ref}")
    if PROCESS_BACKUP_REFS:
        log_event("[+] Process backups still exist:")
        for _, backup_ref in PROCESS_BACKUP_REFS.items():
            log_event(f"    - {backup_ref}")


# ==========================================
# MAIN EXECUTION FLOW
# ==========================================

def main():
    global DRY_RUN, USE_SIGNING, FORCE_TAGS, LOG_FILE, ALLOW_UNTRACKED

    args = parse_args()
    DRY_RUN = args.dry_run
    USE_SIGNING = not args.no_sign
    FORCE_TAGS = args.force_tags
    ALLOW_UNTRACKED = args.allow_untracked
    LOG_FILE = args.log_file

    # Run cleanliness guard before any logging side effects inside the repo.
    if not is_working_directory_clean(allow_untracked=ALLOW_UNTRACKED):
        print("[!] Error: Working directory is not clean. Commit or stash changes first.")
        print(f"[!] Execution log: {LOG_FILE}")
        sys.exit(1)

    log_event(">>> STARTING OFFENSIVE GIT RECONSTRUCTION <<<")
    log_event(f"[+] Run ID: {RUN_ID}")
    log_event(f"[+] Dry run mode: {DRY_RUN}")
    log_event(f"[+] Signing enabled: {USE_SIGNING}")
    log_event(f"[+] Force tags: {FORCE_TAGS}")
    log_event(f"[+] Allow untracked: {ALLOW_UNTRACKED}")

    # Safety-first requirement:
    # create immutable backups of current branch tips before any reconstruction step.
    existing_branches = get_current_branches()
    log_event("[+] Step 1/4: Creating immutable backups for main/dev/QA before preflight.")
    create_branch_backups(existing_branches)

    log_event("[+] Step 2/4: Running preflight validation.")
    preflight_validate()

    log_event("[+] Step 3/4: Waiting for operator confirmation.")
    if not args.yes:
        maybe_confirm_or_exit()

    log_event("[+] Step 4/4: Starting branch reconstruction.")

    # Optional tag cleanup if user explicitly requested overwrite.
    if FORCE_TAGS:
        for phase in PROJECT_CONFIG:
            tag_name = phase["release_tag"]
            if tag_exists(tag_name):
                run_git(["tag", "-d", tag_name], description=f"Removing existing tag {tag_name}")

    # Gets the very first commit reachable from HEAD
    root_output = run_git_capture(["rev-list", "--max-parents=0", "HEAD"])
    root_lines = [line for line in root_output.splitlines() if line.strip()]
    if not root_lines:
        fail_critical("[!] Failed to find root commit.")
    root_commit = root_lines[-1]
    log_event(f">>> Root commit identified: {root_commit}")

    run_git(["checkout", root_commit], description="Checking out root commit (Detached HEAD)")

    run_git(["checkout", "-B", "main", root_commit], description="Resetting main to root")
    run_git(["checkout", "-B", "dev", root_commit], description="Resetting dev to root")
    run_git(["checkout", "-B", "QA", root_commit], description="Resetting QA to root")
    run_git(["checkout", "dev"], description="Switching to dev context")

    for phase in PROJECT_CONFIG:
        phase_name = phase["phase_name"]
        log_event("\n========================================")
        log_event(f" PROCESSING PHASE: {phase_name}")
        log_event("========================================")

        for feat in phase["features"]:
            feat_branch = unique_work_branch(feat["name"])

            run_git(["checkout", "dev"], description="Aligning dev")
            run_git(["checkout", "-b", feat_branch], description=f"Created {feat_branch}")

            for commit_hash in feat["commits"]:
                if commit_already_in_head(commit_hash):
                    log_event(f"[~] Skipping {commit_hash}: already present in HEAD for {feat_branch}")
                    continue
                shelve_conflicting_untracked(commit_hash)
                orig_date = get_commit_date(commit_hash)
                env_dates = {
                    "GIT_AUTHOR_DATE": orig_date,
                    "GIT_COMMITTER_DATE": orig_date
                }
                cherry_pick_with_fallback(
                    commit_hash,
                    env_dates,
                    description=f"Cherry-picking {commit_hash} into {feat_branch}"
                )

            run_git(["checkout", "dev"], description="Switching to dev")
            merge_args = ["merge", "--no-ff"] + signing_flag_or_empty() + [feat_branch]
            run_git(merge_args, description=f"Merging {feat_branch} into dev")
            run_git(["branch", "-d", feat_branch], description=f"Cleaning up {feat_branch}")

        run_git(["checkout", "QA"], description="Switching to QA")
        qa_merge_args = ["merge", "--no-ff"] + signing_flag_or_empty() + ["dev"]
        run_git(qa_merge_args, description=f"Promoting {phase_name} dev code to QA")

        if phase["qa_fixes"]:
            log_event(f">>> Applying QA Fixes for {phase_name}")
            for fix in phase["qa_fixes"]:
                fix_base = fix["name"] if fix["name"].startswith("fix/") else f"fix/{fix['name']}"
                fix_branch = unique_work_branch(fix_base)

                run_git(["checkout", "QA"], description="Aligning QA")
                run_git(["checkout", "-b", fix_branch], description=f"Created {fix_branch}")

                for commit_hash in fix["commits"]:
                    if commit_already_in_head(commit_hash):
                        log_event(f"[~] Skipping {commit_hash}: already present in HEAD for {fix_branch}")
                        continue
                    shelve_conflicting_untracked(commit_hash)
                    orig_date = get_commit_date(commit_hash)
                    env_dates = {
                        "GIT_AUTHOR_DATE": orig_date,
                        "GIT_COMMITTER_DATE": orig_date
                    }
                    cherry_pick_with_fallback(
                        commit_hash,
                        env_dates,
                        description=f"Cherry-picking fix {commit_hash}"
                    )

                run_git(["checkout", "QA"], description="Switching to QA")
                fix_merge_args = ["merge", "--no-ff"] + signing_flag_or_empty() + [fix_branch]
                run_git(fix_merge_args, description=f"Merging fix {fix_branch} into QA")
                run_git(["branch", "-d", fix_branch], description="Cleaning up fix branch")

            run_git(["checkout", "dev"], description="Switching to dev for Sync")
            dev_sync_args = ["merge", "--no-ff"] + signing_flag_or_empty() + ["QA"]
            run_git(dev_sync_args, description=f"Syncing QA fixes back to dev")

        run_git(["checkout", "main"], description="Switching to main")
        main_merge_args = ["merge", "--no-ff"] + signing_flag_or_empty() + ["QA"]
        run_git(main_merge_args, description=f"Releasing {phase_name} to main")

        tag_name = phase["release_tag"]
        if USE_SIGNING:
            tag_args = ["tag", "-s", tag_name, "-m", f"Release {tag_name}"]
            tag_desc = f"Signed Tag: {tag_name}"
        else:
            tag_args = ["tag", "-a", tag_name, "-m", f"Release {tag_name}"]
            tag_desc = f"Annotated Tag: {tag_name}"
        run_git(tag_args, description=tag_desc)

    log_event("\n>>> RECONSTRUCTION COMPLETE <<<")
    verify_backups_persist()
    log_event("Verify history with: git log --graph --oneline --all")
    if SHELVED_PATHS:
        log_event(f"[!] Shelved untracked paths were moved to: {SHELVED_ROOT}")
        log_event("[!] Review and manually restore/delete them as needed after verification.")
    log_event(f"[+] Execution log: {LOG_FILE}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        fail_critical("\n[!] User aborted execution.")
