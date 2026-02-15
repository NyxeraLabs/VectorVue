# Architecture Specification

![Type](https://img.shields.io/badge/Type-Technical-purple?style=flat-square) ![Component](https://img.shields.io/badge/Component-Core-blue?style=flat-square)

VectorVue v2.1 utilizes a "Split-Core" architecture, separating the UI Presentation Layer (Textual) from the Data Persistence Layer (SQLite/FS). This ensures that UI rendering lags do not corrupt data operations.

## 1. Component Diagram

```text
[ USER INPUT ]
      │
      ▼
[ EVENT LOOP (Textual App) ] ───┬───> [ RENDERER (CSS/Widgets) ]
      │                         │
      │                         └───> [ FILE MANAGER VIEW ]
      │
      ▼
[ DATA CONTROLLER ] ────────────┐
      │                         │
      ▼                         ▼
[ INTELLIGENCE ENGINE ]    [ DATABASE MGR ]
(Memory Cache)             (SQLite3 Connection)
      │                         │
      ▼                         ▼
[ mitre_reference.txt ]    [ vectorvue.db ]
```

## 2. Database Schema (`vectorvue.db`)

The application maintains a lightweight, serverless SQLite database. The schema is designed for portability and simplicity.

**Table:** `findings`

| Column | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `id` | INTEGER PK | Auto | Unique record identifier. |
| `title` | TEXT | NULL | The headline of the vulnerability. |
| `description` | TEXT | NULL | The full Markdown body of the finding. |
| `cvss_score` | REAL | 0.0 | Numerical risk score (0.0-10.0). |
| `mitre_id` | TEXT | "" | Associated MITRE T-Code. |
| `tactic_id` | TEXT | "" | (Reserved for future use). |
| `status` | TEXT | "Open" | Workflow state of the finding. |
| `evidence` | TEXT | "" | Raw evidence logs/screenshots path. |
| `remediation` | TEXT | "" | Recommended mitigation steps. |

## 3. Atomic I/O Implementation

To prevent data corruption (partial writes) during unexpected terminations, the `FileSystemService` implements atomic write logic:

1.  **Staging:** Data is written to a `tempfile.NamedTemporaryFile` in the target directory.
2.  **Flushing:** `file.flush()` and `os.fsync(fd)` are called to force the OS to write buffers to the physical disk.
3.  **Swapping:** `os.replace(src, dst)` is called. On POSIX systems, this is an atomic operation that instantly swaps the inode pointers.

## 4. Phosphor Design System (Theme)

The UI is governed by a centralized theme file (`vv_theme.py`). It defines CSS variables for consistency.

**Color Tokens:**
*   `$p-green` (#39FF14): Primary Action, Success, Low Risk.
*   `$e-cyan` (#00FFFF): Information, Selection, File Context.
*   `$a-amber` (#FFBF00): Warning, High Risk, System Pending.
*   `$r-alert` (#FF0000): Critical Error, Destruction, Critical Risk.
*   `$bg-void` (#050505): Application background (High Contrast).

This palette is chosen to maximize readability in low-light environments typical of security operations centers.
