# VectorVue Operator Manual

![Role](https://img.shields.io/badge/Role-Operator-00FFFF?style=flat-square) ![Context](https://img.shields.io/badge/Context-Engagement-39FF14?style=flat-square)

This manual details the operational workflows for the VectorVue suite. The interface is designed for high-velocity keyboard interaction, minimizing the need for mouse input.

## 1. Interface Anatomy

The TUI is divided into three logical zones:

### A. The HUD (Heads-Up Display)
Located at the top, this bar displays the tool version and the currently active buffer (file or database record ID). It serves as the primary context indicator.

### B. The Content Viewport (Left Pane)
This dynamic pane toggles between two modes:
1.  **Editor Mode:** A syntax-aware Markdown editing environment for drafting findings.
2.  **File Manager Mode:** A tree-based filesystem browser for managing project assets.

### C. The Lateral Tools Panel (Right Pane)
Contains tactical inputs and real-time feedback systems:
*   **Risk Assessment:** Displays dynamic CVSS severity ratings.
*   **Input Vectors:** Fields for Title, Score, and MITRE IDs.
*   **Findings Queue:** A scrollable list of committed database entries.
*   **Control Grid:** Buttons for I/O operations and system control.

---

## 2. Operational Workflows

### Risk Assessment (CVSS Scoring)
VectorVue creates a visual feedback loop for risk scoring. Input a base score (0.0 - 10.0) in the **SCORE** field.

| Score Range | Severity Label | Indicator Color | Visual Style |
| :--- | :--- | :--- | :--- |
| **9.0 - 10.0** | CRITICAL | **#FF0000 (Red)** | Heavy Border, Flashing Icon |
| **7.0 - 8.9** | HIGH | **#FFBF00 (Amber)** | Solid Border |
| **4.0 - 6.9** | MEDIUM | **#00FFFF (Cyan)** | Solid Border |
| **0.0 - 3.9** | LOW | **#39FF14 (Green)** | Solid Border |

### Intelligence Engine (Adversary Lookup)
The system assists in mapping findings to the MITRE ATT&CK framework.

1.  Navigate to the **MITRE ID** input field.
2.  Type a technique ID (e.g., `T1059`).
3.  **Automatic Feedback:**
    *   If the ID exists in the local intelligence database, the **MITRE MAPPING** panel will light up **Cyan** and display the technique name.
    *   If the ID is unrecognized, the panel remains **Amber** with an "UNKNOWN" state.

### File Management (Vim-Mode)
Press `Space` to toggle the File Manager.

*   **Navigation:** Use standard Vim keys (`j` for down, `k` for up).
*   **Preview:** Moving the cursor over a file immediately renders a read-only preview in the adjacent pane.
*   **Creation:** Press `n` to spawn a filename input. Enter the name and confirm. The system handles the `.md` extension.
*   **Deletion:** Press `d` on a target node. **Caution:** This executes an immediate filesystem removal using `shutil.rmtree` or `os.unlink`.

### Database Persistence
To commit a finding to the engagement database:
1.  Ensure **Title** and **Score** are populated.
2.  Press `Ctrl+S` or click **COMMIT DB**.
3.  The finding is serialized and stored in `vectorvue.db`.
4.  The Status Bar will confirm: `DATABASE SYNCED`.

### Report Export
To generate a deliverable artifact:
1.  Select a finding or ensure the editor contains the final content.
2.  Click **EXPORT .MD**.
3.  The system writes the file to the `05-Delivery/` directory.
4.  This operation uses **Atomic Writes** to guarantee data integrity.

---

## 3. System Shutdown
Press `Q` or click **SHUTDOWN**. This triggers a cinematic shutdown sequence that:
1.  Closes all SQLite connections.
2.  Flushes temporary file buffers.
3.  Secures file handles.
4.  Terminates the TUI process.
