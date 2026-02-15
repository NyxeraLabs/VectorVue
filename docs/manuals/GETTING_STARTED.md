# Getting Started with VectorVue v2.1

![Setup](https://img.shields.io/badge/Setup-Required-FFBF00?style=flat-square)

This document outlines the procedure for setting up the VectorVue environment. Adherence to these steps is mandatory to ensure the stability of the TUI and the integrity of the reporting data.

## 1. System Requirements

Before proceeding, ensure the host system meets the following specifications:

*   **Operating System:**
    *   Linux (Debian/Ubuntu 20.04+, Fedora 36+, Kali, ParrotOS)
    *   macOS (Monterey 12.0+)
    *   Windows 10/11 (via PowerShell or WSL2)
*   **Runtime:** Python 3.10.x or higher.
*   **Terminal Emulator:** Must support 24-bit TrueColor and UTF-8 rendering.
    *   *Recommended:* Alacritty, Kitty, WezTerm, Windows Terminal.
    *   *Not Supported:* Standard Windows CMD (Legacy Console).

## 2. Installation Procedure

### Step 1: Repository Retrieval
Clone the source code to your local engagement directory.
```bash
git clone https://internal.repo/vectorvue.git
cd vectorvue
```

### Step 2: Virtual Environment (Critical)
To avoid polluting the global Python namespace and to ensure version consistency, a virtual environment is required.

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

### Step 3: Dependency Injection
Install the required libraries. Note that `textual[syntax]` is explicitly required to enable the Tree-Sitter syntax highlighting engine.

```bash
pip install --upgrade pip
pip install textual[syntax]
```

## 3. Intelligence Data Configuration

VectorVue operates in two modes based on the presence of intelligence data.

1.  **Connected Mode (Full):**
    *   Ensure a file named `mitre_reference.txt` exists in the root directory.
    *   Format: `T-Code | Technique Name | Description`
    *   *Result:* The Intelligence Engine will parse this file at startup, enabling real-time lookups.

2.  **Disconnected Mode (Lite):**
    *   If the file is missing, the system will initialize without lookup capabilities.
    *   *Result:* Manual entry of MITRE data is still possible, but validation is disabled.

## 4. Verification

Execute the application to verify successful installation:

```bash
python vv.py
```

**Success Criteria:**
1.  The application launches without traceback errors.
2.  The "Header HUD" displays `VECTORVUE v2.1 [TACTICAL]`.
3.  The Status Bar (bottom) reads `SYSTEM READY`.
4.  Colors are rendered correctly (Neon Green/Cyan vs. Monochrome).

---
*Proceed to the [Operator Manual](OPERATOR_MANUAL.md) for usage instructions.*
