```markdown
██▒   █▓▓█████  ▄████▄  ▄▄▄█████▓ ▒█████   ██▀███      ██▒   █▓ ██▓  ██▓ ▓█████ 
▓██░   █▒▓█   ▀ ▒██▀ ▀█  ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒    ▓██░   █▒▓██▒  ██▒ ▓█   ▀ 
 ▓██  █▒░▒███   ▒▓█    ▄ ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒     ▓██  █▒░▓██░  ██▒ ▒███   
  ▒██ █░░▒▓█  ▄ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄       ▒██ █░░▒██   ██░ ▒▓█  ▄ 
   ▒▀█░  ░▒████▒▒ ▓███▀ ░  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒      ▒▀█░  ░ ████▓▒░ ░▒████▒
   ░ ▐░  ░░ ▒░ ░░ ░▒ ▒  ░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░      ░ ▐░  ░ ▒░▒░▒░  ░░ ▒░ ░
   ░ ░░   ░ ░  ░  ░  ▒       ░      ░ ░ ▒░   ░▒ ░ ▒░      ░ ░░  ░ ░ ▒░▒░   ░ ░  ░
   ░      ░    ░          ░      ░ ░ ░ ▒    ░░   ░ ░      ░        ░ ░ ▒░     ░    
          ░  ░ ░                               ░               ░ ░ ░      ░  ░  
               >> ADVERSARY REPORTING FRAMEWORK <<

```

# VectorVue v2.1 [Tactical]

![Status](https://img.shields.io/badge/Status-Stable-green) ![Version](https://img.shields.io/badge/Version-2.1-blue) ![License](https://img.shields.io/badge/License-Internal-red)

**VectorVue** is a terminal-based Offensive Security Reporting & Intelligence suite designed for Red Teams. It integrates finding management, report generation (Markdown), and adversary intelligence (MITRE ATT&CK) into a high-performance TUI (Text User Interface).

## ⚡ Key Features

*   **Phosphor Cyberpunk UI:** High-contrast, low-latency interface optimized for dimly lit SOC/NOC environments.
*   **Split-Core Architecture:**
    *   **VectorVue DB (`vectorvue.db`):** Manage engagement findings, evidence, and remediation.
    *   **Intelligence Engine:** Real-time MITRE ATT&CK ID lookups (e.g., `T1059`).
*   **Vim-Integrated File Manager:** Manage project files without leaving the terminal using `j/k` navigation.
*   **Atomic I/O:** Fault-tolerant file saving prevents data corruption during crashes.
*   **Markdown Editor:** Syntax-highlighted editor with Dracula theme integration.

## 🚀 Quick Start

### Prerequisites
*   Python 3.10+
*   Terminal with TrueColor support (Alacritty, Kitty, Windows Terminal)

### Installation

```bash
# Clone repository
git clone https://internal.repo/vectorvue.git
cd vectorvue

# Install dependencies (including syntax highlighting)
pip install textual[syntax]