# --- START OF FILE vv.py ---

import os
import sys
import time
import asyncio
from datetime import datetime
from pathlib import Path

# Textual TUI
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    ListView, ListItem, Label, Input, 
    TextArea, Button, Static, ContentSwitcher, LoadingIndicator
)
from textual.binding import Binding
from textual.screen import Screen
from textual.reactive import reactive

# Custom Modules
try:
    from vv_core import Database, Finding, IntelligenceEngine
    from vv_fs import FileSystemService
    from vv_file_manager import FileManagerView
    from vv_theme import CYBER_CSS, CyberColors
except ImportError as e:
    print(f"CRITICAL: Dependency missing. {e}")
    sys.exit(1)

# --- CUSTOM WIDGETS ---

class HeaderHUD(Static):
    """Top Banner with Tool Info and Active File"""
    current_file = reactive("NO FILE ACTIVE")

    def compose(self) -> ComposeResult:
        yield Label("VECTORVUE v2.1 [TACTICAL]", classes="hud-title")
        yield Label(f"// BUFFER: {self.current_file}", classes="hud-file")

    def watch_current_file(self, val):
        if self.is_mounted:
            try:
                self.query_one(".hud-file", Label).update(f"// BUFFER: {val}")
            except Exception:
                pass

class ShutdownScreen(Screen):
    """Cinematic Exit Screen - FIXED"""
    def compose(self) -> ComposeResult:
        with Container(id="shutdown-container"):
            # FIX: Use Rich Markup [bold white] instead of style argument
            yield Label("[bold white]INITIATING SHUTDOWN SEQUENCE[/]", classes="shutdown-header")
            
            with Horizontal(classes="shutdown-row"):
                yield Label("CLOSING DATABASE CONNECTION...", classes="shutdown-label")
                yield Label("...", id="st-db", classes="shutdown-status status-pending")
            
            with Horizontal(classes="shutdown-row"):
                yield Label("PURGING TEMPORARY BUFFERS...", classes="shutdown-label")
                yield Label("...", id="st-tmp", classes="shutdown-status status-pending")
            
            with Horizontal(classes="shutdown-row"):
                yield Label("SECURING FILESYSTEM...", classes="shutdown-label")
                yield Label("...", id="st-fs", classes="shutdown-status status-pending")
            
            # FIX: Use Rich Markup [bold red] instead of style argument
            yield Label("[bold red]SYSTEM HALTED[/]", id="final-msg")

    def on_mount(self):
        self.query_one("#final-msg").visible = False
        self.run_shutdown_sequence()

    @work
    async def run_shutdown_sequence(self):
        # Cinematic delay logic
        await asyncio.sleep(0.5)
        if self.app.db: self.app.db.close()
        self.query_one("#st-db").update("[OK]")
        self.query_one("#st-db").remove_class("status-pending")
        self.query_one("#st-db").add_class("status-done")

        await asyncio.sleep(0.4)
        FileSystemService.cleanup_temp_files()
        self.query_one("#st-tmp").update("[OK]")
        self.query_one("#st-tmp").remove_class("status-pending")
        self.query_one("#st-tmp").add_class("status-done")

        await asyncio.sleep(0.4)
        self.query_one("#st-fs").update("[SECURE]")
        self.query_one("#st-fs").remove_class("status-pending")
        self.query_one("#st-fs").add_class("status-done")

        await asyncio.sleep(0.5)
        self.query_one("#final-msg").visible = True
        await asyncio.sleep(0.8)
        self.app.exit()

class FindingItem(ListItem):
    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        # FIX: Explicitly convert score to float to handle string inputs safely
        try:
            score = float(self.finding.cvss_score)
        except (ValueError, TypeError):
            score = 0.0
            
        score_fmt = f"{score:.1f}"
        icon = "⚡" if score >= 9.0 else "●"
        
        # Color coding for list items using Rich markup
        color = "white"
        if score >= 9.0: color = CyberColors.RED_ALERT
        elif score >= 7.0: color = CyberColors.AMBER_WARNING
        elif score >= 4.0: color = CyberColors.ELECTRIC_CYAN
        
        yield Label(f"[{color}]{icon} [{score_fmt}] {self.finding.title[:20]}[/]")

# --- MAIN APPLICATION ---

class CyberTUI(App):
    CSS = CYBER_CSS 
    
    BINDINGS = [
        Binding("q", "quit_app", "Quit"),
        Binding("space", "toggle_file_manager", "Files"),
        Binding("ctrl+s", "save_db", "Save"),
    ]
    
    def compose(self) -> ComposeResult:
        # 1. Header HUD
        yield HeaderHUD(id="hud-header")
        
        # 2. Main Content Area (Left)
        with ContentSwitcher(initial="editor-view", id="view-switcher"):
            # Editor
            with Container(id="editor-view"):
                yield TextArea(
                    language="markdown", 
                    theme="dracula", 
                    id="editor-main",
                    show_line_numbers=True
                )
            # File Manager
            yield FileManagerView(id="fm-view")

        # 3. Lateral Tools (Right)
        with Container(id="lateral-tools"):
            # Info Panels
            yield Label("RISK ASSESSMENT:", classes="cyber-label")
            yield Static("NO SIGNAL", id="info-severity", classes="info-box")
            
            yield Label("CVSS 4.0 SCORE:", classes="cyber-label")
            yield Static("0.0", id="info-score", classes="info-box")
            
            yield Label("MITRE MAPPING:", classes="cyber-label")
            yield Static("NONE", id="info-mitre", classes="info-box")

            # Inputs
            yield Label("VECTOR TITLE:", classes="cyber-label")
            yield Input(id="inp-title", placeholder="Vulnerability Title...")
            
            yield Label("SCORE / MITRE ID:", classes="cyber-label")
            
            # --- INPUT ROW LAYOUT ---
            with Horizontal(classes="input-row"):
                yield Input(id="inp-score", type="number", placeholder="9.8", classes="half-input")
                yield Input(id="inp-mitre", placeholder="T1548", classes="half-input")
            
            # Queue
            yield Label("FINDINGS QUEUE:", classes="cyber-label")
            yield ListView(id="findings-list")
            
            # Actions
            yield Label("OPERATIONS:", classes="cyber-label")
            yield Button("COMMIT DB", id="btn-save", classes="btn-save")
            yield Button("NEW ENTRY", id="btn-new")
            yield Button("DELETE", id="btn-del", classes="btn-delete")
            
            yield Label("SYSTEM:", classes="cyber-label")
            yield Button("FILESYSTEM", id="btn-file-mgr")
            yield Button("EXPORT .MD", id="btn-save-md")
            yield Button("SHUTDOWN", id="btn-exit")
        
        # 4. Status Bar
        yield Label("SYSTEM READY", id="status-bar")

    def on_mount(self):
        self.db = Database()
        self.intel = IntelligenceEngine()
        self.current_id = None
        os.makedirs("05-Delivery", exist_ok=True)
        self.refresh_list()
        self.query_one("#editor-main").focus()

    def action_quit_app(self):
        self.push_screen(ShutdownScreen())

    def update_status(self, msg, color="#ffffff"):
        bar = self.query_one("#status-bar")
        ts = datetime.now().strftime('%H:%M:%S')
        bar.update(f"[{ts}] {msg}")
        bar.styles.color = color

    # --- MITRE LOOKUP ---
    @on(Input.Changed, "#inp-mitre")
    def on_mitre_input(self, event):
        val = event.value.strip().upper()
        mitre_box = self.query_one("#info-mitre")
        
        # Intelligence Engine Lookup
        if len(val) >= 4:
            info = self.intel.lookup_mitre(val)
            if info:
                # Found match in IntelligenceEngine
                mitre_box.update(f"{info.id}\n{info.name[:20]}")
                mitre_box.styles.color = CyberColors.ELECTRIC_CYAN
                mitre_box.styles.border = "heavy", CyberColors.ELECTRIC_CYAN
                self.update_status(f"INTEL MATCH: {info.name}", CyberColors.ELECTRIC_CYAN)
            else:
                mitre_box.update("UNKNOWN ID")
                mitre_box.styles.color = CyberColors.AMBER_WARNING
                mitre_box.styles.border = "solid", CyberColors.AMBER_WARNING
        else:
            mitre_box.update("WAITING...")
            mitre_box.styles.border = "solid", CyberColors.STEEL_BORDER

    # --- SCORE & SEVERITY ---
    @on(Input.Changed, "#inp-score")
    def on_score_input(self, event):
        try:
            score = float(event.value)
        except ValueError:
            score = 0.0
        
        self.update_risk_panels(score)

    def update_risk_panels(self, score):
        sev_box = self.query_one("#info-severity")
        score_box = self.query_one("#info-score")
        
        score_box.update(str(score))
        
        # Reset classes
        for cls in ["risk-crit", "risk-high", "risk-med", "risk-low"]:
            sev_box.remove_class(cls)
            score_box.remove_class(cls)

        if score >= 9.0:
            sev_box.update("CRITICAL")
            sev_box.add_class("risk-crit")
            score_box.add_class("risk-crit")
        elif score >= 7.0:
            sev_box.update("HIGH")
            sev_box.add_class("risk-high")
            score_box.add_class("risk-high")
        elif score >= 4.0:
            sev_box.update("MEDIUM")
            sev_box.add_class("risk-med")
            score_box.add_class("risk-med")
        else:
            sev_box.update("LOW")
            sev_box.add_class("risk-low")
            score_box.add_class("risk-low")

    # --- VIEWPORT LOGIC ---
    def action_toggle_file_manager(self):
        switcher = self.query_one("#view-switcher", ContentSwitcher)
        if switcher.current == "editor-view":
            switcher.current = "fm-view"
            self.query_one("FileManagerView").action_refresh()
            self.query_one("FileManagerView")._focus_tree()
        else:
            switcher.current = "editor-view"
            self.query_one("#editor-main").focus()

    @on(FileManagerView.FileSelected)
    def on_file_selected(self, event):
        path = event.path
        self.read_file_worker(path)
        self.query_one("#view-switcher").current = "editor-view"
        self.query_one("#editor-main").focus()

    @work(exclusive=True, thread=True)
    def read_file_worker(self, path: Path):
        success, content, _ = FileSystemService.read_file(path)
        if success:
            self.app.call_from_thread(self._load_editor, content, path.name)
        else:
            self.app.call_from_thread(self.update_status, "READ ERROR", CyberColors.RED_ALERT)

    def _load_editor(self, content, title):
        self.current_id = None
        self.query_one("#inp-title").value = title
        self.query_one("#editor-main").load_text(content)
        self.query_one("#hud-header").current_file = title
        self.update_status("FILE LOADED", CyberColors.PHOSPHOR_GREEN)

    # --- DB OPS ---
    def refresh_list(self):
        lv = self.query_one("#findings-list", ListView)
        lv.clear()
        for f in self.db.get_findings():
            lv.append(FindingItem(f))

    def on_list_view_selected(self, event):
        f = event.item.finding
        self.current_id = f.id
        self.query_one("#inp-title").value = f.title
        self.query_one("#inp-score").value = str(f.cvss_score)
        self.query_one("#inp-mitre").value = f.mitre_id
        
        full_text = f.description
        if f.evidence: full_text = f"## EVIDENCE\n{f.evidence}\n\n" + full_text
        if f.remediation: full_text += f"\n\n## REMEDIATION\n{f.remediation}"
            
        self.query_one("#editor-main").load_text(full_text)
        self.query_one("#hud-header").current_file = f"DB:{f.id}"
        self.update_risk_panels(f.cvss_score)
        self.update_status(f"RECORD {f.id} LOADED", CyberColors.PHOSPHOR_GREEN)

    @on(Button.Pressed)
    def on_buttons(self, event):
        bid = event.button.id
        if bid == "btn-exit": self.action_quit_app()
        elif bid == "btn-save": self.save_db()
        elif bid == "btn-new": self.new_entry()
        elif bid == "btn-del": self.delete_entry()
        elif bid == "btn-save-md": self.export_md()
        elif bid == "btn-file-mgr": self.action_toggle_file_manager()

    def save_db(self):
        try: score = float(self.query_one("#inp-score").value)
        except: score = 0.0
        
        f = Finding(
            id=self.current_id,
            title=self.query_one("#inp-title").value or "Untitled",
            description=self.query_one("#editor-main").text,
            cvss_score=score,
            mitre_id=self.query_one("#inp-mitre").value,
            tactic_id="", status="Open"
        )
        
        if self.current_id: self.db.update_finding(f)
        else: self.current_id = self.db.add_finding(f)
        
        self.refresh_list()
        self.update_status("DATABASE SYNCED", CyberColors.PHOSPHOR_GREEN)

    def new_entry(self):
        self.current_id = None
        self.query_one("#inp-title").value = ""
        self.query_one("#inp-score").value = "0.0"
        self.query_one("#inp-mitre").value = ""
        self.query_one("#editor-main").load_text("")
        self.query_one("#hud-header").current_file = "NEW BUFFER"
        self.query_one("#inp-title").focus()

    def delete_entry(self):
        if self.current_id:
            self.db.delete_finding(self.current_id)
            self.new_entry()
            self.refresh_list()
            self.update_status("RECORD DELETED", CyberColors.RED_ALERT)

    def export_md(self):
        title = self.query_one("#inp-title").value.replace(" ", "_") or "Untitled"
        if not title.endswith(".md"): title += ".md"
        path = Path("05-Delivery") / title
        success, msg = FileSystemService.atomic_write(path, self.query_one("#editor-main").text)
        self.update_status(msg.upper(), CyberColors.PHOSPHOR_GREEN if success else CyberColors.RED_ALERT)

if __name__ == '__main__':
    if sys.platform == "win32": os.system("cls")
    else: os.system("clear")
    app = CyberTUI()
    app.run()