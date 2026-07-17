from __future__ import annotations

import argparse
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import queue
import socket
import sys
import tempfile
from threading import Event, Thread
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Mapping
from zipfile import ZipFile

from . import __version__
from .admin import is_admin
from .database import Database
from .demo import create_demo_case
from .graph_view import EvidenceGraph
from .impact import ImpactAnalyzer
from .pipeline import IncidentPipeline
from .presentation import FILTER_TO_GROUP, entity_group
from .report import CaseExporter


COLORS = {
    "bg": "#101010",
    "header": "#181818",
    "panel": "#151515",
    "panel2": "#1c1c1c",
    "line": "#2c2c2c",
    "text": "#e7e7e7",
    "muted": "#8d8d8d",
    "accent": "#f15a2b",
    "accent2": "#d94b20",
    "danger": "#db4b4b",
    "warning": "#d6a23f",
}


def _get(record: Any, key: str, default: Any = None) -> Any:
    if record is None:
        return default
    if isinstance(record, Mapping):
        return record.get(key, default)
    return getattr(record, key, default)


def _dict(record: Any) -> dict[str, Any]:
    if record is None:
        return {}
    if isinstance(record, dict):
        return dict(record)
    if is_dataclass(record):
        return asdict(record)
    if isinstance(record, Mapping):
        return dict(record)
    if hasattr(record, "__dict__"):
        return dict(vars(record))
    return {"value": str(record)}


def default_data_dir() -> Path:
    configured = os.environ.get("NODETRACE_IR_DATA_DIR")
    if configured:
        return Path(configured).expanduser()
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "NodeTraceIR"


def validate_offline_root(value: str | Path) -> Path:
    """Validate a mounted Windows installation without writing to it."""

    root = Path(value).expanduser().absolute()
    if not root.is_dir():
        raise ValueError(f"offline root is not an accessible directory: {root}")
    windows_directory = root / "Windows"
    if not windows_directory.is_dir():
        raise ValueError(f"offline root does not contain a Windows directory: {root}")
    return root


def is_path_within(path: str | Path, parent: str | Path) -> bool:
    """Return whether *path* resolves inside *parent* without requiring existence."""

    child = Path(path).expanduser().resolve(strict=False)
    root = Path(parent).expanduser().resolve(strict=False)
    try:
        child.relative_to(root)
        return True
    except ValueError:
        return False


def ensure_writable_data_dir(value: str | Path) -> Path:
    """Create and actively verify the case-storage directory is writable."""

    destination = Path(value).expanduser().absolute()
    destination.mkdir(parents=True, exist_ok=True)
    if not destination.is_dir():
        raise OSError(f"case storage is not a directory: {destination}")
    with tempfile.NamedTemporaryFile(
        mode="wb",
        prefix=".nodetrace-write-check-",
        dir=destination,
        delete=True,
    ) as probe:
        probe.write(b"NodeTrace IR writable storage check\n")
        probe.flush()
        os.fsync(probe.fileno())
    return destination


def resource_path(*parts: str) -> Path:
    """Resolve bundled resources from source trees and PyInstaller builds."""
    bundle_root = getattr(sys, "_MEIPASS", None)
    root = Path(bundle_root) if bundle_root else Path(__file__).resolve().parent.parent
    return root.joinpath(*parts)


def choose_evidence_workspace(root: tk.Tk) -> Path | None:
    """Require an explicit live-response write destination for GUI launches."""
    messagebox.showinfo(
        "Хранилище доказательств",
        "NodeTrace IR создаёт SQLite-базу и рабочие артефакты. Это изменяет носитель, выбранный для хранения.\n\n"
        "Для расследования заражённого узла рекомендуется заранее создать папку на отдельном доверенном или внешнем носителе и выбрать её сейчас.\n\n"
        "Live-сбор не является побитово read-only acquisition.",
        parent=root,
    )
    suggested = default_data_dir()
    initial = suggested if suggested.exists() else Path.cwd()
    selected = filedialog.askdirectory(
        parent=root,
        title="Выберите или создайте папку хранилища NodeTrace IR",
        initialdir=str(initial),
        mustexist=True,
    )
    return Path(selected) if selected else None


def configure_styles(root: tk.Tk) -> None:
    root.configure(bg=COLORS["bg"])
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(".", background=COLORS["bg"], foreground=COLORS["text"], font=("Segoe UI", 9))
    style.configure("Header.TFrame", background=COLORS["header"])
    style.configure(
        "Panel.TFrame",
        background=COLORS["panel"],
        borderwidth=0,
        relief="flat",
        bordercolor=COLORS["line"],
        lightcolor=COLORS["line"],
        darkcolor=COLORS["line"],
    )
    style.configure("Card.TFrame", background=COLORS["panel2"], relief="flat")
    style.configure("TFrame", background=COLORS["bg"])
    style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"])
    style.configure("Header.TLabel", background=COLORS["header"], foreground=COLORS["text"])
    style.configure("Brand.TLabel", background=COLORS["header"], foreground=COLORS["text"], font=("Segoe UI", 11, "bold"))
    style.configure("Title.TLabel", background=COLORS["panel"], foreground=COLORS["text"], font=("Segoe UI", 10, "bold"))
    style.configure("Section.TLabel", background=COLORS["panel"], foreground=COLORS["text"], font=("Segoe UI", 10, "bold"))
    style.configure("CardTitle.TLabel", background=COLORS["panel2"], foreground=COLORS["muted"], font=("Segoe UI", 8))
    style.configure("Metric.TLabel", background=COLORS["panel2"], foreground=COLORS["text"], font=("Segoe UI", 11, "bold"))
    style.configure("Muted.TLabel", background=COLORS["bg"], foreground=COLORS["muted"])
    style.configure("PanelMuted.TLabel", background=COLORS["panel"], foreground=COLORS["muted"])
    style.configure("Panel.TLabel", background=COLORS["panel"], foreground=COLORS["text"])
    style.configure("TButton", background=COLORS["panel2"], foreground=COLORS["text"], borderwidth=1, relief="flat", padding=(8, 5))
    style.map("TButton", background=[("active", "#282828"), ("pressed", "#303030"), ("disabled", "#181818")], foreground=[("disabled", "#5f5f5f")])
    style.configure("Top.TButton", background=COLORS["header"], foreground="#cfcfcf", borderwidth=0, relief="flat", padding=(7, 4), font=("Segoe UI", 8))
    style.map("Top.TButton", background=[("active", "#292929"), ("disabled", COLORS["header"])], foreground=[("disabled", "#595959")])
    style.configure("Accent.TButton", background=COLORS["accent"], foreground="#ffffff", borderwidth=0, font=("Segoe UI", 8, "bold"), padding=(9, 5))
    style.map("Accent.TButton", background=[("active", "#ff6a38"), ("pressed", COLORS["accent2"]), ("disabled", "#673323")])
    style.configure("Danger.TButton", background="#3a2020", foreground="#ef9a9a", borderwidth=0)
    style.map("Danger.TButton", background=[("active", "#522727"), ("disabled", "#201919")], foreground=[("disabled", "#5f4949")])
    style.configure("TEntry", fieldbackground="#1b1b1b", foreground=COLORS["text"], insertcolor=COLORS["text"], bordercolor=COLORS["line"], lightcolor=COLORS["line"], darkcolor=COLORS["line"], padding=5)
    style.configure("Search.TEntry", fieldbackground="#1b1b1b", foreground=COLORS["text"], insertcolor=COLORS["text"], bordercolor="#303030", padding=5)
    style.configure("TCombobox", fieldbackground="#1b1b1b", background="#1b1b1b", foreground=COLORS["text"], arrowcolor=COLORS["muted"], bordercolor=COLORS["line"], lightcolor=COLORS["line"], darkcolor=COLORS["line"], padding=4)
    style.map("TCombobox", fieldbackground=[("readonly", "#1b1b1b")], foreground=[("readonly", COLORS["text"])])
    style.configure("Treeview", background="#141414", fieldbackground="#141414", foreground="#d7d7d7", rowheight=26, borderwidth=0, relief="flat", bordercolor=COLORS["line"], lightcolor=COLORS["line"], darkcolor=COLORS["line"])
    style.configure("Case.Treeview", background="#141414", fieldbackground="#141414", foreground="#d7d7d7", rowheight=40, borderwidth=0, relief="flat", bordercolor=COLORS["line"], lightcolor=COLORS["line"], darkcolor=COLORS["line"])
    style.configure("Properties.Treeview", background="#151515", fieldbackground="#151515", foreground="#d5d5d5", rowheight=30, borderwidth=0, relief="flat", bordercolor=COLORS["line"], lightcolor=COLORS["line"], darkcolor=COLORS["line"])
    borderless_tree = [("Treeview.treearea", {"sticky": "nswe"})]
    style.layout("Treeview", borderless_tree)
    style.layout("Case.Treeview", borderless_tree)
    style.layout("Properties.Treeview", borderless_tree)
    style.configure("Treeview.Heading", background="#1d1d1d", foreground="#999999", relief="flat", font=("Segoe UI", 8, "bold"), padding=(5, 5))
    style.map("Treeview", background=[("selected", "#3b241c")], foreground=[("selected", "#ffffff")])
    style.configure("TNotebook", background=COLORS["panel"], borderwidth=0, tabmargins=0, bordercolor=COLORS["line"], lightcolor=COLORS["line"], darkcolor=COLORS["line"])
    style.configure("TNotebook.Tab", background="#181818", foreground="#858585", padding=(11, 6), borderwidth=0, font=("Segoe UI", 8))
    style.map("TNotebook.Tab", background=[("selected", "#232323")], foreground=[("selected", COLORS["text"])])
    style.configure("Left.TNotebook", background=COLORS["panel"], borderwidth=0, tabmargins=0)
    style.configure("Left.TNotebook.Tab", background="#171717", foreground="#8d8d8d", padding=(18, 7), borderwidth=0, font=("Segoe UI", 9))
    style.map("Left.TNotebook.Tab", background=[("selected", "#222222")], foreground=[("selected", "#ffffff")])
    style.configure("Workspace.TNotebook", background=COLORS["panel"], borderwidth=0, tabmargins=0, bordercolor=COLORS["line"], lightcolor=COLORS["line"], darkcolor=COLORS["line"])
    style.layout("Workspace.TNotebook.Tab", [])
    style.configure("Horizontal.TProgressbar", background=COLORS["accent"], troughcolor="#252525", borderwidth=0)
    style.configure(
        "TScrollbar",
        background="#343434",
        troughcolor="#171717",
        bordercolor="#171717",
        arrowcolor=COLORS["muted"],
        lightcolor="#343434",
        darkcolor="#343434",
        relief="flat",
        borderwidth=0,
        arrowsize=8,
        width=9,
    )
    style.map("TScrollbar", background=[("active", "#454545"), ("pressed", COLORS["accent"])])
    style.configure("TPanedwindow", background=COLORS["bg"])


class NewCaseDialog(tk.Toplevel):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.title("Новый кейс")
        self.configure(bg=COLORS["panel"])
        self.resizable(False, False)
        self.transient(master)
        self.result: dict[str, Any] | None = None
        self.title_var = tk.StringVar(value="Расследование подозрительного файла")
        self.path_var = tk.StringVar()
        self.lookback_var = tk.IntVar(value=7)

        shell = ttk.Frame(self, style="Panel.TFrame", padding=22)
        shell.grid(sticky="nsew")
        ttk.Label(shell, text="Создание кейса", style="Section.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
        ttk.Label(shell, text="Подозрительный файл не будет запущен — только прочитан для хэширования.", style="PanelMuted.TLabel", wraplength=520).grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 18))
        ttk.Label(shell, text="Название", style="Panel.TLabel").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Entry(shell, textvariable=self.title_var, width=56).grid(row=2, column=1, columnspan=2, sticky="ew", pady=5)
        ttk.Label(shell, text="Файл-зерно", style="Panel.TLabel").grid(row=3, column=0, sticky="w", pady=5)
        ttk.Entry(shell, textvariable=self.path_var, width=48).grid(row=3, column=1, sticky="ew", pady=5)
        ttk.Button(shell, text="Обзор…", command=self._browse).grid(row=3, column=2, padx=(8, 0), pady=5)
        ttk.Label(shell, text="Глубина, дней", style="Panel.TLabel").grid(row=4, column=0, sticky="w", pady=5)
        ttk.Spinbox(shell, from_=1, to=90, textvariable=self.lookback_var, width=10).grid(row=4, column=1, sticky="w", pady=5)
        ttk.Label(shell, text="Заметка", style="Panel.TLabel").grid(row=5, column=0, sticky="nw", pady=5)
        self.notes = tk.Text(shell, width=48, height=5, bg="#1b1b1b", fg=COLORS["text"], insertbackground=COLORS["text"], relief="flat", padx=8, pady=7, wrap="word")
        self.notes.grid(row=5, column=1, columnspan=2, sticky="ew", pady=5)
        buttons = ttk.Frame(shell, style="Panel.TFrame")
        buttons.grid(row=6, column=0, columnspan=3, sticky="e", pady=(18, 0))
        ttk.Button(buttons, text="Отмена", command=self.destroy).pack(side="left", padx=5)
        ttk.Button(buttons, text="Создать", style="Accent.TButton", command=self._accept).pack(side="left", padx=5)
        shell.columnconfigure(1, weight=1)
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.grab_set()
        self.after(50, self._center)

    def _browse(self) -> None:
        path = filedialog.askopenfilename(parent=self, title="Выберите подозрительный файл (он не будет запущен)")
        if path:
            self.path_var.set(path)
            if self.title_var.get() == "Расследование подозрительного файла":
                self.title_var.set(f"Расследование {Path(path).name}")

    def _accept(self) -> None:
        title = self.title_var.get().strip()
        if not title:
            messagebox.showwarning("Название", "Введите название кейса.", parent=self)
            return
        self.result = {
            "title": title,
            "suspect_path": self.path_var.get().strip(),
            "lookback_days": max(1, int(self.lookback_var.get() or 7)),
            "description": self.notes.get("1.0", "end").strip(),
        }
        self.destroy()

    def _center(self) -> None:
        self.update_idletasks()
        parent = self.master.winfo_toplevel()
        x = parent.winfo_rootx() + max(0, (parent.winfo_width() - self.winfo_width()) // 2)
        y = parent.winfo_rooty() + max(0, (parent.winfo_height() - self.winfo_height()) // 2)
        self.geometry(f"+{x}+{y}")


class NodeTraceApp:
    def __init__(
        self,
        root: tk.Tk,
        data_dir: Path,
        *,
        target_mode: str = "live",
        offline_root: str | Path | None = None,
        winpe: bool = False,
    ) -> None:
        self.root = root
        self.data_dir = data_dir
        self.target_mode = str(target_mode or "live").strip().casefold()
        if self.target_mode not in {"live", "offline"}:
            raise ValueError("target_mode must be 'live' or 'offline'")
        if self.target_mode == "offline" and offline_root is None:
            raise ValueError("offline_root is required for an offline target")
        self.offline_root = (
            Path(offline_root).expanduser().absolute()
            if self.target_mode == "offline" and offline_root is not None
            else None
        )
        self.winpe = bool(winpe)
        self.auto_export = self.winpe
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.database = Database(self.data_dir / "nodetrace_ir.sqlite3")
        self.current_case_id: int | None = None
        self.current_case: Any = None
        self._evidence: dict[int, Any] = {}
        self._timeline: list[Any] = []
        self._relations: list[Any] = []
        self._gaps: list[Any] = []
        self._impact_assessment: Any = None
        self._selected_evidence_id: int | None = None
        self._worker: Thread | None = None
        self._cancel_event: Event | None = None
        self._events: queue.Queue[dict[str, Any]] = queue.Queue()
        self._closing = False
        self._window_icon: tk.PhotoImage | None = None
        self._brand_image: tk.PhotoImage | None = None

        mode_suffix = " · OFFLINE TARGET" if self.target_mode == "offline" else ""
        self.root.title(f"NodeTrace IR {__version__}{mode_suffix}")
        self.root.geometry("1480x900")
        self.root.minsize(1120, 700)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        configure_styles(root)
        self._load_brand_assets()
        self._build_ui()
        self._refresh_cases(select_first=True)
        self.root.after(120, self._poll_events)
        self.root.after(350, self._auto_startup_investigation)

    def _load_brand_assets(self) -> None:
        try:
            self._window_icon = tk.PhotoImage(
                master=self.root,
                file=str(resource_path("assets", "nodetrace-icon.png")),
            )
            self.root.iconphoto(True, self._window_icon)
            max_dimension = max(self._window_icon.width(), self._window_icon.height())
            scale = max(1, (max_dimension + 29) // 30)
            self._brand_image = self._window_icon.subsample(scale, scale)
        except (OSError, tk.TclError):
            self._window_icon = None
            self._brand_image = None

    def _build_ui(self) -> None:
        self.root.rowconfigure(1, weight=1)
        self.root.columnconfigure(0, weight=1)
        self.breadcrumb_var = tk.StringVar(value="Расследование  /  Кейс не выбран")
        self.search_var = tk.StringVar()

        topbar = tk.Frame(
            self.root,
            bg=COLORS["header"],
            height=46,
            highlightbackground=COLORS["line"],
            highlightthickness=1,
        )
        topbar.grid(row=0, column=0, sticky="ew")
        topbar.grid_propagate(False)
        topbar.columnconfigure(2, weight=1)

        brand = tk.Frame(topbar, bg=COLORS["header"])
        brand.grid(row=0, column=0, sticky="w", padx=(10, 14), pady=5)
        if self._brand_image is not None:
            tk.Label(brand, image=self._brand_image, bg=COLORS["header"], bd=0).pack(
                side="left", padx=(0, 7)
            )
        tk.Label(
            brand,
            text="NodeTrace IR",
            bg=COLORS["header"],
            fg=COLORS["text"],
            font=("Segoe UI", 11, "bold"),
        ).pack(side="left")

        tk.Label(
            topbar,
            textvariable=self.breadcrumb_var,
            bg=COLORS["header"],
            fg="#b0b0b0",
            font=("Segoe UI", 9),
            anchor="w",
        ).grid(row=0, column=1, sticky="w", padx=(4, 12))

        search_shell = tk.Frame(topbar, bg=COLORS["header"])
        search_shell.grid(row=0, column=2, pady=7)
        ttk.Entry(
            search_shell,
            textvariable=self.search_var,
            style="Search.TEntry",
            width=38,
        ).pack()

        actions = tk.Frame(topbar, bg=COLORS["header"])
        actions.grid(row=0, column=3, sticky="e", padx=(8, 8), pady=5)
        admin_text = "АДМИН" if is_admin() else "ОГР. ПРАВА"
        admin_color = COLORS["accent"] if is_admin() else COLORS["warning"]
        self.admin_badge = tk.Label(
            actions,
            text=f"● {admin_text}",
            bg=COLORS["header"],
            fg=admin_color,
            font=("Segoe UI", 7, "bold"),
            padx=5,
        )
        self.admin_badge.pack(side="left", padx=(0, 5))
        self.new_button = ttk.Button(actions, text="＋ Кейс", style="Top.TButton", command=self._new_case)
        self.new_button.pack(side="left", padx=1)
        self.cancel_button = ttk.Button(actions, text="■ Стоп", style="Danger.TButton", command=self._cancel_collection, state="disabled")
        self.cancel_button.pack(side="left", padx=1)
        self.export_button = ttk.Button(actions, text="⇩ Экспорт", style="Top.TButton", command=self._export_case)
        self.export_button.pack(side="left", padx=1)
        ttk.Button(actions, text="◇ Демо", style="Top.TButton", command=self._create_demo).pack(side="left", padx=1)
        ttk.Button(actions, text="↻", style="Top.TButton", command=self._refresh_current).pack(side="left", padx=(1, 0))

        if self.winpe:
            # WinPE is an unattended appliance: boot starts analysis and the
            # verified export automatically. Keep the status badge, but hide
            # every operator action so no start/export button is required.
            for widget in actions.winfo_children():
                if widget is not self.admin_badge:
                    widget.pack_forget()

        workspace = tk.Frame(self.root, bg=COLORS["bg"])
        workspace.grid(row=1, column=0, sticky="nsew")
        workspace.rowconfigure(0, weight=1)
        workspace.columnconfigure(2, weight=1, minsize=420)
        workspace.columnconfigure(0, minsize=54)
        workspace.columnconfigure(1, minsize=290)
        workspace.columnconfigure(3, minsize=300)
        self._build_icon_rail(workspace)
        self._build_case_panel(workspace)
        self._build_center(workspace)
        self._build_inspector(workspace)

        status = tk.Frame(
            self.root,
            bg=COLORS["header"],
            height=23,
            highlightbackground=COLORS["line"],
            highlightthickness=1,
        )
        status.grid(row=2, column=0, sticky="ew")
        status.grid_propagate(False)
        status.columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value=f"Готово · данные: {self.data_dir}")
        tk.Label(status, textvariable=self.status_var, bg=COLORS["header"], fg="#8e8e8e", font=("Segoe UI", 8), anchor="w").grid(row=0, column=0, sticky="ew", padx=8)
        self.progress = ttk.Progressbar(status, mode="determinate", length=170, maximum=100)
        self.progress.grid(row=0, column=1, sticky="e", padx=(6, 8), pady=7)

    def _build_icon_rail(self, parent: tk.Misc) -> None:
        rail = tk.Frame(
            parent,
            bg="#161616",
            width=54,
            highlightbackground=COLORS["line"],
            highlightthickness=1,
        )
        rail.grid(row=0, column=0, sticky="nsew")
        rail.grid_propagate(False)
        rail.rowconfigure(8, weight=1)
        items = (
            ("⌂", lambda: self._select_workspace(0, 0)),
            ("◎", lambda: self._select_workspace(0)),
            ("≋", lambda: self._select_workspace(1)),
            ("▤", lambda: self._select_workspace(2, 1)),
            ("△", lambda: self._select_workspace(4)),
        )
        for row, (glyph, command) in enumerate(items):
            tk.Button(
                rail,
                text=glyph,
                command=command,
                bg="#161616",
                fg="#9a9a9a",
                activebackground="#242424",
                activeforeground=COLORS["accent"],
                relief="flat",
                bd=0,
                highlightthickness=0,
                font=("Segoe UI Symbol", 14),
                cursor="hand2",
            ).grid(row=row, column=0, sticky="ew", padx=5, pady=(5 if row == 0 else 1, 1), ipady=6)
        tk.Button(
            rail,
            text="◇",
            command=self._create_demo,
            bg="#161616",
            fg="#777777",
            activebackground="#242424",
            activeforeground=COLORS["accent"],
            relief="flat",
            bd=0,
            highlightthickness=0,
            font=("Segoe UI Symbol", 13),
            cursor="hand2",
        ).grid(row=9, column=0, sticky="ew", padx=5, pady=6, ipady=5)

    def _select_workspace(self, index: int, left_index: int | None = None) -> None:
        if hasattr(self, "workspace_notebook"):
            self.workspace_notebook.select(index)
        if left_index is not None and hasattr(self, "left_notebook"):
            self.left_notebook.select(left_index)

    def _build_case_panel(self, parent: tk.Misc) -> None:
        panel = tk.Frame(
            parent,
            bg=COLORS["panel"],
            width=290,
            highlightbackground=COLORS["line"],
            highlightthickness=1,
        )
        panel.grid(row=0, column=1, sticky="nsew")
        panel.grid_propagate(False)
        panel.rowconfigure(0, weight=1)
        panel.columnconfigure(0, weight=1)
        self.left_notebook = ttk.Notebook(panel, style="Left.TNotebook")
        self.left_notebook.grid(row=0, column=0, sticky="nsew")

        cases_tab = ttk.Frame(self.left_notebook, style="Panel.TFrame", padding=(8, 8, 8, 6))
        evidence_tab = ttk.Frame(self.left_notebook, style="Panel.TFrame", padding=(8, 8, 8, 6))
        self.left_notebook.add(cases_tab, text="Кейсы")
        self.left_notebook.add(evidence_tab, text="Объекты")

        cases_tab.rowconfigure(1, weight=1)
        cases_tab.columnconfigure(0, weight=1)
        self.case_search_var = tk.StringVar()
        ttk.Entry(cases_tab, textvariable=self.case_search_var, style="Search.TEntry").grid(row=0, column=0, sticky="ew", pady=(0, 7))
        case_list = ttk.Frame(cases_tab, style="Panel.TFrame")
        case_list.grid(row=1, column=0, sticky="nsew")
        case_list.rowconfigure(0, weight=1)
        case_list.columnconfigure(0, weight=1)
        self.case_tree = ttk.Treeview(case_list, show="tree", selectmode="browse", style="Case.Treeview")
        self.case_tree.grid(row=0, column=0, sticky="nsew")
        case_scroll = ttk.Scrollbar(case_list, orient="vertical", command=self.case_tree.yview)
        case_scroll.grid(row=0, column=1, sticky="ns")
        self.case_tree.configure(yscrollcommand=case_scroll.set)
        self.case_tree.bind("<<TreeviewSelect>>", self._case_selected)
        self.case_count_var = tk.StringVar(value="0 кейсов")
        ttk.Label(cases_tab, textvariable=self.case_count_var, style="PanelMuted.TLabel").grid(row=2, column=0, sticky="w", pady=(6, 0))

        evidence_tab.rowconfigure(1, weight=1)
        evidence_tab.columnconfigure(0, weight=1)
        ttk.Entry(evidence_tab, textvariable=self.search_var, style="Search.TEntry").grid(row=0, column=0, sticky="ew", pady=(0, 7))
        evidence_list = ttk.Frame(evidence_tab, style="Panel.TFrame")
        evidence_list.grid(row=1, column=0, sticky="nsew")
        self.left_evidence_tree = self._tree(evidence_list, ("type", "label"), (76, 190))
        self.left_evidence_tree.bind("<<TreeviewSelect>>", self._table_selected)
        self.evidence_count_var = tk.StringVar(value="0 объектов")
        ttk.Label(evidence_tab, textvariable=self.evidence_count_var, style="PanelMuted.TLabel").grid(row=2, column=0, sticky="w", pady=(6, 0))

        self.metric_evidence = tk.StringVar(value="0")
        self.metric_relations = tk.StringVar(value="0")
        self.metric_gaps = tk.StringVar(value="0")
        self.metric_high = tk.StringVar(value="0")
        self.left_stats_var = tk.StringVar(value="0 наблюдений · 0 связей · 0 пробелов")
        self.case_search_var.trace_add("write", lambda *_: self._refresh_cases())

    def _build_center(self, parent: tk.Misc) -> None:
        center = tk.Frame(
            parent,
            bg=COLORS["panel"],
            highlightbackground=COLORS["line"],
            highlightthickness=1,
        )
        center.grid(row=0, column=2, sticky="nsew")
        center.rowconfigure(2, weight=1)
        center.columnconfigure(0, weight=1)
        self.case_title_var = tk.StringVar(value="Выберите или создайте кейс")
        self.case_subtitle_var = tk.StringVar(value="")
        self.coverage_var = tk.StringVar(value="ИСТОЧНИКОВ —")
        self.type_var = tk.StringVar(value="Все типы")
        self.confidence_var = tk.StringVar(value="Любая уверенность")
        pipeline = tk.Frame(
            center,
            bg="#121212",
            height=62,
            highlightbackground=COLORS["line"],
            highlightthickness=1,
        )
        pipeline.grid(row=0, column=0, sticky="ew")
        pipeline.grid_propagate(False)
        self.stage_status_vars: dict[str, tk.StringVar] = {}
        self.stage_status_labels: dict[str, tk.Label] = {}
        self.stage_cards: dict[str, tk.Frame] = {}
        stages = (
            ("DETECT", "01", "ДЕТЕКТИРОВАНИЕ"),
            ("PRESERVE", "02", "СОХРАНЕНИЕ"),
            ("INVESTIGATE", "03", "РАССЛЕДОВАНИЕ"),
            ("IMPACT", "04", "ВЛИЯНИЕ"),
        )
        for column, (stage, number, title) in enumerate(stages):
            pipeline.columnconfigure(column, weight=1, uniform="pipeline")
            card = tk.Frame(
                pipeline,
                bg="#1a1a1a",
                highlightbackground="#303030",
                highlightthickness=1,
            )
            card.grid(
                row=0,
                column=column,
                sticky="nsew",
                padx=(7 if column == 0 else 3, 7 if column == len(stages) - 1 else 3),
                pady=7,
            )
            card.columnconfigure(1, weight=1)
            tk.Label(
                card,
                text=number,
                bg="#1a1a1a",
                fg=COLORS["accent"],
                font=("Segoe UI", 12, "bold"),
                padx=9,
            ).grid(row=0, column=0, rowspan=2, sticky="nsw")
            tk.Label(
                card,
                text=title,
                bg="#1a1a1a",
                fg="#d8d8d8",
                font=("Segoe UI", 7, "bold"),
                anchor="w",
            ).grid(row=0, column=1, sticky="sew", padx=(0, 5), pady=(5, 0))
            status_var = tk.StringVar(value="ОЖИДАЕТ")
            status_label = tk.Label(
                card,
                textvariable=status_var,
                bg="#1a1a1a",
                fg=COLORS["muted"],
                font=("Segoe UI", 7),
                anchor="w",
            )
            status_label.grid(row=1, column=1, sticky="new", padx=(0, 5), pady=(0, 5))
            self.stage_status_vars[stage] = status_var
            self.stage_status_labels[stage] = status_label
            self.stage_cards[stage] = card

        controls = tk.Frame(center, bg="#181818", height=38, highlightbackground=COLORS["line"], highlightthickness=1)
        controls.grid(row=1, column=0, sticky="ew")
        controls.grid_propagate(False)
        controls.columnconfigure(1, weight=1)
        modes = tk.Frame(controls, bg="#181818")
        modes.grid(row=0, column=0, sticky="w", padx=(5, 2), pady=4)
        for label, index in (("Граф", 0), ("Хронология", 1), ("Расследование", 2), ("Объекты", 3), ("Пробелы", 4)):
            ttk.Button(
                modes,
                text=label,
                style="Top.TButton",
                command=lambda target=index: self._select_workspace(target),
            ).pack(side="left", padx=1)
        self.coverage_badge = tk.Label(controls, textvariable=self.coverage_var, bg="#181818", fg=COLORS["muted"], font=("Segoe UI", 7, "bold"), padx=6)
        self.coverage_badge.grid(row=0, column=1, sticky="e", padx=4)
        ttk.Combobox(controls, textvariable=self.type_var, state="readonly", width=14, values=tuple(FILTER_TO_GROUP)).grid(row=0, column=2, padx=3, pady=5)
        ttk.Combobox(controls, textvariable=self.confidence_var, state="readonly", width=16, values=("Любая уверенность", "high", "medium", "low")).grid(row=0, column=3, padx=(3, 7), pady=5)

        self.workspace_notebook = ttk.Notebook(center, style="Workspace.TNotebook")
        self.workspace_notebook.grid(row=2, column=0, sticky="nsew")
        graph_tab = ttk.Frame(self.workspace_notebook, style="Panel.TFrame")
        timeline_tab = ttk.Frame(self.workspace_notebook, style="Panel.TFrame", padding=4)
        investigation_tab = ttk.Frame(self.workspace_notebook, style="Panel.TFrame", padding=4)
        evidence_tab = ttk.Frame(self.workspace_notebook, style="Panel.TFrame", padding=4)
        gap_tab = ttk.Frame(self.workspace_notebook, style="Panel.TFrame", padding=4)
        self.workspace_notebook.add(graph_tab, text="Граф")
        self.workspace_notebook.add(timeline_tab, text="Хронология")
        self.workspace_notebook.add(investigation_tab, text="Расследование")
        self.workspace_notebook.add(evidence_tab, text="Объекты")
        self.workspace_notebook.add(gap_tab, text="Пробелы")
        graph_tab.rowconfigure(0, weight=1); graph_tab.columnconfigure(0, weight=1)
        self.graph = EvidenceGraph(graph_tab, on_select=self._select_evidence)
        self.graph.grid(row=0, column=0, sticky="nsew")

        self.timeline_tree = self._tree(timeline_tab, ("time", "type", "event", "source", "confidence"), (170, 95, 360, 180, 105))
        self.timeline_tree.bind("<<TreeviewSelect>>", self._table_selected)

        investigation_tab.rowconfigure(2, weight=1)
        investigation_tab.columnconfigure(0, weight=1)
        investigation_header = tk.Frame(investigation_tab, bg=COLORS["panel"], height=42)
        investigation_header.grid(row=0, column=0, sticky="ew", padx=4, pady=(1, 3))
        investigation_header.grid_propagate(False)
        investigation_header.columnconfigure(0, weight=1)
        self.investigation_summary_var = tk.StringVar(value="Цепочка воздействия ещё не построена")
        tk.Label(
            investigation_header,
            textvariable=self.investigation_summary_var,
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=("Segoe UI", 9, "bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="ew", padx=5, pady=(3, 0))
        tk.Label(
            investigation_header,
            text="Наблюдение = прямое показание · корреляция = связь источников · гипотеза требует проверки",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=("Segoe UI", 7),
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", padx=5)

        causal_chain = tk.Frame(
            investigation_tab,
            bg="#111111",
            height=112,
            highlightbackground=COLORS["line"],
            highlightthickness=1,
        )
        causal_chain.grid(row=1, column=0, sticky="ew", padx=4, pady=(0, 4))
        causal_chain.grid_propagate(False)
        for column in (0, 2, 4):
            causal_chain.columnconfigure(column, weight=1, uniform="causal-chain")
        tk.Label(
            causal_chain,
            text="ПРИЧИННАЯ ЦЕПОЧКА · ТОЛЬКО ПО ЗАФИКСИРОВАННЫМ ПОКАЗАНИЯМ И КОРРЕЛЯЦИЯМ",
            bg="#111111",
            fg="#777777",
            font=("Segoe UI", 7, "bold"),
            anchor="w",
        ).grid(row=0, column=0, columnspan=5, sticky="ew", padx=8, pady=(5, 2))

        self.chain_source_var = tk.StringVar(value="Не установлен")
        self.chain_source_meta_var = tk.StringVar(
            value="Нет подтверждённой связи происхождения"
        )
        self.chain_file_var = tk.StringVar(value="Не установлен")
        self.chain_file_meta_var = tk.StringVar(value="Файл-зерно ещё не подтверждён")
        self.chain_impact_var = tk.StringVar(value="Не установлено")
        self.chain_impact_meta_var = tk.StringVar(value="Связанное воздействие ещё не выявлено")

        chain_cards = (
            (
                0,
                "01  ОТКУДА ПОПАЛ ФАЙЛ",
                self.chain_source_var,
                self.chain_source_meta_var,
                "#1b2023",
                "#56a9c7",
            ),
            (
                2,
                "02  ФАЙЛ",
                self.chain_file_var,
                self.chain_file_meta_var,
                "#261b17",
                COLORS["accent"],
            ),
            (
                4,
                "03  ВОЗДЕЙСТВИЕ ФАЙЛА",
                self.chain_impact_var,
                self.chain_impact_meta_var,
                "#21191d",
                "#d46b8d",
            ),
        )
        for column, title, value_var, meta_var, background, accent in chain_cards:
            card = tk.Frame(
                causal_chain,
                bg=background,
                height=75,
                highlightbackground=accent,
                highlightthickness=1,
            )
            card.grid(row=1, column=column, sticky="nsew", padx=7, pady=(0, 7))
            card.grid_propagate(False)
            card.columnconfigure(0, weight=1)
            tk.Label(
                card,
                text=title,
                bg=background,
                fg=accent,
                font=("Segoe UI", 7, "bold"),
                anchor="w",
            ).grid(row=0, column=0, sticky="ew", padx=9, pady=(6, 0))
            tk.Label(
                card,
                textvariable=value_var,
                bg=background,
                fg="#f1f1f1",
                font=("Segoe UI", 10, "bold"),
                anchor="w",
            ).grid(row=1, column=0, sticky="ew", padx=9, pady=(2, 0))
            tk.Label(
                card,
                textvariable=meta_var,
                bg=background,
                fg="#999999",
                font=("Segoe UI", 7),
                anchor="w",
            ).grid(row=2, column=0, sticky="ew", padx=9, pady=(0, 5))
        for column in (1, 3):
            tk.Label(
                causal_chain,
                text="→",
                bg="#111111",
                fg=COLORS["accent"],
                font=("Segoe UI", 17, "bold"),
            ).grid(row=1, column=column, padx=0, pady=(0, 7))

        self.investigation_notebook = ttk.Notebook(investigation_tab)
        self.investigation_notebook.grid(row=2, column=0, sticky="nsew")
        entry_tab = ttk.Frame(self.investigation_notebook, style="Panel.TFrame", padding=4)
        processes_tab = ttk.Frame(self.investigation_notebook, style="Panel.TFrame", padding=4)
        impact_tab = ttk.Frame(self.investigation_notebook, style="Panel.TFrame", padding=4)
        self.investigation_notebook.add(entry_tab, text="Как попало")
        self.investigation_notebook.add(processes_tab, text="Процессы")
        self.investigation_notebook.add(impact_tab, text="Что затронуто")
        self.entry_tree = self._tree(
            entry_tab,
            ("basis", "label", "relation", "confidence"),
            (120, 330, 230, 105),
        )
        self.process_tree = self._tree(
            processes_tab,
            ("basis", "label", "confidence", "chain"),
            (120, 330, 105, 330),
        )
        self.impact_tree = self._tree(
            impact_tab,
            ("category", "basis", "label", "confidence", "chain"),
            (120, 110, 300, 100, 310),
        )
        self.impact_limitations_var = tk.StringVar(value="Полнота зависит от журналов и доступной телеметрии.")
        tk.Label(
            investigation_tab,
            textvariable=self.impact_limitations_var,
            bg=COLORS["panel"],
            fg=COLORS["warning"],
            font=("Segoe UI", 7),
            anchor="w",
        ).grid(row=3, column=0, sticky="ew", padx=7, pady=(4, 1))
        self.evidence_tree = self._tree(evidence_tab, ("type", "label", "source", "severity", "confidence", "digest"), (110, 360, 180, 90, 100, 170))
        self.evidence_tree.bind("<<TreeviewSelect>>", self._table_selected)
        self.gap_tree = self._tree(gap_tab, ("collector", "source", "reason", "impact"), (120, 160, 330, 350))
        self.gap_tree.bind("<<TreeviewSelect>>", self._gap_selected)
        self.search_var.trace_add("write", lambda *_: self._apply_filters())
        self.type_var.trace_add("write", lambda *_: self._apply_filters())
        self.confidence_var.trace_add("write", lambda *_: self._apply_filters())

    @staticmethod
    def _tree(parent: ttk.Frame, columns: tuple[str, ...], widths: tuple[int, ...]) -> ttk.Treeview:
        parent.rowconfigure(0, weight=1); parent.columnconfigure(0, weight=1)
        tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
        labels = {"time": "Время UTC", "type": "Тип", "event": "Событие", "label": "Объект", "source": "Источник", "confidence": "Уверенность", "severity": "Риск", "digest": "Digest", "collector": "Коллектор", "reason": "Причина", "impact": "Влияние", "basis": "Основание", "relation": "Связь", "category": "Категория", "chain": "Цепочка"}
        for column, width in zip(columns, widths):
            tree.heading(column, text=labels.get(column, column))
            tree.column(column, width=width, minwidth=70, stretch=column in {"event", "label", "reason", "impact", "chain", "relation"})
        ybar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        xbar = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        tree.grid(row=0, column=0, sticky="nsew"); ybar.grid(row=0, column=1, sticky="ns"); xbar.grid(row=1, column=0, sticky="ew")
        return tree

    def _build_inspector(self, parent: tk.Misc) -> None:
        panel = tk.Frame(
            parent,
            bg=COLORS["panel"],
            width=300,
            highlightbackground=COLORS["line"],
            highlightthickness=1,
        )
        panel.grid(row=0, column=3, sticky="nsew")
        panel.grid_propagate(False)
        panel.rowconfigure(1, weight=1)
        panel.columnconfigure(0, weight=1)

        heading = tk.Frame(panel, bg=COLORS["panel"], height=58)
        heading.grid(row=0, column=0, sticky="ew")
        heading.grid_propagate(False)
        heading.columnconfigure(0, weight=1)
        self.inspector_title_var = tk.StringVar(value="Свойства")
        self.inspector_meta_var = tk.StringVar(value="НЕТ ВЫБОРА")
        tk.Label(heading, textvariable=self.inspector_title_var, bg=COLORS["panel"], fg=COLORS["text"], font=("Segoe UI", 11, "bold"), anchor="w").grid(row=0, column=0, sticky="ew", padx=11, pady=(7, 0))
        tk.Label(heading, textvariable=self.inspector_meta_var, bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 7, "bold"), anchor="w").grid(row=1, column=0, sticky="ew", padx=11, pady=(0, 7))

        table = ttk.Frame(panel, style="Panel.TFrame")
        table.grid(row=1, column=0, sticky="nsew")
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)
        self.inspector = ttk.Treeview(
            table,
            columns=("property", "value"),
            show="headings",
            selectmode="browse",
            style="Properties.Treeview",
        )
        self.inspector.heading("property", text="ПОЛЕ")
        self.inspector.heading("value", text="ЗНАЧЕНИЕ")
        self.inspector.column("property", width=98, minwidth=78, stretch=False)
        self.inspector.column("value", width=194, minwidth=120, stretch=True)
        ybar = ttk.Scrollbar(table, orient="vertical", command=self.inspector.yview)
        self.inspector.configure(yscrollcommand=ybar.set)
        self.inspector.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        self.inspector.bind("<Double-1>", self._copy_property_value)
        self._show_inspector_message("Выберите узел графа или строку таймлайна.")

    def _refresh_cases(self, select_first: bool = False, select_id: int | None = None) -> None:
        all_cases = self.database.list_cases()
        query = self.case_search_var.get().strip().lower() if hasattr(self, "case_search_var") else ""
        cases = [
            case for case in all_cases
            if not query
            or query in str(_get(case, "title", "")).lower()
            or query in str(_get(case, "suspect_path", "")).lower()
            or query in str(_get(case, "hostname", "")).lower()
        ]
        if hasattr(self, "case_count_var"):
            suffix = f" / {len(all_cases)}" if len(cases) != len(all_cases) else ""
            self.case_count_var.set(f"{len(cases)}{suffix} кейсов")
        selected = select_id or self.current_case_id
        self.case_tree.delete(*self.case_tree.get_children())
        for case in cases:
            title = str(_get(case, "title", f"Кейс {_get(case, 'id')}"))
            status = str(_get(case, "status", "open"))
            prefix = "●" if status == "open" else "○"
            iid = f"case:{_get(case, 'id')}"
            self.case_tree.insert("", "end", iid=iid, text=f"{prefix}  {title[:34]}\n    {status} · {str(_get(case, 'updated_at', ''))[:16]}")
        if selected is not None and self.case_tree.exists(f"case:{selected}"):
            self.case_tree.selection_set(f"case:{selected}")
            self.case_tree.focus(f"case:{selected}")
            self._load_case(int(selected))
        elif select_first and cases:
            first_id = int(_get(cases[0], "id"))
            self.case_tree.selection_set(f"case:{first_id}")
            self._load_case(first_id)
        elif not all_cases:
            self._clear_case()

    def _case_selected(self, _event: tk.Event | None = None) -> None:
        selected = self.case_tree.selection()
        if selected:
            self._load_case(int(selected[0].split(":", 1)[1]))

    def _load_case(self, case_id: int) -> None:
        case = self.database.get_case(case_id)
        if case is None:
            return
        self.current_case_id = case_id
        self.current_case = case
        self._evidence = {int(_get(row, "id")): row for row in self.database.list_evidence(case_id)}
        self._timeline = list(self.database.list_timeline(case_id))
        self._relations = list(self.database.list_relations(case_id))
        self._gaps = list(self.database.list_gaps(case_id))
        try:
            self._impact_assessment = ImpactAnalyzer(self.database).analyze(
                case_id, str(_get(case, "suspect_path", ""))
            )
        except Exception:
            self._impact_assessment = None
        title = str(_get(case, "title", f"Кейс {case_id}"))
        self.case_title_var.set(title)
        suspect = str(_get(case, "suspect_path", "")) or "файл-зерно не указан"
        self.case_subtitle_var.set(f"{_get(case, 'hostname', socket.gethostname())} · {suspect}")
        seed_name = Path(suspect).name if suspect != "файл-зерно не указан" else "Файл не указан"
        self.breadcrumb_var.set(f"Расследование  /  {title[:34]}  /  {seed_name[:28]}")
        self._update_metrics()
        self._apply_filters()
        self._refresh_pipeline_summary()
        self._show_case_overview()

    def _clear_case(self) -> None:
        self.current_case_id = None; self.current_case = None
        self._evidence = {}; self._timeline = []; self._relations = []; self._gaps = []
        self._impact_assessment = None
        self.case_title_var.set("Создайте первый кейс")
        self.case_subtitle_var.set("Выберите подозрительный файл или откройте синтетический демо-кейс")
        self.breadcrumb_var.set("Расследование  /  Кейс не выбран")
        self.graph.clear()
        for tree in (
            self.timeline_tree,
            self.evidence_tree,
            self.gap_tree,
            self.left_evidence_tree,
            self.entry_tree,
            self.process_tree,
            self.impact_tree,
        ):
            tree.delete(*tree.get_children())
        self.investigation_summary_var.set("Цепочка воздействия ещё не построена")
        self.chain_source_var.set("Не установлен")
        self.chain_source_meta_var.set("Нет подтверждённой связи происхождения")
        self.chain_file_var.set("Не установлен")
        self.chain_file_meta_var.set("Файл-зерно ещё не подтверждён")
        self.chain_impact_var.set("Не установлено")
        self.chain_impact_meta_var.set("Связанное воздействие ещё не выявлено")
        self.impact_limitations_var.set("Полнота зависит от журналов и доступной телеметрии.")
        for stage in ("DETECT", "PRESERVE", "INVESTIGATE", "IMPACT"):
            self._set_pipeline_stage(stage, "ОЖИДАЕТ", "pending")
        self._update_metrics()
        self._show_inspector_message("Выберите кейс или создайте новое расследование.")

    def _update_metrics(self) -> None:
        high = sum(1 for row in self._evidence.values() if str(_get(row, "severity", "")) in {"high", "critical"})
        self.metric_evidence.set(str(len(self._timeline)))
        self.metric_relations.set(str(len(self._relations)))
        self.metric_gaps.set(str(len(self._gaps)))
        self.metric_high.set(str(high))
        self.left_stats_var.set(
            f"{len(self._timeline)} наблюдений · {len(self._relations)} связей · {len(self._gaps)} пробелов"
        )
        if hasattr(self, "evidence_count_var"):
            self.evidence_count_var.set(f"{len(self._evidence)} объектов · {high} высокого риска")
        sources = {str(_get(row, "source", "")) for row in self._evidence.values() if _get(row, "source")}
        if self._evidence:
            self.coverage_var.set(f"ИСТОЧНИКОВ {len(sources)} · ПРОБЕЛОВ {len(self._gaps)}")
            self.coverage_badge.configure(fg=COLORS["accent"] if not self._gaps else COLORS["warning"])
        else:
            self.coverage_var.set("ИСТОЧНИКОВ —")
            self.coverage_badge.configure(fg=COLORS["muted"])

    def _filtered_evidence(self) -> list[Any]:
        query_text = self.search_var.get().strip().lower()
        entity_filter = FILTER_TO_GROUP.get(self.type_var.get(), "all")
        confidence_filter = self.confidence_var.get()
        rows = []
        for row in self._evidence.values():
            entity = str(_get(row, "entity_type", ""))
            if entity_filter != "all" and entity_group(entity) != entity_filter:
                continue
            if confidence_filter != "Любая уверенность" and str(_get(row, "confidence", "")) != confidence_filter:
                continue
            searchable = " ".join((str(_get(row, "label", "")), str(_get(row, "source", "")), json.dumps(_get(row, "properties", {}), ensure_ascii=False, default=str))).lower()
            if query_text and query_text not in searchable:
                continue
            rows.append(row)
        return rows

    def _filtered_timeline(self) -> list[Any]:
        query_text = self.search_var.get().strip().lower()
        entity_filter = FILTER_TO_GROUP.get(self.type_var.get(), "all")
        confidence_filter = self.confidence_var.get()
        rows = []
        for row in self._timeline:
            entity = str(_get(row, "entity_type", ""))
            if entity_filter != "all" and entity_group(entity) != entity_filter:
                continue
            if confidence_filter != "Любая уверенность" and str(_get(row, "confidence", "")) != confidence_filter:
                continue
            searchable = " ".join((str(_get(row, "label", "")), str(_get(row, "source", "")), json.dumps(_get(row, "properties", {}), ensure_ascii=False, default=str))).lower()
            if query_text and query_text not in searchable:
                continue
            rows.append(row)
        return rows

    def _apply_filters(self) -> None:
        if not hasattr(self, "timeline_tree"):
            return
        rows = self._filtered_evidence()
        ids = {int(_get(row, "id")) for row in rows}
        relations = [row for row in self._relations if _get(row, "source_evidence_id") in ids and _get(row, "target_evidence_id") in ids]
        graph_rows = self._graph_subset(rows, 180)
        graph_ids = {int(_get(row, "id")) for row in graph_rows}
        graph_relations = [
            row for row in relations
            if _get(row, "source_evidence_id") in graph_ids
            and _get(row, "target_evidence_id") in graph_ids
        ]
        self.graph.render(graph_rows, graph_relations, self._selected_evidence_id)
        self.timeline_tree.delete(*self.timeline_tree.get_children())
        for row in sorted(self._filtered_timeline(), key=lambda item: str(_get(item, "observed_at", "")), reverse=True):
            observation_id = int(_get(row, "id"))
            self.timeline_tree.insert("", "end", iid=f"o:{observation_id}", values=(
                str(_get(row, "observed_at", "")), str(_get(row, "entity_type", "")), str(_get(row, "label", "")), str(_get(row, "source", "")), str(_get(row, "confidence", "")),
            ))
        self.evidence_tree.delete(*self.evidence_tree.get_children())
        self.left_evidence_tree.delete(*self.left_evidence_tree.get_children())
        for row in sorted(rows, key=lambda item: (str(_get(item, "severity", "")), str(_get(item, "label", "")))):
            evidence_id = int(_get(row, "id"))
            self.evidence_tree.insert("", "end", iid=f"e:{evidence_id}", values=(
                str(_get(row, "entity_type", "")), str(_get(row, "label", "")), str(_get(row, "source", "")), str(_get(row, "severity", "")), str(_get(row, "confidence", "")), str(_get(row, "evidence_digest", ""))[:18] + "…",
            ))
            self.left_evidence_tree.insert("", "end", iid=f"e:{evidence_id}", values=(
                str(_get(row, "entity_type", "")), str(_get(row, "label", "")),
            ))
        if hasattr(self, "evidence_count_var"):
            suffix = f" / {len(self._evidence)}" if len(rows) != len(self._evidence) else ""
            self.evidence_count_var.set(f"{len(rows)}{suffix} объектов")
        selected_iid = f"e:{self._selected_evidence_id}" if self._selected_evidence_id is not None else ""
        for tree in (self.evidence_tree, self.left_evidence_tree):
            if selected_iid and tree.exists(selected_iid):
                tree.selection_set(selected_iid)
        self.gap_tree.delete(*self.gap_tree.get_children())
        for gap in self._gaps:
            gap_id = int(_get(gap, "id"))
            self.gap_tree.insert("", "end", iid=f"g:{gap_id}", values=(str(_get(gap, "collector", "")), str(_get(gap, "source", "")), str(_get(gap, "reason", "")), str(_get(gap, "impact", ""))))
        self._populate_investigation()

    def _set_pipeline_stage(self, stage: str, text: str, state: str) -> None:
        if not hasattr(self, "stage_status_vars") or stage not in self.stage_status_vars:
            return
        colors = {
            "pending": COLORS["muted"],
            "running": COLORS["accent"],
            "done": "#5bc7a5",
            "warning": COLORS["warning"],
            "critical": COLORS["accent"],
        }
        backgrounds = {
            "pending": "#1a1a1a",
            "running": "#261b17",
            "done": "#17211e",
            "warning": "#252016",
            "critical": "#2a1b17",
        }
        self.stage_status_vars[stage].set(text)
        self.stage_status_labels[stage].configure(
            fg=colors.get(state, COLORS["muted"]),
            bg=backgrounds.get(state, "#1a1a1a"),
        )
        self.stage_cards[stage].configure(
            bg=backgrounds.get(state, "#1a1a1a"),
            highlightbackground=colors.get(state, "#303030") if state != "pending" else "#303030",
        )
        for child in self.stage_cards[stage].winfo_children():
            if isinstance(child, tk.Label) and child is not self.stage_status_labels[stage]:
                child.configure(bg=backgrounds.get(state, "#1a1a1a"))

    def _refresh_pipeline_summary(self) -> None:
        if self.current_case_id is None:
            return
        detections = [
            row
            for row in self._evidence.values()
            if str(_get(row, "entity_type", "")) in {"malware_detection", "alert"}
        ]
        avz_gaps = [
            gap
            for gap in self._gaps
            if "avz" in str(_get(gap, "collector", "")).casefold()
            or "avz" in str(_get(gap, "source", "")).casefold()
        ]
        try:
            runs = list(self.database.list_collection_runs(self.current_case_id))
        except Exception:
            runs = []
        try:
            artifacts = list(self.database.list_artifacts(self.current_case_id))
        except Exception:
            artifacts = []
        preserved = [
            item
            for item in artifacts
            if "preserv" in str(_get(item, "kind", "")).casefold()
            or "preserv" in str(_get(item, "name", "")).casefold()
        ]

        if detections:
            self._set_pipeline_stage("DETECT", f"ПОКАЗАНИЯ · {len(detections)}", "critical")
        elif avz_gaps:
            self._set_pipeline_stage("DETECT", "НЕПОЛНО · СМ. ПРОБЕЛЫ", "warning")
        elif runs:
            self._set_pipeline_stage("DETECT", "В ОБЛАСТИ НЕ НАЙДЕНО", "done")
        else:
            self._set_pipeline_stage("DETECT", "ОЖИДАЕТ", "pending")

        if preserved:
            self._set_pipeline_stage("PRESERVE", "КОПИЯ + SHA-256", "done")
        elif runs:
            self._set_pipeline_stage("PRESERVE", "НЕ СОХРАНЕНО", "warning")
        else:
            self._set_pipeline_stage("PRESERVE", "ОЖИДАЕТ", "pending")

        if self._evidence:
            self._set_pipeline_stage("INVESTIGATE", f"ОБЪЕКТОВ · {len(self._evidence)}", "done")
        else:
            self._set_pipeline_stage("INVESTIGATE", "ОЖИДАЕТ", "pending")

        findings = tuple(getattr(self._impact_assessment, "findings", ()) or ())
        if findings:
            self._set_pipeline_stage("IMPACT", f"СВЯЗАНО · {len(findings)}", "done")
        elif runs:
            self._set_pipeline_stage("IMPACT", "СВЯЗИ НЕ ДОКАЗАНЫ", "warning")
        else:
            self._set_pipeline_stage("IMPACT", "ОЖИДАЕТ", "pending")

    @staticmethod
    def _basis_label(value: str) -> str:
        return {
            "observed": "Наблюдение",
            "correlated": "Корреляция",
            "hypothesis": "Гипотеза",
            "high": "Наблюдение",
            "medium": "Корреляция",
            "low": "Гипотеза",
        }.get(str(value).casefold(), str(value))

    @staticmethod
    def _causal_basis(*values: Any) -> str:
        """Return a display basis only when every input is evidentially usable."""
        normalized = {str(value or "").casefold() for value in values}
        if not normalized or not normalized <= {
            "high",
            "medium",
            "observed",
            "correlated",
        }:
            return ""
        if normalized & {"medium", "correlated"}:
            return "Корреляция"
        return "Наблюдение"

    @staticmethod
    def _compact_chain_text(value: Any, limit: int = 48) -> str:
        text = " ".join(str(value or "").split())
        if len(text) <= limit:
            return text
        return f"{text[: limit - 1].rstrip()}…"

    @classmethod
    def _zone_origin(cls, item: Any) -> tuple[str, str] | None:
        """Read only explicit origin fields; a zone never identifies the exact channel."""
        properties = _get(item, "properties", {}) or {}
        content = str(properties.get("content", "") or "")
        fields: dict[str, str] = {}
        for line in content.splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip() and value.strip():
                fields[key.strip().casefold()] = value.strip()
        for field, caption in (("hosturl", "HostUrl"), ("referrerurl", "ReferrerUrl")):
            if fields.get(field):
                return cls._compact_chain_text(fields[field]), f"{caption} из Zone.Identifier"

        zone_value = properties.get("zone_id")
        if zone_value in (None, ""):
            zone_value = fields.get("zoneid")
        if zone_value in (None, ""):
            return None
        zone_id = str(zone_value).strip()
        zone_names = {
            "0": "Локальная машина",
            "1": "Локальная интрасеть",
            "2": "Доверенная зона",
            "3": "Зона Интернета",
            "4": "Ограниченная зона",
        }
        return (
            f"{zone_names.get(zone_id, 'Zone.Identifier')} (ZoneId={zone_id})",
            "метка зоны; точный канал не установлен",
        )

    @classmethod
    def _causal_chain_display(
        cls,
        evidence: list[Any],
        relations: list[Any],
        assessment: Any,
        entry_path: str = "",
    ) -> dict[str, str]:
        """Build source → seed → impact text without promoting hypotheses to facts."""
        by_key = {
            str(_get(item, "stable_key", "")): item
            for item in evidence
            if _get(item, "stable_key")
        }
        entry_keys = tuple(getattr(assessment, "entry_keys", ()) or ())
        entry_items = [by_key[key] for key in entry_keys if key in by_key]
        seed = next(
            (
                item
                for item in entry_items
                if str(_get(item, "entity_type", "")).casefold()
                in {"file", "module"}
            ),
            entry_items[0] if entry_items else None,
        )

        effective_path = str(
            getattr(assessment, "entry_path", "") or entry_path or ""
        )
        if seed is not None:
            file_label = cls._compact_chain_text(_get(seed, "label", "")) or "Не установлен"
            file_basis = cls._causal_basis(_get(seed, "confidence", ""))
            file_meta = (
                f"{file_basis} · файл-зерно"
                if file_basis
                else "Файл указан в кейсе · требует подтверждения"
            )
        elif effective_path:
            file_label = cls._compact_chain_text(Path(effective_path).name or effective_path)
            file_meta = "Задан в кейсе · показаний о файле нет"
        else:
            file_label = "Не установлен"
            file_meta = "Файл-зерно ещё не подтверждён"

        source_candidates: list[tuple[int, str, str]] = []
        incoming_provenance = {
            "present_on_removable_media": (0, "текущий USB/съёмный носитель; историческая доставка не доказана"),
            "reported_download_source": (0, "источник из Zone.Identifier"),
            "reported_delivery_source": (1, "связанный канал доставки"),
            "browser_downloaded": (0, "браузер загрузил файл"),
            "downloaded": (0, "загрузка файла"),
            "delivered": (1, "доставка файла"),
            "received_as": (1, "получение файла"),
            "extracted_to": (2, "извлечение файла"),
            "copied_to": (2, "копирование файла"),
            "created": (3, "процесс создал файл"),
            "written": (3, "процесс записал файл"),
        }
        outgoing_provenance = {
            "downloaded_from": (0, "источник загрузки"),
            "originated_from": (0, "источник происхождения"),
            "received_from": (1, "источник получения"),
            "delivered_via": (1, "канал доставки"),
            "extracted_from": (2, "исходный архив"),
            "copied_from": (2, "источник копирования"),
            "attached_to": (2, "исходное вложение"),
            "has_alternate_stream": (4, "Zone.Identifier"),
        }
        entry_key_set = set(entry_keys)
        for relation in relations:
            relation_type = str(_get(relation, "relation_type", "")).casefold()
            source_key = str(_get(relation, "source_key", ""))
            target_key = str(_get(relation, "target_key", ""))
            candidate: Any = None
            descriptor = ""
            priority = 99
            if target_key in entry_key_set and relation_type in incoming_provenance:
                candidate = by_key.get(source_key)
                priority, descriptor = incoming_provenance[relation_type]
            elif source_key in entry_key_set and relation_type in outgoing_provenance:
                candidate = by_key.get(target_key)
                priority, descriptor = outgoing_provenance[relation_type]
            if candidate is None:
                continue
            basis = cls._causal_basis(
                _get(relation, "confidence", ""),
                _get(candidate, "confidence", ""),
            )
            if not basis:
                continue
            if relation_type == "has_alternate_stream":
                origin = cls._zone_origin(candidate)
                if origin is None:
                    continue
                label, descriptor = origin
            else:
                label = cls._compact_chain_text(_get(candidate, "label", ""))
                if not label:
                    continue
            basis_rank = 0 if basis == "Наблюдение" else 1
            source_candidates.append(
                (priority * 10 + basis_rank, label, f"{basis} · {descriptor}")
            )

        if seed is not None:
            seed_basis = cls._causal_basis(_get(seed, "confidence", ""))
            if seed_basis:
                origin = cls._zone_origin(seed)
                if origin is not None:
                    label, descriptor = origin
                    basis_rank = 0 if seed_basis == "Наблюдение" else 1
                    source_candidates.append(
                        (50 + basis_rank, label, f"{seed_basis} · {descriptor}")
                    )

        if source_candidates:
            _, source_label, source_meta = min(source_candidates, key=lambda item: item[0])
        else:
            source_label = "Не установлен"
            source_meta = "Нет подтверждённой связи происхождения"

        findings = tuple(getattr(assessment, "findings", ()) or ())
        attributable = [
            finding
            for finding in findings
            if str(getattr(finding, "category", "")).casefold()
            not in {"entry", "source"}
            and str(getattr(finding, "basis", "")).casefold()
            in {"observed", "correlated"}
        ]
        process_count = sum(
            1
            for finding in attributable
            if str(getattr(finding, "category", "")).casefold() == "process"
        )
        other_count = len(attributable) - process_count
        if attributable:
            impact_parts = []
            if process_count:
                impact_parts.append(f"процессов: {process_count}")
            if other_count:
                impact_parts.append(f"объектов: {other_count}")
            impact_label = " · ".join(impact_parts)
            observed_count = sum(
                1
                for finding in attributable
                if str(getattr(finding, "basis", "")).casefold() == "observed"
            )
            impact_meta = (
                f"Наблюдений: {observed_count} · корреляций: "
                f"{len(attributable) - observed_count}"
            )
        else:
            impact_label = "Не установлено"
            impact_meta = (
                "Есть только гипотезы · в цепочку не включены"
                if findings
                else "Связанное воздействие ещё не выявлено"
            )

        return {
            "source": source_label,
            "source_meta": source_meta,
            "file": file_label,
            "file_meta": file_meta,
            "impact": impact_label,
            "impact_meta": impact_meta,
        }

    def _populate_investigation(self) -> None:
        if not hasattr(self, "entry_tree"):
            return
        for tree in (self.entry_tree, self.process_tree, self.impact_tree):
            tree.delete(*tree.get_children())
        assessment = self._impact_assessment
        chain = self._causal_chain_display(
            list(self._evidence.values()),
            self._relations,
            assessment,
            str(_get(self.current_case, "suspect_path", "")),
        )
        self.chain_source_var.set(chain["source"])
        self.chain_source_meta_var.set(chain["source_meta"])
        self.chain_file_var.set(chain["file"])
        self.chain_file_meta_var.set(chain["file_meta"])
        self.chain_impact_var.set(chain["impact"])
        self.chain_impact_meta_var.set(chain["impact_meta"])
        if assessment is None:
            self.investigation_summary_var.set("Цепочка воздействия недоступна")
            self.impact_limitations_var.set(
                "Не удалось построить консервативный граф по имеющимся показаниям."
            )
            return

        by_key = {
            str(_get(item, "stable_key", "")): item for item in self._evidence.values()
        }
        entry_keys = set(getattr(assessment, "entry_keys", ()) or ())
        seen_entry_rows: set[tuple[str, str, str]] = set()
        row_index = 0
        for key in entry_keys:
            item = by_key.get(str(key))
            if item is None:
                continue
            marker = (str(key), "точка входа", "high")
            seen_entry_rows.add(marker)
            self.entry_tree.insert(
                "",
                "end",
                iid=f"entry:{row_index}",
                values=(
                    "Наблюдение",
                    str(_get(item, "label", key)),
                    "точка входа",
                    "high",
                ),
            )
            row_index += 1

        entry_relations = {
            "has_alternate_stream",
            "has_signature_state",
            "executed_as",
            "detected_as",
            "referenced_by",
            "spawned",
            "reported_parent_of",
        }
        for relation in self._relations:
            relation_type = str(_get(relation, "relation_type", ""))
            source_key = str(_get(relation, "source_key", ""))
            target_key = str(_get(relation, "target_key", ""))
            if relation_type not in entry_relations or not (
                source_key in entry_keys or target_key in entry_keys
            ):
                continue
            other_key = target_key if source_key in entry_keys else source_key
            other = by_key.get(other_key)
            confidence = str(_get(relation, "confidence", "medium"))
            marker = (other_key, relation_type, confidence)
            if marker in seen_entry_rows:
                continue
            seen_entry_rows.add(marker)
            self.entry_tree.insert(
                "",
                "end",
                iid=f"entry:{row_index}",
                values=(
                    self._basis_label(confidence),
                    str(_get(other, "label", other_key)),
                    relation_type.replace("_", " "),
                    confidence,
                ),
            )
            row_index += 1

        affected_processes = tuple(getattr(assessment, "affected_processes", ()) or ())
        for index, finding in enumerate(affected_processes):
            self.process_tree.insert(
                "",
                "end",
                iid=f"process-impact:{index}",
                values=(
                    self._basis_label(str(getattr(finding, "basis", ""))),
                    str(getattr(finding, "label", "")),
                    str(getattr(finding, "confidence", "")),
                    " → ".join(getattr(finding, "relation_path", ()) or ()) or "прямое показание",
                ),
            )

        category_labels = {
            "file": "Файлы / модули",
            "persistence": "Закрепление",
            "network": "Сеть",
            "entry": "Точка входа",
        }
        affected = [
            finding
            for finding in (getattr(assessment, "findings", ()) or ())
            if str(getattr(finding, "category", "")) not in {"process", "entry"}
        ]
        for index, finding in enumerate(affected):
            category = str(getattr(finding, "category", ""))
            self.impact_tree.insert(
                "",
                "end",
                iid=f"impact:{index}",
                values=(
                    category_labels.get(category, category),
                    self._basis_label(str(getattr(finding, "basis", ""))),
                    str(getattr(finding, "label", "")),
                    str(getattr(finding, "confidence", "")),
                    " → ".join(getattr(finding, "relation_path", ()) or ()) or "прямое показание",
                ),
            )

        self.investigation_summary_var.set(
            f"Точек входа: {len(entry_keys)} · процессов: {len(affected_processes)} · "
            f"прочих затронутых объектов: {len(affected)}"
        )
        limitations = tuple(getattr(assessment, "limitations", ()) or ())
        gap_count = int(getattr(assessment, "coverage_gap_count", 0) or 0)
        if gap_count:
            self.impact_limitations_var.set(
                f"Ограничение: зафиксировано пробелов покрытия — {gap_count}; "
                "ненаблюдавшиеся действия восстановить невозможно."
            )
        elif limitations:
            self.impact_limitations_var.set(
                "Ограничение: выводы показывают доступные показания и связи, "
                "но не доказывают причинность или размер ущерба."
            )
        else:
            self.impact_limitations_var.set("Полнота зависит от доступной телеметрии.")

    def _graph_subset(self, rows: list[Any], limit: int) -> list[Any]:
        """Keep a large case responsive while preserving seed/risky/connected nodes."""
        if len(rows) <= limit:
            return rows
        row_by_id = {int(_get(row, "id")): row for row in rows}
        suspect_path = os.path.normcase(str(_get(self.current_case, "suspect_path", "")))
        seed_ids = {
            row_id for row_id, row in row_by_id.items()
            if (_get(row, "properties", {}) or {}).get("is_seed")
            or str(_get(row, "stable_key", "")).startswith("file:seed")
            or str(_get(row, "source", "")) == "filesystem seed"
            or (
                suspect_path
                and os.path.normcase(str((_get(row, "properties", {}) or {}).get("path", ""))) == suspect_path
            )
        }
        priority_ids = {
            row_id for row_id, row in row_by_id.items()
            if str(_get(row, "severity", "")) in {"critical", "high"}
        } | seed_ids
        for relation in self._relations:
            source = _get(relation, "source_evidence_id")
            target = _get(relation, "target_evidence_id")
            if source in priority_ids and target in row_by_id:
                priority_ids.add(int(target))
            if target in priority_ids and source in row_by_id:
                priority_ids.add(int(source))
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ordered = sorted(
            rows,
            key=lambda row: (
                0 if int(_get(row, "id")) in seed_ids else 1,
                0 if int(_get(row, "id")) in priority_ids else 1,
                rank.get(str(_get(row, "severity", "info")), 5),
                0 if str(_get(row, "confidence", "")) == "high" else 1,
                str(_get(row, "observed_at", "")),
            ),
        )
        return ordered[:limit]

    def _select_evidence(self, evidence_id: int) -> None:
        row = self._evidence.get(int(evidence_id))
        if row is None:
            return
        self._selected_evidence_id = int(evidence_id)
        self._show_evidence(row)
        self._apply_filters()

    def _table_selected(self, event: tk.Event) -> None:
        tree = event.widget
        selected = tree.selection()
        if selected and selected[0].startswith("e:"):
            self._select_evidence(int(selected[0].split(":", 1)[1]))
        elif selected and selected[0].startswith("o:"):
            self._select_observation(int(selected[0].split(":", 1)[1]))

    def _select_observation(self, observation_id: int) -> None:
        row = next((item for item in self._timeline if int(_get(item, "id")) == observation_id), None)
        if row is None:
            return
        evidence_id = int(_get(row, "evidence_id"))
        self._selected_evidence_id = evidence_id
        self._show_evidence(row, relation_evidence_id=evidence_id, observation=True)
        graph_rows = self._filtered_evidence()
        graph_subset = self._graph_subset(graph_rows, 180)
        graph_ids = {int(_get(item, "id")) for item in graph_subset}
        graph_relations = [
            relation for relation in self._relations
            if _get(relation, "source_evidence_id") in graph_ids
            and _get(relation, "target_evidence_id") in graph_ids
        ]
        self.graph.render(graph_subset, graph_relations, evidence_id)

    def _gap_selected(self, event: tk.Event) -> None:
        selected = event.widget.selection()
        if not selected:
            return
        gap_id = int(selected[0].split(":", 1)[1])
        gap = next((item for item in self._gaps if int(_get(item, "id")) == gap_id), None)
        if gap:
            self._show_gap(gap)

    def _show_case_overview(self) -> None:
        case = self.current_case
        if case is None:
            self._show_inspector_message("Кейс не выбран.")
            return
        rows = [
            ("Статус", _get(case, "status", "open")),
            ("Узел", _get(case, "hostname", "")),
            ("Создан UTC", _get(case, "created_at", "")),
            ("Обновлён UTC", _get(case, "updated_at", "")),
            ("Файл-зерно", _get(case, "suspect_path", "не указан")),
            ("Наблюдения", len(self._timeline)),
            ("Объекты", len(self._evidence)),
            ("Связи", len(self._relations)),
            ("Пробелы", len(self._gaps)),
            (
                "Оговорка",
                "Отсутствие записи не означает отсутствие действия; полнота зависит от доступной телеметрии.",
            ),
        ]
        self._set_properties(str(_get(case, "title", "Кейс")), "СВОДКА ПО КЕЙСУ", rows)

    def _show_evidence(self, row: Any, relation_evidence_id: int | None = None, observation: bool = False) -> None:
        severity = str(_get(row, "severity", "info"))
        related: list[str] = []
        row_id = int(relation_evidence_id if relation_evidence_id is not None else _get(row, "id"))
        for relation in self._relations:
            source = _get(relation, "source_evidence_id"); target = _get(relation, "target_evidence_id")
            if source == row_id or target == row_id:
                other_id = target if source == row_id else source
                other = self._evidence.get(int(other_id)) if other_id is not None else None
                direction = "→" if source == row_id else "←"
                related.append(
                    f"{direction} {_get(relation, 'relation_type', 'связь')} · "
                    f"{_get(other, 'label', other_id)} [{_get(relation, 'confidence', '')}] · "
                    f"{_get(relation, 'rationale', '')}"
                )
        rows: list[tuple[str, Any]] = [
            ("Тип", _get(row, "entity_type", "")),
            ("Обнаружено UTC", _get(row, "observed_at", "")),
            ("Собрано UTC", _get(row, "collected_at", _get(row, "last_seen_at", ""))),
            ("Запуск", _get(row, "run_id", "")),
            ("Источник", _get(row, "source", "")),
            ("Ссылка", _get(row, "source_ref", "")),
            ("Уверенность", _get(row, "confidence", "")),
            ("Риск", severity),
        ]
        rows.extend(self._flatten_properties(_get(row, "properties", {}), "свойство"))
        if related:
            rows.extend((f"связь {index}", value) for index, value in enumerate(related, 1))
        else:
            rows.append(("Связи", "Связи не построены"))
        rows.append(("Digest", _get(row, "evidence_digest", "")))
        rows.extend(self._flatten_properties(_get(row, "raw", {}), "исходное"))
        meta = f"{'НАБЛЮДЕНИЕ' if observation else 'ДОКАЗАТЕЛЬСТВО'} · {severity.upper()}"
        self._set_properties(str(_get(row, "label", "Доказательство")), meta, rows)

    def _show_gap(self, gap: Any) -> None:
        rows = [
            ("Коллектор", _get(gap, "collector", "")),
            ("Источник", _get(gap, "source", "")),
            ("Причина", _get(gap, "reason", "")),
            ("Влияние", _get(gap, "impact", "")),
            ("Рекомендация", _get(gap, "recommendation", "")),
            ("Записано UTC", _get(gap, "created_at", "")),
        ]
        self._set_properties(str(_get(gap, "source", "Пробел телеметрии")), "ПРОБЕЛ ПОКРЫТИЯ", rows)

    def _show_inspector_message(self, message: str) -> None:
        self._set_properties("Свойства", "НЕТ ВЫБОРА", [("Статус", message)])

    @staticmethod
    def _flatten_properties(value: Any, prefix: str) -> list[tuple[str, Any]]:
        if isinstance(value, Mapping):
            rows: list[tuple[str, Any]] = []
            for key, nested in value.items():
                name = f"{prefix}.{key}"
                if isinstance(nested, Mapping):
                    rows.extend(NodeTraceApp._flatten_properties(nested, name))
                else:
                    rows.append((name, nested))
            return rows or [(prefix, "—")]
        return [(prefix, value)]

    @staticmethod
    def _property_value(value: Any) -> str:
        if value is None or value == "":
            return "—"
        if isinstance(value, (Mapping, list, tuple, set)):
            return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        return str(value)

    def _set_properties(self, title: str, meta: str, rows: list[tuple[str, Any]]) -> None:
        compact_title = title if len(title) <= 30 else f"{title[:29]}…"
        self.inspector_title_var.set(compact_title or "Свойства")
        self.inspector_meta_var.set(meta)
        self.inspector.delete(*self.inspector.get_children())
        for index, (name, value) in enumerate(rows):
            self.inspector.insert(
                "",
                "end",
                iid=f"property:{index}",
                values=(str(name), self._property_value(value)),
            )

    def _copy_property_value(self, _event: tk.Event[Any] | None = None) -> None:
        selected = self.inspector.selection()
        if not selected:
            return
        values = self.inspector.item(selected[0], "values")
        if len(values) < 2:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(str(values[1]))
        self.status_var.set("Значение свойства скопировано")

    def _set_inspector(self, chunks: list[tuple[str, str]]) -> None:
        rows: list[tuple[str, str]] = []
        for text, tag in chunks:
            for line in (line.strip() for line in text.splitlines()):
                if line:
                    rows.append((tag or "Деталь", line))
        self._set_properties("Свойства", "ДЕТАЛИ", rows)

    def _target_case_properties(self, **values: Any) -> dict[str, Any]:
        properties: dict[str, Any] = {
            "target_mode": self.target_mode,
            "offline_root": str(self.offline_root) if self.offline_root is not None else "",
            "winpe": self.winpe,
            "read_only": True,
            "live_host_telemetry_collected": self.target_mode == "live",
        }
        properties.update(values)
        return properties

    def _target_hostname(self) -> str:
        if self.target_mode == "offline":
            return "offline-target"
        return socket.gethostname()

    def _case_matches_target(self, case: Any) -> bool:
        properties = _get(case, "properties", {}) or {}
        case_mode = str(properties.get("target_mode") or "live").strip().casefold()
        if case_mode != self.target_mode:
            return False
        if self.target_mode != "offline":
            return True
        case_root = str(properties.get("offline_root") or "").strip()
        if not case_root or self.offline_root is None:
            return False
        return os.path.normcase(str(Path(case_root).expanduser().absolute())) == os.path.normcase(
            str(self.offline_root)
        )

    def _new_case(self) -> None:
        dialog = NewCaseDialog(self.root)
        self.root.wait_window(dialog)
        if not dialog.result:
            return
        data = dialog.result
        case = self.database.create_case(
            data["title"],
            suspect_path=data["suspect_path"],
            description=data["description"],
            hostname=self._target_hostname(),
            properties=self._target_case_properties(lookback_days=data["lookback_days"]),
        )
        self.database.log_action(case.id, "case_created", {"suspect_path": data["suspect_path"], "lookback_days": data["lookback_days"]})
        self._refresh_cases(select_id=case.id)
        self.status_var.set("Кейс создан. Анализ запускается автоматически…")
        self.root.after(120, self._start_collection)

    def _auto_startup_investigation(self) -> None:
        if self._closing or (self._worker and self._worker.is_alive()):
            return
        if self.current_case_id is None or not self._case_matches_target(self.current_case):
            host = self._target_hostname()
            if self.target_mode == "offline":
                assert self.offline_root is not None
                title = f"Офлайн-обследование {self.offline_root}"
                description = (
                    "Кейс создан автоматически для смонтированной, не запущенной Windows-системы. "
                    f"Целевой корень: {self.offline_root}. "
                    "Данные WinPE-хоста не используются как процессы или сеть целевой ОС; "
                    "исследуются сохранённые EVTX, Prefetch и выбранные файловые артефакты."
                )
            else:
                title = f"Автоматическое обследование {host}"
                description = (
                    "Кейс создан автоматически при запуске NodeTrace IR. "
                    "Сначала выполняется системный аналитический отчёт AVZ, "
                    "затем встроенное live-response расследование."
                )
            case = self.database.create_case(
                title,
                description=description,
                hostname=host,
                properties=self._target_case_properties(lookback_days=30, auto_started=True),
            )
            self.database.log_action(
                case.id,
                "automatic_case_created",
                {
                    "reason": "application_start",
                    "suspect_path": "",
                    "target_mode": self.target_mode,
                    "offline_root": str(self.offline_root) if self.offline_root is not None else "",
                },
                actor="system",
            )
            self._refresh_cases(select_id=case.id)
        try:
            existing_runs = self.database.list_collection_runs(int(self.current_case_id))
        except Exception:
            existing_runs = []
        if not existing_runs:
            self.status_var.set(
                "Автоматический офлайн-анализ смонтированной Windows запускается…"
                if self.target_mode == "offline"
                else "Автоматический анализ узла запускается…"
            )
            self._start_collection()

    def _create_demo(self) -> None:
        case = create_demo_case(self.database)
        self._refresh_cases(select_id=int(_get(case, "id")))
        self.status_var.set("Открыт синтетический демо-кейс — данные явно помечены как DEMO.")

    def _start_collection(self) -> None:
        if self.current_case_id is None:
            messagebox.showinfo("Кейс", "Сначала создайте или выберите кейс.", parent=self.root)
            return
        if self._worker and self._worker.is_alive():
            return
        suspect_path = str(_get(self.current_case, "suspect_path", ""))
        if suspect_path and not Path(suspect_path).exists():
            self.status_var.set(
                "Файл-зерно недоступен; анализ остальных источников продолжается с явным пробелом."
            )
        if not is_admin():
            self.status_var.set(
                "Запуск без прав администратора: недоступные источники будут отмечены в «Пробелах»."
            )
        lookback = int((_get(self.current_case, "properties", {}) or {}).get("lookback_days", 7))
        self._cancel_event = Event()
        self._set_busy(True)
        case_id = self.current_case_id
        artifact_root = self.data_dir / "case_artifacts"

        def worker() -> None:
            try:
                avz_executable = os.environ.get("NODETRACE_AVZ_EXE") or None
                pipeline = IncidentPipeline(
                    self.database,
                    artifact_root=artifact_root,
                    avz_executable=avz_executable,
                )
                summary = pipeline.run(
                    case_id,
                    suspect_path,
                    lookback_days=lookback,
                    cancel_event=self._cancel_event,
                    progress_callback=lambda event: self._events.put({"kind": "progress", **event}),
                    options={
                        "admin": is_admin(),
                        "collector_version": __version__,
                        "read_only": True,
                        "automatic_start": True,
                        "target_mode": self.target_mode,
                        "offline_root": str(self.offline_root) if self.offline_root is not None else "",
                        "winpe": self.winpe,
                        "avz_distribution": os.environ.get("NODETRACE_AVZ_DISTRIBUTION", ""),
                        "avz_archive": os.environ.get("NODETRACE_AVZ_ARCHIVE", ""),
                        "avz_base_archive": os.environ.get("NODETRACE_AVZ_BASE_ARCHIVE", ""),
                    },
                )
                self._events.put({"kind": "collection_done", "case_id": case_id, "status": summary.status})
            except Exception as exc:
                self._events.put({"kind": "error", "title": "Ошибка анализа", "message": f"{type(exc).__name__}: {exc}"})
        self._launch_worker(worker, "NodeTraceInvestigation")

    def _cancel_collection(self) -> None:
        if self._cancel_event:
            self._cancel_event.set()
            self.status_var.set("Остановка после завершения текущей стадии…")
            self.cancel_button.configure(state="disabled")

    def _export_case(self) -> None:
        if self.current_case_id is None or (self._worker and self._worker.is_alive()):
            return
        case_title = str(_get(self.current_case, "title", f"case_{self.current_case_id}"))
        path = filedialog.asksaveasfilename(parent=self.root, title="Сохранить проверяемый набор кейса", defaultextension=".zip", filetypes=(("ZIP archive", "*.zip"),), initialfile=f"NodeTraceIR_{case_title[:45]}.zip")
        if not path:
            return
        case_id = self.current_case_id
        self._set_busy(True, indeterminate=True)

        def worker() -> None:
            try:
                result = CaseExporter(self.database).export(case_id, path)
                self._events.put({"kind": "export_done", "path": str(result.zip_path), "sha256": result.sha256, "manifest_sha256": result.manifest_sha256})
            except Exception as exc:
                self._events.put({"kind": "error", "title": "Ошибка экспорта", "message": f"{type(exc).__name__}: {exc}"})
        self._launch_worker(worker, "NodeTraceExport")

    def _launch_worker(self, target: Any, name: str) -> None:
        self._worker = Thread(target=target, name=name, daemon=False)
        self._worker.start()

    def _poll_events(self) -> None:
        if self._closing:
            return
        try:
            while True:
                event = self._events.get_nowait()
                kind = event.get("kind")
                if kind == "progress":
                    stage = str(event.get("stage", ""))
                    phase = str(event.get("phase", ""))
                    state = str(event.get("status", "running"))
                    if stage:
                        visual_state = (
                            "running"
                            if phase == "stage_started" or state == "running"
                            else "done"
                            if state == "completed"
                            else "warning"
                            if state in {"partial", "skipped"}
                            else "critical"
                        )
                        self._set_pipeline_stage(
                            stage,
                            "ВЫПОЛНЯЕТСЯ" if visual_state == "running" else state.upper(),
                            visual_state,
                        )
                    total = max(1, int(event.get("total", event.get("total_stages", 1))))
                    completed = int(
                        event.get(
                            "completed",
                            max(0, int(event.get("stage_index", 1)) - (1 if phase == "stage_started" else 0)),
                        )
                    )
                    self.progress.configure(mode="determinate", value=completed / total * 100)
                    self.status_var.set(str(event.get("message", "Анализ…")))
                elif kind == "collection_done":
                    self._set_busy(False)
                    self._refresh_cases(select_id=int(event["case_id"]))
                    self.status_var.set(
                        f"Анализ завершён: {event.get('status')}. "
                        "Откройте «Расследование»: как попало, процессы и что затронуто."
                    )
                    if self.auto_export:
                        self._start_automatic_export(int(event["case_id"]))
                elif kind == "export_done":
                    self._set_busy(False)
                    self.status_var.set(f"Экспорт готов: {event['path']}")
                    messagebox.showinfo("Экспорт завершён", f"Набор кейса:\n{event['path']}\n\nSHA-256 ZIP:\n{event['sha256']}\n\nManifest SHA-256:\n{event['manifest_sha256']}", parent=self.root)
                elif kind == "automatic_export_done":
                    self._set_busy(False)
                    report_path = str(event.get("report_path") or "")
                    suffix = f"; HTML: {report_path}" if report_path else ""
                    self.status_var.set(
                        f"Автоэкспорт завершён: {event['path']}{suffix}"
                    )
                elif kind == "error":
                    self._set_busy(False)
                    self.status_var.set(str(event.get("message", "Ошибка")))
                    messagebox.showerror(str(event.get("title", "Ошибка")), str(event.get("message", "")), parent=self.root)
        except queue.Empty:
            pass
        if not self._closing:
            self.root.after(120, self._poll_events)

    def _start_automatic_export(self, case_id: int) -> None:
        """Write a verified ZIP and convenient HTML/SVG copies in WinPE mode."""

        exports = self.data_dir / "exports"
        exports.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = exports / f"NodeTraceIR_case-{case_id}_{stamp}.zip"
        ordinal = 1
        while destination.exists():
            destination = exports / f"NodeTraceIR_case-{case_id}_{stamp}_{ordinal}.zip"
            ordinal += 1
        self._set_busy(True, indeterminate=True)
        self.status_var.set("Формируется проверяемый ZIP и автономный HTML-отчёт…")

        def worker() -> None:
            try:
                result = CaseExporter(self.database).export(case_id, destination)
                view = destination.with_suffix("")
                view.mkdir(parents=False, exist_ok=False)
                report_path = ""
                with ZipFile(result.zip_path, "r") as archive:
                    for member, name in (
                        ("NodeTraceIR_Case/report.html", "report.html"),
                        ("NodeTraceIR_Case/graph.svg", "graph.svg"),
                        ("NodeTraceIR_Case/impact.json", "impact.json"),
                        ("NodeTraceIR_Case/SHA256SUMS.txt", "SHA256SUMS.txt"),
                    ):
                        content = archive.read(member)
                        target = view / name
                        with target.open("xb") as output:
                            output.write(content)
                        if name == "report.html":
                            report_path = str(target)
                self._events.put(
                    {
                        "kind": "automatic_export_done",
                        "path": str(result.zip_path),
                        "report_path": report_path,
                        "sha256": result.sha256,
                        "manifest_sha256": result.manifest_sha256,
                    }
                )
            except Exception as exc:
                self._events.put(
                    {
                        "kind": "error",
                        "title": "Ошибка автоэкспорта",
                        "message": f"{type(exc).__name__}: {exc}",
                    }
                )

        self._launch_worker(worker, "NodeTraceAutomaticExport")

    def _on_close(self) -> None:
        if self._closing:
            return
        self._closing = True
        if self._cancel_event is not None:
            self._cancel_event.set()
        if self._worker is not None and self._worker.is_alive():
            self.status_var.set(
                "Завершение текущей операции перед закрытием…"
            )
            self.cancel_button.configure(state="disabled")
        self._await_worker_shutdown()

    def _await_worker_shutdown(self) -> None:
        worker = self._worker
        if worker is not None and worker.is_alive():
            worker.join(timeout=0.05)
            if worker.is_alive():
                self.root.after(50, self._await_worker_shutdown)
                return
        self.database.close()
        self.root.destroy()

    def _set_busy(self, busy: bool, indeterminate: bool = False) -> None:
        self.new_button.configure(state="disabled" if busy else "normal")
        self.export_button.configure(state="disabled" if busy else "normal")
        self.cancel_button.configure(state="normal" if busy and not indeterminate else "disabled")
        if busy and indeterminate:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
        elif not busy:
            self.progress.stop(); self.progress.configure(mode="determinate", value=0)

    def _refresh_current(self) -> None:
        if self.current_case_id is not None:
            self._load_case(self.current_case_id)
            self.status_var.set("Данные кейса обновлены.")
        else:
            self._refresh_cases(select_first=True)

def smoke_test() -> int:
    with tempfile.TemporaryDirectory(prefix="nodetrace_ir_smoke_") as temporary:
        root = Path(temporary)
        database = Database(root / "smoke.sqlite3")
        case = create_demo_case(database)
        result = CaseExporter(database).export(int(_get(case, "id")), root / "smoke.zip")
        if not result.zip_path.exists() or result.zip_path.stat().st_size == 0:
            raise RuntimeError("smoke export was not created")
        print(json.dumps({"status": "ok", "version": __version__, "case_id": _get(case, "id"), "evidence": len(database.list_evidence(int(_get(case, "id")))), "observations": len(database.list_timeline(int(_get(case, "id")))), "relations": len(database.list_relations(int(_get(case, "id")))), "export_sha256": result.sha256}, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NodeTrace IR — local Windows incident-response graph")
    parser.add_argument("--data-dir", type=Path, help="Local case storage directory (recommended: trusted external drive)")
    parser.add_argument(
        "--winpe",
        action="store_true",
        help="Run in WinPE mode against a mounted offline Windows target",
    )
    parser.add_argument(
        "--offline-root",
        type=Path,
        help="Mounted affected Windows volume root, for example D:\\",
    )
    parser.add_argument("--demo", action="store_true", help="Create a synthetic demo case before opening the GUI")
    parser.add_argument("--create-demo-only", action="store_true", help="Create demo case and exit")
    parser.add_argument("--smoke-test", action="store_true", help="Run a self-contained database/export check and exit")
    parser.add_argument("--export-case", type=int, metavar="ID", help="Export an existing case and exit")
    parser.add_argument("--output", type=Path, help="Output ZIP path for --export-case")
    parser.add_argument("--scan-case", type=int, metavar="ID", help="Run the full detector-first pipeline for an existing case and exit")
    parser.add_argument("--lookback", type=int, default=7, help="Lookback days for --scan-case")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.winpe and args.data_dir is None:
        parser.error("--winpe requires an explicit writable --data-dir")
    if args.winpe and args.offline_root is None:
        parser.error("--winpe requires --offline-root for the mounted affected Windows volume")

    target_mode = "offline" if args.winpe or args.offline_root is not None else "live"
    offline_root: Path | None = None
    if target_mode == "offline":
        if args.offline_root is None:
            parser.error("offline target mode requires --offline-root")
        try:
            offline_root = validate_offline_root(args.offline_root)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))

    if args.smoke_test and target_mode == "live":
        return smoke_test()
    root: tk.Tk | None = None
    data_dir = args.data_dir if args.data_dir is not None else default_data_dir()
    if offline_root is not None and is_path_within(data_dir, offline_root):
        parser.error(
            "--data-dir must be outside --offline-root so NodeTrace IR never writes to the target volume"
        )
    try:
        data_dir = ensure_writable_data_dir(data_dir)
    except OSError as exc:
        parser.error(f"--data-dir is not writable: {exc}")
    if args.smoke_test:
        return smoke_test()
    database = Database(data_dir / "nodetrace_ir.sqlite3")
    if args.create_demo_only:
        case = create_demo_case(database)
        print(int(_get(case, "id")))
        return 0
    if args.export_case is not None:
        destination = args.output or (Path.cwd() / f"NodeTraceIR_case_{args.export_case}.zip")
        result = CaseExporter(database).export(args.export_case, destination)
        print(json.dumps({"path": str(result.zip_path), "sha256": result.sha256, "manifest_sha256": result.manifest_sha256}, ensure_ascii=False))
        return 0
    if args.scan_case is not None:
        case = database.get_case(args.scan_case)
        if case is None:
            raise SystemExit(f"Case {args.scan_case} not found")
        summary = IncidentPipeline(
            database,
            artifact_root=data_dir / "case_artifacts",
            avz_executable=os.environ.get("NODETRACE_AVZ_EXE") or None,
        ).run(
            args.scan_case,
            str(_get(case, "suspect_path", "")),
            lookback_days=max(1, args.lookback),
            options={
                "admin": is_admin(),
                "read_only": True,
                "automatic_start": True,
                "target_mode": target_mode,
                "offline_root": str(offline_root) if offline_root is not None else "",
                "winpe": bool(args.winpe),
            },
        )
        print(json.dumps(summary.as_dict(), ensure_ascii=False, default=str))
        return 0 if summary.status in {"completed", "partial"} else 2
    if root is None:
        root = tk.Tk()
    else:
        root.deiconify()
    app = NodeTraceApp(
        root,
        data_dir,
        target_mode=target_mode,
        offline_root=offline_root,
        winpe=bool(args.winpe),
    )
    if args.demo:
        case = create_demo_case(app.database)
        app._refresh_cases(select_id=int(_get(case, "id")))
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
