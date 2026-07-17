from __future__ import annotations

from collections import defaultdict, deque
import json
import math
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable

from .presentation import entity_group


CANVAS_BG = "#191919"
GRID_DOT = "#242424"
EDGE_COLORS = {
    "high": "#494949",
    "medium": "#3b3b3b",
    "low": "#303030",
}
ACCENT = "#ff5b35"

# Flowsint-like muted entity colours. Colour is deliberately secondary to
# topology: nodes stay 6-10 px wide and selected/important entities get the
# strong orange ring.
NODE_COLORS = {
    "file": "#aeb89e",
    "process": "#72b8a4",
    "user": "#9b91b4",
    "host": "#83a9b5",
    "source": "#c79a68",
    "registry": "#b8a66f",
    "service": "#b8a66f",
    "scheduled_task": "#b8a66f",
    "startup": "#b8a66f",
    "persistence": "#b8a66f",
    "ip": "#62acd0",
    "domain": "#72b8a4",
    "connection": "#62acd0",
    "network": "#62acd0",
    "event": "#8998a6",
    "alert": "#db7359",
    "prefetch": "#7cb2aa",
    "artifact": "#8fa6a2",
}


def _value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _coerce_id(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class EvidenceGraph(ttk.Frame):
    """Fast, dependency-free evidence graph with a compact investigation UI."""

    MIN_SCALE = 0.28
    MAX_SCALE = 2.40

    def __init__(self, master: tk.Misc, on_select: Callable[[int], None] | None = None) -> None:
        super().__init__(master, style="Panel.TFrame")
        self.on_select = on_select
        self.canvas = tk.Canvas(
            self,
            bg=CANVAS_BG,
            highlightthickness=0,
            cursor="arrow",
            takefocus=True,
        )
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self._item_to_id: dict[int, int] = {}
        self._node_items: dict[int, tuple[int, ...]] = {}
        self._nodes: dict[int, Any] = {}
        self._edges: list[tuple[int, int, str, str]] = []
        self._adjacency: dict[int, set[int]] = defaultdict(set)
        self._model_positions: dict[int, tuple[float, float]] = {}
        self._node_levels: dict[int, int] = {}
        self._root_id: int | None = None
        self._selected_id: int | None = None
        self._graph_signature: tuple[Any, ...] | None = None

        self._scale = 1.0
        self._origin = (450.0, 280.0)
        self._pan_last: tuple[int, int] | None = None
        self._layout_rotation = -math.pi / 2
        self._last_size = (0, 0)
        self._redraw_job: str | None = None
        self._grid_visible = True

        self._build_toolbar()
        self._bind_navigation()
        self._draw_grid()
        self._draw_empty()

    # ------------------------------------------------------------------ UI

    def _build_toolbar(self) -> None:
        toolbar_bg = "#202020"
        border = "#343434"

        self._layout_toolbar = tk.Frame(
            self,
            bg=toolbar_bg,
            highlightbackground=border,
            highlightthickness=1,
            bd=0,
        )
        self._toolbar_button(self._layout_toolbar, "↻", self.layout, width=3).pack(side="left")
        self._toolbar_button(self._layout_toolbar, "⌂", self.fit, width=3).pack(side="left")
        self._layout_toolbar.place(x=16, y=16)

        self._view_toolbar = tk.Frame(
            self,
            bg=toolbar_bg,
            highlightbackground=border,
            highlightthickness=1,
            bd=0,
        )
        self._toolbar_button(self._view_toolbar, "−", self.zoom_out, width=3).pack(side="left")
        self._zoom_label = self._toolbar_button(
            self._view_toolbar,
            "100%",
            self.reset_view,
            width=5,
            font=("Segoe UI", 8, "bold"),
        )
        self._zoom_label.pack(side="left")
        self._toolbar_button(self._view_toolbar, "+", self.zoom_in, width=3).pack(side="left")
        self._grid_button = self._toolbar_button(
            self._view_toolbar,
            "⌗",
            self.toggle_grid,
            width=3,
        )
        self._grid_button.pack(side="left")
        self._view_toolbar.place(relx=1.0, x=-16, y=16, anchor="ne")

    @staticmethod
    def _toolbar_button(
        parent: tk.Misc,
        text: str,
        command: Callable[[], None],
        *,
        width: int,
        font: tuple[str, int] | tuple[str, int, str] = ("Segoe UI Symbol", 11),
    ) -> tk.Button:
        button = tk.Button(
            parent,
            text=text,
            command=command,
            width=width,
            height=1,
            bg="#202020",
            fg="#b8b8b8",
            activebackground="#2a2a2a",
            activeforeground="#f1f1f1",
            disabledforeground="#666666",
            relief="flat",
            bd=0,
            highlightthickness=0,
            padx=1,
            pady=5,
            font=font,
            takefocus=False,
            cursor="hand2",
        )
        button.bind("<Enter>", lambda _event: button.configure(bg="#292929"))
        button.bind("<Leave>", lambda _event: button.configure(bg="#202020"))
        return button

    def _bind_navigation(self) -> None:
        self.canvas.bind("<Configure>", self._on_configure)
        self.canvas.bind("<Button-1>", self._click)
        self.canvas.bind("<Double-Button-1>", lambda _event: self.fit())

        for button in (2, 3):
            self.canvas.bind(f"<ButtonPress-{button}>", self._pan_begin)
            self.canvas.bind(f"<B{button}-Motion>", self._pan_move)
            self.canvas.bind(f"<ButtonRelease-{button}>", self._pan_end)
        self.canvas.bind("<Shift-ButtonPress-1>", self._pan_begin)
        self.canvas.bind("<Shift-B1-Motion>", self._pan_move)
        self.canvas.bind("<Shift-ButtonRelease-1>", self._pan_end)

        self.canvas.bind("<MouseWheel>", self._wheel)
        self.canvas.bind("<Button-4>", self._wheel)
        self.canvas.bind("<Button-5>", self._wheel)
        self.canvas.bind("<Key-plus>", lambda _event: self.zoom_in())
        self.canvas.bind("<Key-equal>", lambda _event: self.zoom_in())
        self.canvas.bind("<Key-minus>", lambda _event: self.zoom_out())
        self.canvas.bind("<Key-0>", lambda _event: self.reset_view())
        self.canvas.bind("<Key-f>", lambda _event: self.fit())
        self.canvas.bind("<Key-r>", lambda _event: self.layout())
        self.canvas.bind("<Enter>", lambda _event: self.canvas.focus_set())
        self.canvas.tag_bind("node", "<Enter>", lambda _event: self.canvas.configure(cursor="hand2"))
        self.canvas.tag_bind("node", "<Leave>", lambda _event: self.canvas.configure(cursor="arrow"))

    def _draw_grid(self) -> None:
        self.canvas.delete("grid")
        if not self._grid_visible:
            return
        width = max(self.canvas.winfo_width(), 2)
        height = max(self.canvas.winfo_height(), 2)
        spacing = 36
        offset = spacing // 2
        for x in range(offset, width, spacing):
            for y in range(offset, height, spacing):
                self.canvas.create_oval(
                    x,
                    y,
                    x + 1,
                    y + 1,
                    fill=GRID_DOT,
                    outline="",
                    tags=("grid",),
                )
        self.canvas.tag_lower("grid")

    def toggle_grid(self) -> None:
        self._grid_visible = not self._grid_visible
        self._grid_button.configure(fg="#d0d0d0" if self._grid_visible else "#666666")
        self._draw_grid()

    def _draw_empty(self) -> None:
        self.canvas.delete("world")
        self.canvas.delete("empty")
        width = max(self.canvas.winfo_width(), 900)
        height = max(self.canvas.winfo_height(), 560)
        cx, cy = width / 2, height / 2
        self.canvas.create_oval(
            cx - 4,
            cy - 4,
            cx + 4,
            cy + 4,
            fill=ACCENT,
            outline="",
            tags=("empty",),
        )
        self.canvas.create_text(
            cx,
            cy + 28,
            text="Выберите кейс, чтобы построить граф расследования",
            fill="#b2b2b2",
            font=("Segoe UI", 11, "bold"),
            tags=("empty",),
        )
        self.canvas.create_text(
            cx,
            cy + 52,
            text="Колесо — масштаб · средняя или правая кнопка — перемещение",
            fill="#646464",
            font=("Segoe UI", 9),
            tags=("empty",),
        )
        self.canvas.tag_raise("empty")

    def _on_configure(self, event: tk.Event) -> None:
        old_width, old_height = self._last_size
        new_width, new_height = max(1, event.width), max(1, event.height)
        self._last_size = (new_width, new_height)

        if self._model_positions:
            if old_width > 1 and old_height > 1:
                dx = (new_width - old_width) / 2
                dy = (new_height - old_height) / 2
                if dx or dy:
                    self.canvas.move("world", dx, dy)
                    self._origin = (self._origin[0] + dx, self._origin[1] + dy)
            else:
                # The first idle callback can run while Tk still reports a
                # provisional 1x1 canvas. Re-fit on the first real Configure so
                # the root is centred in the actual viewport, not at (120, 90).
                self._origin = (new_width / 2, new_height / 2)
                self.fit()
        elif not self._model_positions:
            cx, cy = new_width / 2, new_height / 2
            empty_items = self.canvas.find_withtag("empty")
            if len(empty_items) >= 3:
                self.canvas.coords(empty_items[0], cx - 4, cy - 4, cx + 4, cy + 4)
                self.canvas.coords(empty_items[1], cx, cy + 28)
                self.canvas.coords(empty_items[2], cx, cy + 52)

        self._draw_grid()
        self._layout_toolbar.lift()
        self._view_toolbar.lift()

    # -------------------------------------------------------------- Data/API

    def clear(self) -> None:
        self._cancel_scheduled_redraw()
        self._item_to_id.clear()
        self._node_items.clear()
        self._nodes.clear()
        self._edges.clear()
        self._adjacency.clear()
        self._model_positions.clear()
        self._node_levels.clear()
        self._root_id = None
        self._selected_id = None
        self._graph_signature = None
        self._scale = 1.0
        self._update_zoom_label()
        self._draw_empty()

    def render(self, evidence: list[Any], relations: list[Any], selected_id: int | None = None) -> None:
        if not evidence:
            self.clear()
            return

        nodes: dict[int, Any] = {}
        for row in evidence:
            node_id = _coerce_id(_value(row, "id"))
            if node_id is not None:
                nodes[node_id] = row
        if not nodes:
            self.clear()
            return

        adjacency: dict[int, set[int]] = defaultdict(set)
        edges: list[tuple[int, int, str, str]] = []
        for relation in relations:
            source = _coerce_id(_value(relation, "source_evidence_id", _value(relation, "source_id")))
            target = _coerce_id(_value(relation, "target_evidence_id", _value(relation, "target_id")))
            if source not in nodes or target not in nodes or source == target:
                continue
            confidence = str(_value(relation, "confidence", "medium")).lower()
            relation_type = str(_value(relation, "relation_type", "related_to"))
            edges.append((source, target, confidence, relation_type))
            adjacency[source].add(target)
            adjacency[target].add(source)

        signature = (
            tuple(nodes),
            tuple((source, target, relation_type) for source, target, _confidence, relation_type in edges),
        )
        preserve_view = signature == self._graph_signature and bool(self._model_positions)

        self._cancel_scheduled_redraw()
        self.canvas.delete("empty")
        self._nodes = nodes
        self._edges = edges
        self._adjacency = adjacency
        self._selected_id = selected_id if selected_id in nodes else None
        self._graph_signature = signature

        if not preserve_view:
            self._root_id = self._pick_root(nodes)
            levels = self._levels(self._root_id, nodes, adjacency)
            self._node_levels = {
                node_id: level for level, node_ids in levels.items() for node_id in node_ids
            }
            self._model_positions = self._positions(levels, rotation=self._layout_rotation)
            width = max(self.canvas.winfo_width(), 900)
            height = max(self.canvas.winfo_height(), 560)
            self._origin = (width / 2, height / 2)
            self._scale = 1.0

        self._draw_world()
        if not preserve_view:
            self.after_idle(lambda expected=signature: self._fit_if_current(expected))

    def fit(self) -> None:
        """Fit the complete graph while keeping the investigation root centred."""
        if not self._model_positions:
            return
        width = max(self.canvas.winfo_width(), 240)
        height = max(self.canvas.winfo_height(), 180)
        max_x = max((abs(x) for x, _y in self._model_positions.values()), default=1.0)
        max_y = max((abs(y) for _x, y in self._model_positions.values()), default=1.0)
        available_width = max(80.0, width - 150.0)
        available_height = max(80.0, height - 130.0)
        scale_x = available_width / max(170.0, max_x * 2 + 80)
        scale_y = available_height / max(140.0, max_y * 2 + 80)
        self._scale = max(self.MIN_SCALE, min(self.MAX_SCALE, scale_x, scale_y))
        self._origin = (width / 2, height / 2)
        self._draw_world()
        self._update_zoom_label()

    def reset_view(self) -> None:
        """Return to 100% zoom and centre the root in the viewport."""
        if not self._model_positions:
            return
        width = max(self.canvas.winfo_width(), 240)
        height = max(self.canvas.winfo_height(), 180)
        self._scale = 1.0
        self._origin = (width / 2, height / 2)
        self._draw_world()
        self._update_zoom_label()

    def reset(self) -> None:
        """Toolbar-friendly alias retained for embedders."""
        self.reset_view()

    def layout(self) -> None:
        """Re-run the radial layout and fit it around the root node."""
        if not self._nodes or self._root_id is None:
            return
        self._layout_rotation = (self._layout_rotation + math.pi / 10) % (2 * math.pi)
        levels = self._levels(self._root_id, self._nodes, self._adjacency)
        self._node_levels = {
            node_id: level for level, node_ids in levels.items() for node_id in node_ids
        }
        self._model_positions = self._positions(levels, rotation=self._layout_rotation)
        self.fit()

    def relayout(self) -> None:
        self.layout()

    def zoom_in(self) -> None:
        self._zoom_at(self.canvas.winfo_width() / 2, self.canvas.winfo_height() / 2, 1.16)

    def zoom_out(self) -> None:
        self._zoom_at(self.canvas.winfo_width() / 2, self.canvas.winfo_height() / 2, 1 / 1.16)

    # --------------------------------------------------------------- Layout

    @staticmethod
    def _properties(row: Any) -> dict[str, Any]:
        properties = _value(row, "properties", {}) or {}
        if isinstance(properties, dict):
            return properties
        if isinstance(properties, str):
            try:
                decoded = json.loads(properties)
                return decoded if isinstance(decoded, dict) else {}
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}

    @staticmethod
    def _pick_root(nodes: dict[int, Any]) -> int:
        for node_id, row in nodes.items():
            properties = EvidenceGraph._properties(row)
            if properties.get("is_seed") or str(_value(row, "stable_key", "")).startswith("file:seed"):
                return node_id
            if str(_value(row, "source", "")).lower() == "filesystem seed":
                return node_id
        for node_id, row in nodes.items():
            if str(_value(row, "entity_type", "")) == "file":
                return node_id
        return next(iter(nodes))

    @staticmethod
    def _levels(
        root: int,
        nodes: dict[int, Any],
        adjacency: dict[int, set[int]],
    ) -> dict[int, list[int]]:
        distances = {root: 0}
        queue: deque[int] = deque([root])
        while queue:
            current = queue.popleft()
            for neighbour in sorted(adjacency.get(current, ())):
                if neighbour not in distances:
                    distances[neighbour] = distances[current] + 1
                    queue.append(neighbour)

        detached_level = max(distances.values(), default=0) + 1
        levels: dict[int, list[int]] = defaultdict(list)
        for node_id in nodes:
            levels[distances.get(node_id, detached_level)].append(node_id)
        for node_ids in levels.values():
            node_ids.sort(
                key=lambda node_id: (
                    entity_group(str(_value(nodes[node_id], "entity_type", "artifact"))),
                    str(_value(nodes[node_id], "label", "")).casefold(),
                    node_id,
                )
            )
        return dict(levels)

    @staticmethod
    def _positions(
        levels: dict[int, list[int]],
        *,
        rotation: float = -math.pi / 2,
    ) -> dict[int, tuple[float, float]]:
        result: dict[int, tuple[float, float]] = {}
        previous_radius = 0.0
        for level, node_ids in sorted(levels.items()):
            if level == 0:
                if node_ids:
                    result[node_ids[0]] = (0.0, 0.0)
                continue

            count = len(node_ids)
            base_radius = 100.0 + (level - 1) * 92.0
            density_radius = count * 14.0 / (2 * math.pi)
            radius = max(base_radius, density_radius, previous_radius + 82.0)
            previous_radius = radius
            if count == 1:
                angles = [rotation + level * 0.76]
            else:
                start = rotation + (level % 2) * math.pi / max(4, count)
                angles = [start + (2 * math.pi * index / count) for index in range(count)]
            for node_id, angle in zip(node_ids, angles):
                result[node_id] = (
                    math.cos(angle) * radius,
                    math.sin(angle) * radius * 0.76,
                )
        return result

    # -------------------------------------------------------------- Drawing

    def _draw_world(self) -> None:
        self._redraw_job = None
        self.canvas.delete("world")
        self._item_to_id.clear()
        self._node_items.clear()
        if not self._model_positions:
            return

        selected = self._selected_id
        for source, target, confidence, _relation_type in self._edges:
            if source not in self._model_positions or target not in self._model_positions:
                continue
            sx, sy = self._screen_position(source)
            tx, ty = self._screen_position(target)
            incident = selected is not None and selected in (source, target)
            colour = "#7a473b" if incident else EDGE_COLORS.get(confidence, EDGE_COLORS["medium"])
            dash = (4, 5) if confidence == "low" else None
            self.canvas.create_line(
                sx,
                sy,
                tx,
                ty,
                fill=colour,
                width=1.25 if incident else 1.0,
                arrow=tk.LAST,
                arrowshape=(5, 6, 2),
                dash=dash,
                tags=("world", "edge"),
            )

        for node_id, row in self._nodes.items():
            x, y = self._screen_position(node_id)
            entity_type = str(_value(row, "entity_type", "artifact"))
            colour = self._entity_colour(entity_type)
            severity = str(_value(row, "severity", "info")).lower()
            is_selected = node_id == selected
            is_root = node_id == self._root_id
            is_important = is_root or is_selected or severity in {"high", "critical"}
            radius = 4.5 if is_root or is_selected else 3.5
            items: list[int] = []

            if is_important:
                ring_radius = 9.0 if is_selected else 7.5
                ring = self.canvas.create_oval(
                    x - ring_radius,
                    y - ring_radius,
                    x + ring_radius,
                    y + ring_radius,
                    fill="",
                    outline=ACCENT,
                    width=2 if is_selected else 1,
                    tags=("world", "node", "node-ring", f"node:{node_id}"),
                )
                items.append(ring)

            dot = self.canvas.create_oval(
                x - radius,
                y - radius,
                x + radius,
                y + radius,
                fill=colour,
                outline="#151515",
                width=1,
                tags=("world", "node", "node-dot", f"node:{node_id}"),
            )
            items.append(dot)
            for item_id in items:
                self._item_to_id[item_id] = node_id
            self._node_items[node_id] = tuple(items)

        label_ids = self._label_node_ids()
        occupied: list[tuple[float, float, float, float]] = []
        for node_id in label_ids:
            self._draw_label(node_id, occupied)

        self.canvas.tag_raise("node-ring")
        self.canvas.tag_raise("node-dot")
        self.canvas.tag_raise("node-label-bg")
        self.canvas.tag_raise("node-label")
        self.canvas.tag_lower("grid")

    def _label_node_ids(self) -> list[int]:
        node_count = len(self._nodes)
        # The reference keeps the canvas readable by labelling only selected,
        # hub and highest-priority entities. Eight capsules is a deliberate
        # ceiling even when a case contains hundreds of high-severity records.
        limit = min(8, max(5, int(math.sqrt(node_count) * 0.55)))
        scored: list[tuple[float, int]] = []
        for node_id, row in self._nodes.items():
            severity = str(_value(row, "severity", "info")).lower()
            entity_type = str(_value(row, "entity_type", "artifact"))
            score = float(len(self._adjacency.get(node_id, ())) * 12)
            score -= self._node_levels.get(node_id, 99) * 3
            if node_id == self._root_id:
                score += 10_000
            if node_id == self._selected_id:
                score += 9_000
            if severity == "critical":
                score += 8_000
            elif severity == "high":
                score += 7_000
            if entity_type == "alert":
                score += 6_000
            scored.append((score, node_id))

        scored.sort(key=lambda item: (-item[0], item[1]))
        return [node_id for _score, node_id in scored[:limit]]

    def _draw_label(
        self,
        node_id: int,
        occupied: list[tuple[float, float, float, float]],
    ) -> None:
        row = self._nodes[node_id]
        x, y = self._screen_position(node_id)
        width = max(self.canvas.winfo_width(), 2)
        height = max(self.canvas.winfo_height(), 2)
        if x < -180 or y < -60 or x > width + 180 or y > height + 60:
            return

        entity_type = str(_value(row, "entity_type", "artifact"))
        label = " ".join(str(_value(row, "label", entity_type)).split())
        if len(label) > 34:
            label = label[:31] + "…"
        text = f"{self._glyph(entity_type)}  {label}"
        model_x, _model_y = self._model_positions.get(node_id, (0.0, 0.0))
        place_right = model_x >= 0 or node_id == self._root_id
        anchor = "w" if place_right else "e"
        label_x = x + 11 if place_right else x - 11
        colour = self._entity_colour(entity_type)
        selected = node_id == self._selected_id
        text_id = self.canvas.create_text(
            label_x,
            y,
            text=text,
            anchor=anchor,
            fill=ACCENT if selected else colour,
            font=("Segoe UI", 9, "bold"),
            tags=("world", "node", "node-label", f"node:{node_id}"),
        )

        chosen_bbox: tuple[float, float, float, float] | None = None
        for offset in (0, -19, 19, -38, 38, -57, 57):
            self.canvas.coords(text_id, label_x, y + offset)
            raw_bbox = self.canvas.bbox(text_id)
            if raw_bbox is None:
                continue
            candidate = (
                raw_bbox[0] - 7,
                raw_bbox[1] - 4,
                raw_bbox[2] + 7,
                raw_bbox[3] + 4,
            )
            if not any(self._overlaps(candidate, other) for other in occupied):
                chosen_bbox = candidate
                break
        if chosen_bbox is None:
            raw_bbox = self.canvas.bbox(text_id)
            if raw_bbox is None:
                self.canvas.delete(text_id)
                return
            chosen_bbox = (
                raw_bbox[0] - 7,
                raw_bbox[1] - 4,
                raw_bbox[2] + 7,
                raw_bbox[3] + 4,
            )

        background = self._rounded_rectangle(
            *chosen_bbox,
            radius=5,
            fill="#332622" if selected else "#252b2d",
            outline="#9a4935" if selected else "#30383a",
            tags=("world", "node", "node-label-bg", f"node:{node_id}"),
        )
        self.canvas.tag_lower(background, text_id)
        occupied.append(chosen_bbox)
        self._item_to_id[text_id] = node_id
        self._item_to_id[background] = node_id
        self._node_items[node_id] = self._node_items.get(node_id, ()) + (background, text_id)

    def _rounded_rectangle(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        *,
        radius: float,
        fill: str,
        outline: str,
        tags: tuple[str, ...],
    ) -> int:
        radius = min(radius, abs(x2 - x1) / 2, abs(y2 - y1) / 2)
        points = (
            x1 + radius,
            y1,
            x2 - radius,
            y1,
            x2,
            y1,
            x2,
            y1 + radius,
            x2,
            y2 - radius,
            x2,
            y2,
            x2 - radius,
            y2,
            x1 + radius,
            y2,
            x1,
            y2,
            x1,
            y2 - radius,
            x1,
            y1 + radius,
            x1,
            y1,
        )
        return self.canvas.create_polygon(
            points,
            smooth=True,
            splinesteps=8,
            fill=fill,
            outline=outline,
            width=1,
            tags=tags,
        )

    @staticmethod
    def _overlaps(
        first: tuple[float, float, float, float],
        second: tuple[float, float, float, float],
    ) -> bool:
        margin = 3
        return not (
            first[2] + margin < second[0]
            or first[0] - margin > second[2]
            or first[3] + margin < second[1]
            or first[1] - margin > second[3]
        )

    def _screen_position(self, node_id: int) -> tuple[float, float]:
        model_x, model_y = self._model_positions[node_id]
        return (
            self._origin[0] + model_x * self._scale,
            self._origin[1] + model_y * self._scale,
        )

    @staticmethod
    def _glyph(entity_type: str) -> str:
        grouped = entity_group(entity_type)
        glyphs = {
            "file": "F",
            "process": "P",
            "user": "U",
            "host": "H",
            "registry": "R",
            "service": "S",
            "scheduled_task": "T",
            "startup": "A",
            "ip": "IP",
            "domain": "DNS",
            "connection": "NET",
            "event": "E",
            "alert": "!",
            "prefetch": "PF",
            "persistence": "R",
            "network": "NET",
        }
        return glyphs.get(entity_type, glyphs.get(grouped, "•"))

    @staticmethod
    def _entity_colour(entity_type: str) -> str:
        return NODE_COLORS.get(entity_type, NODE_COLORS.get(entity_group(entity_type), NODE_COLORS["artifact"]))

    # --------------------------------------------------------------- Camera

    def _click(self, event: tk.Event) -> None:
        if event.state & 0x0001:  # Shift+drag is reserved for panning.
            return
        current = self.canvas.find_withtag("current")
        if not current:
            return
        node_id = self._item_to_id.get(current[0])
        if node_id is None:
            return
        if node_id != self._selected_id:
            self._selected_id = node_id
            self._draw_world()
        if self.on_select:
            self.on_select(node_id)

    def _pan_begin(self, event: tk.Event) -> None:
        self._pan_last = (event.x, event.y)
        self.canvas.configure(cursor="fleur")

    def _pan_move(self, event: tk.Event) -> None:
        if self._pan_last is None or not self._model_positions:
            return
        dx = event.x - self._pan_last[0]
        dy = event.y - self._pan_last[1]
        self._pan_last = (event.x, event.y)
        self.canvas.move("world", dx, dy)
        self._origin = (self._origin[0] + dx, self._origin[1] + dy)

    def _pan_end(self, _event: tk.Event) -> None:
        self._pan_last = None
        self.canvas.configure(cursor="arrow")

    def _wheel(self, event: tk.Event) -> str:
        direction = 1 if getattr(event, "num", None) == 4 or getattr(event, "delta", 0) > 0 else -1
        if event.state & 0x0001 and self._model_positions:
            dx = 52 * direction
            self.canvas.move("world", dx, 0)
            self._origin = (self._origin[0] + dx, self._origin[1])
        else:
            factor = 1.12 if direction > 0 else 1 / 1.12
            self._zoom_at(event.x, event.y, factor)
        return "break"

    def _zoom_at(self, x: float, y: float, factor: float) -> None:
        if not self._model_positions:
            return
        old_scale = self._scale
        new_scale = max(self.MIN_SCALE, min(self.MAX_SCALE, old_scale * factor))
        if math.isclose(new_scale, old_scale):
            return
        actual_factor = new_scale / old_scale
        old_x, old_y = self._origin
        self._origin = (
            x - (x - old_x) * actual_factor,
            y - (y - old_y) * actual_factor,
        )
        self._scale = new_scale

        # Scaling existing items makes wheel input immediate even for very large
        # graphs. A short debounced redraw then restores constant-size dots,
        # arrowheads and label capsules.
        self.canvas.scale("world", x, y, actual_factor, actual_factor)
        self._update_zoom_label()
        self._cancel_scheduled_redraw()
        self._redraw_job = self.after(55, self._draw_world)

    def _cancel_scheduled_redraw(self) -> None:
        if self._redraw_job is not None:
            try:
                self.after_cancel(self._redraw_job)
            except tk.TclError:
                pass
            self._redraw_job = None

    def _update_zoom_label(self) -> None:
        if hasattr(self, "_zoom_label"):
            self._zoom_label.configure(text=f"{round(self._scale * 100):d}%")

    def _fit_if_current(self, expected_signature: tuple[Any, ...]) -> None:
        if expected_signature == self._graph_signature and self._model_positions:
            self.fit()
