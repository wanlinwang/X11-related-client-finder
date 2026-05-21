#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
X11 Related Client Finder. Powered by www.icinfra.cn

Workflow:
    1. Click one X11 window.
    2. Read WM_CLIENT_MACHINE and _NET_WM_PID with xprop.
    3. SSH to the remote execution host.
    4. Read the remote process table.
    5. Build the ancestor PID chain from the clicked PID up to PID 1.
    6. Display the ancestor chain as a process tree.
    7. For every process row, attach related X Client window rows if any.
    8. Right-click a process row to expand direct child processes or all descendant processes.
    9. Double-click a window row, or a process row with related windows, to bring the GUI window to the front.

Local dependencies:
    python3
    xprop
    xdotool
    ssh
    tkinter

Remote dependencies:
    ps

Remote shell compatibility:
    Remote commands are forced through /bin/sh -lc, so csh/tcsh login shells are supported.
"""

import argparse
import io
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict


ACTIVATE_CMD_TIMEOUT = 3


DEFAULT_SSH_CONNECT_TIMEOUT = 8
DEFAULT_SSH_BATCH_MODE = "yes"

DEFAULT_HOST_MATCH_MODE = "loose"
DEFAULT_ACTIVATE_MODE = "activate"
DEFAULT_FLASH_ROUNDS = 1
DEFAULT_FLASH_INTERVAL = 0.45

# Linux/Unix init is PID 1; the ancestor-chain view intentionally stops there.
INIT_PID = 1
MAX_TREE_NODES = 30000

GRAPH_NODE_MIN_WIDTH = 120
GRAPH_NODE_HEIGHT_SINGLE_LINE = 34
GRAPH_NODE_HEIGHT_DOUBLE_LINE = 58
GRAPH_NODE_TEXT_PADDING_X = 10
GRAPH_NODE_TITLE_Y_WITH_DETAIL = 14
GRAPH_NODE_SEPARATOR_Y = 24
GRAPH_NODE_DETAIL_Y = 38
GRAPH_NODE_OUTLINE_WIDTH = 2
GRAPH_LAYOUT_MARGIN_X = 40
GRAPH_START_Y = 35
GRAPH_LEVEL_Y_GAP = 92
GRAPH_NODE_X_GAP = 64
GRAPH_ZOOM_STEP = 1.12
GRAPH_ZOOM_MIN = 0.45
GRAPH_ZOOM_MAX = 2.8
GRAPH_ZOOM_EPSILON = 1e-9
GRAPH_PROCESS_FILL_COLOR = "#e8f1ff"
GRAPH_WINDOW_FILL_COLOR = "#e8f7e8"
GRAPH_PROCESS_OUTLINE_COLOR = "#4c78a8"
GRAPH_WINDOW_OUTLINE_COLOR = "#59a14f"
GRAPH_CARD_SHADOW_COLOR = "#ccd6e4"
GRAPH_CARD_SEPARATOR_COLOR = "#c0c8d6"
GRAPH_DEAD_ITEM_COLOR = "gray"
GRAPH_SELECTION_OUTLINE_COLOR = "#d62728"
GRAPH_SELECTION_OUTLINE_WIDTH = 3
GRAPH_WINDOW_THUMB_WIDTH = 160
GRAPH_WINDOW_THUMB_HEIGHT = 100
GRAPH_WINDOW_NODE_WIDTH = GRAPH_WINDOW_THUMB_WIDTH + 20
GRAPH_WINDOW_NODE_HEIGHT = GRAPH_WINDOW_THUMB_HEIGHT + 48
GRAPH_WINDOW_THUMB_TOP_PADDING = 10
GRAPH_WINDOW_THUMB_BG = "#f2f4f8"
GRAPH_WINDOW_THUMB_PENDING_TEXT = "Loading preview..."
GRAPH_WINDOW_THUMB_MISSING_TEXT = "No preview"
GRAPH_WINDOW_THUMB_CAPTURE_TIMEOUT_SECONDS = 6
CANVAS_ITEM_TYPES_SUPPORTING_FILL = {"rectangle", "oval", "arc", "polygon", "line", "text"}


def command_exists(cmd):
    return shutil.which(cmd) is not None


def run_cmd(cmd, timeout=None):
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )

    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        raise RuntimeError("Command timeout: {}".format(" ".join(cmd)))

    return proc.returncode, out, err


def show_info(message, title="X11 Related Client Finder. Powered by www.icinfra.cn"):
    if command_exists("zenity"):
        subprocess.call([
            "zenity",
            "--info",
            "--title", title,
            "--text", message,
            "--width", "680",
        ])
    elif command_exists("xmessage"):
        subprocess.call([
            "xmessage",
            "-center",
            message,
        ])
    else:
        print(message)


def show_error(message, title="X11 Related Client Finder Error"):
    if command_exists("zenity"):
        subprocess.call([
            "zenity",
            "--error",
            "--title", title,
            "--text", message,
            "--width", "860",
        ])
    elif command_exists("xmessage"):
        subprocess.call([
            "xmessage",
            "-center",
            "ERROR:\n\n" + message,
        ])
    else:
        print("ERROR:", message, file=sys.stderr)


def parse_xprop_value(line):
    if "=" not in line:
        return ""

    value = line.split("=", 1)[1].strip()

    if value.startswith('"') and value.endswith('"') and value.count('"') == 2:
        return value[1:-1]

    return value


def wm_class_first_field(value):
    raw = str(value or "").strip()

    if not raw:
        return ""

    return raw.split(",", 1)[0].strip().strip('"').strip("'")


def normalize_pid(pid_text):
    pid_text = str(pid_text).strip()
    m = re.search(r"\d+", pid_text)

    if not m:
        raise ValueError("_NET_WM_PID is not a valid PID: {}".format(pid_text))

    return int(m.group(0))


def normalize_host(value):
    return str(value).strip().strip('"').strip("'").lower()


def short_host(value):
    return normalize_host(value).split(".", 1)[0]


def host_matches(window_machine, target_machine, mode):
    wm = normalize_host(window_machine)
    tm = normalize_host(target_machine)

    if not wm or not tm:
        return False

    if mode == "strict":
        return wm == tm

    if wm == tm:
        return True

    return short_host(wm) == short_host(tm)


def get_xprop_from_clicked_window():
    show_info(
        "Please click one target X11 application window.\n\n"
        "The program will read:\n"
        "  WM_CLIENT_MACHINE\n"
        "  _NET_WM_PID\n\n"
        "Then it will connect to the remote host, build the process tree, "
        "and list related X Client windows."
    )

    rc, out, err = run_cmd(["xprop"])

    if rc != 0:
        raise RuntimeError("xprop failed or the operation was cancelled.\n\n{}".format(err.strip()))

    props = {
        "WM_CLIENT_MACHINE": "",
        "_NET_WM_PID": None,
        "WM_NAME": "",
        "WM_CLASS": "",
        "WM_COMMAND": "",
        "_RAW_XPROP": out,
    }

    for raw_line in out.splitlines():
        line = raw_line.strip()

        if line.startswith("WM_CLIENT_MACHINE"):
            props["WM_CLIENT_MACHINE"] = parse_xprop_value(line)

        elif line.startswith("_NET_WM_PID"):
            value = parse_xprop_value(line)
            props["_NET_WM_PID"] = normalize_pid(value)

        elif line.startswith("WM_NAME"):
            props["WM_NAME"] = parse_xprop_value(line)

        elif line.startswith("WM_CLASS"):
            props["WM_CLASS"] = parse_xprop_value(line)

        elif line.startswith("WM_COMMAND"):
            props["WM_COMMAND"] = parse_xprop_value(line)

    return props


def remote_sh(command):
    return "/bin/sh -lc {}".format(shlex.quote(command))


def ssh_command(machine, remote_command, connect_timeout, batch_mode):
    cmd = [
        "ssh",
        "-o", "ConnectTimeout={}".format(connect_timeout),
        "-o", "BatchMode={}".format(batch_mode),
        machine,
        remote_command,
    ]

    return run_cmd(cmd)


def fetch_remote_hostname(machine, connect_timeout, batch_mode):
    remote_cmd = remote_sh(
        "hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown"
    )

    rc, out, err = ssh_command(
        machine,
        remote_cmd,
        connect_timeout,
        batch_mode,
    )

    if rc != 0:
        return "unknown"

    return out.strip() or "unknown"


def fetch_remote_process_table(machine, connect_timeout, batch_mode):
    remote_cmd = remote_sh(
        "LC_ALL=C ps -ww -eo pid=,ppid=,user=,stat=,comm=,args="
    )

    rc, out, err = ssh_command(
        machine,
        remote_cmd,
        connect_timeout,
        batch_mode,
    )

    if rc != 0:
        raise RuntimeError(
            "Failed to run remote ps command.\n\n"
            "Remote host: {}\n\n"
            "stderr:\n{}".format(machine, err.strip())
        )

    return out


def parse_ps_output(ps_output):
    procs = {}
    children = defaultdict(list)

    for raw_line in ps_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parts = line.split(None, 5)
        if len(parts) < 5:
            continue

        try:
            pid = int(parts[0])
            ppid = int(parts[1])
        except ValueError:
            continue

        user = parts[2]
        stat = parts[3]
        comm = parts[4]
        args = parts[5] if len(parts) >= 6 else "[{}]".format(comm)

        procs[pid] = {
            "pid": pid,
            "ppid": ppid,
            "user": user,
            "stat": stat,
            "comm": comm,
            "args": args,
        }

    for pid, info in procs.items():
        children[info["ppid"]].append(pid)

    for ppid in children:
        children[ppid].sort()

    return procs, children


def build_ancestor_chain_to_pid1(seed_pid, procs):
    """
    Return PID chain from seed PID upward to PID 1.

    Example:
        [238741, 238700, 221000, 1850, 1]
    """
    chain = []
    seen = set()
    current = seed_pid

    while current in procs and current not in seen:
        chain.append(current)
        seen.add(current)

        if current == INIT_PID:
            break

        ppid = procs[current]["ppid"]

        if ppid <= 0:
            break

        current = ppid

    return chain


def collect_descendant_pids(root_pid, children):
    result = set()
    stack = [root_pid]

    while stack:
        pid = stack.pop()

        if pid in result:
            continue

        if len(result) > MAX_TREE_NODES:
            break

        result.add(pid)

        for child in children.get(pid, []):
            stack.append(child)

    return result


def get_net_client_list():
    for prop in ["_NET_CLIENT_LIST_STACKING", "_NET_CLIENT_LIST"]:
        rc, out, err = run_cmd(["xprop", "-root", prop])

        if rc != 0:
            continue

        ids = re.findall(r"0x[0-9a-fA-F]+", out)
        if ids:
            return ids

    return []


def get_window_props(window_id):
    rc, out, err = run_cmd(["xprop", "-id", window_id])

    if rc != 0:
        return None

    props = {
        "WINDOW_ID": window_id,
        "WM_CLIENT_MACHINE": "",
        "_NET_WM_PID": None,
        "WM_NAME": "",
        "WM_CLASS": "",
        "WM_COMMAND": "",
    }

    for raw_line in out.splitlines():
        line = raw_line.strip()

        if line.startswith("WM_CLIENT_MACHINE"):
            props["WM_CLIENT_MACHINE"] = parse_xprop_value(line)

        elif line.startswith("_NET_WM_PID"):
            value = parse_xprop_value(line)
            try:
                props["_NET_WM_PID"] = normalize_pid(value)
            except Exception:
                props["_NET_WM_PID"] = None

        elif line.startswith("WM_NAME"):
            props["WM_NAME"] = parse_xprop_value(line)

        elif line.startswith("WM_CLASS"):
            props["WM_CLASS"] = parse_xprop_value(line)

        elif line.startswith("WM_COMMAND"):
            props["WM_COMMAND"] = parse_xprop_value(line)

    return props


def enumerate_x_clients_for_machine(machine, host_match_mode):
    window_ids = get_net_client_list()
    pid_to_windows = defaultdict(list)
    all_windows = []

    for window_id in window_ids:
        props = get_window_props(window_id)

        if not props:
            continue

        win_machine = props.get("WM_CLIENT_MACHINE", "")
        win_pid = props.get("_NET_WM_PID", None)

        if win_pid is None:
            continue

        if not host_matches(win_machine, machine, host_match_mode):
            continue

        pid_to_windows[win_pid].append(props)
        all_windows.append(props)

    for pid in pid_to_windows:
        pid_to_windows[pid].sort(key=lambda item: (
            item.get("WM_NAME") or "",
            item.get("WINDOW_ID") or "",
        ))

    return pid_to_windows, all_windows


def get_active_window():
    rc, out, err = run_cmd(["xdotool", "getactivewindow"])

    if rc != 0:
        return None

    value = out.strip()
    return value or None


def activate_window(window_id, mode):
    """Return True if at least one xdotool sub-command exited 0 (window exists)."""
    if not window_id:
        return False

    if mode == "raise":
        cmds = [["xdotool", "windowraise", window_id]]
    elif mode == "focus":
        cmds = [["xdotool", "windowfocus", window_id]]
    else:
        # No --sync: avoids blocking on slow window managers. Follow with windowraise
        # so the window still comes forward even if activate hasn't taken effect yet.
        cmds = [
            ["xdotool", "windowactivate", window_id],
            ["xdotool", "windowraise", window_id],
        ]

    any_success = False

    for cmd in cmds:
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=ACTIVATE_CMD_TIMEOUT,
            )
            if result.returncode == 0:
                any_success = True
        except subprocess.TimeoutExpired:
            pass

    return any_success


def activate_window_async(window_id, mode, on_done=None):
    if not window_id:
        if on_done:
            on_done(False)
        return

    def worker():
        ok = activate_window(window_id, mode)
        if on_done:
            on_done(ok)

    threading.Thread(
        target=worker,
        daemon=True,
    ).start()


def xkill_window(window_id):
    if not window_id:
        return

    try:
        subprocess.run(
            ["xkill", "-id", window_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=ACTIVATE_CMD_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        pass


def xkill_window_async(window_id):
    if not window_id:
        return

    threading.Thread(
        target=xkill_window,
        args=(window_id,),
        daemon=True,
    ).start()


def flash_window_ids(window_ids, rounds, interval, mode, restore_focus):
    original_active = get_active_window() if restore_focus else None

    for _ in range(rounds):
        for window_id in window_ids:
            activate_window(window_id, mode)
            time.sleep(interval)

    if restore_focus and original_active:
        activate_window(original_active, "activate")


def format_process(pid, procs):
    info = procs.get(pid)

    if not info:
        return "{} <missing>".format(pid)

    return "{} ppid={} user={} stat={} comm={} args={}".format(
        info["pid"],
        info["ppid"],
        info["user"],
        info["stat"],
        info["comm"],
        info["args"],
    )


def print_console_summary(
    seed_props,
    machine,
    remote_hostname,
    seed_pid,
    procs,
    ancestor_chain,
    pid_to_windows,
):
    print("")
    print("Seed X11 window:")
    print("  WM_CLIENT_MACHINE : {}".format(seed_props.get("WM_CLIENT_MACHINE", "")))
    print("  _NET_WM_PID       : {}".format(seed_props.get("_NET_WM_PID", "")))
    print("  WM_NAME           : {}".format(seed_props.get("WM_NAME", "")))
    print("  WM_CLASS          : {}".format(seed_props.get("WM_CLASS", "")))
    print("  WM_COMMAND        : {}".format(seed_props.get("WM_COMMAND", "")))

    print("")
    print("Remote host:")
    print("  SSH machine       : {}".format(machine))
    print("  Remote hostname   : {}".format(remote_hostname))
    print("  Seed PID          : {}".format(seed_pid))

    print("")
    print("Ancestor chain to PID 1:")
    for pid in ancestor_chain:
        print("  {}".format(format_process(pid, procs)))

    print("")
    print("Known X Client PIDs on the same remote host:")
    for pid in sorted(pid_to_windows.keys()):
        print("  PID {}: {} window(s)".format(pid, len(pid_to_windows[pid])))

    print("")


class XClientTreeApp:
    def __init__(
        self,
        root,
        context,
        activate_mode,
        flash_rounds,
        flash_interval,
        restore_focus,
        reload_callback,
    ):
        import tkinter as tk
        from tkinter import ttk
        from tkinter import font as tkfont

        self.tk = tk
        self.ttk = ttk
        self.tkfont = tkfont

        self.root = root
        self.context = context
        self.activate_mode = activate_mode
        self.flash_rounds = flash_rounds
        self.flash_interval = flash_interval
        self.restore_focus = restore_focus
        self.reload_callback = reload_callback

        self.row_type = {}
        self.row_pid = {}
        self.row_window_ids = {}
        self.pid_item = {}
        self.inserted_pid_under_parent = set()
        self.window_row_seq = 0
        self.killed_rows = set()
        self.graph_node_type = {}
        self.graph_node_pid = {}
        self.graph_node_window_ids = {}
        self.graph_node_canvas_items = {}
        self.graph_canvas_item_node = {}
        self.graph_node_boxes = {}
        self.graph_node_window_id = {}
        self.graph_node_thumb_image_item = {}
        self.graph_node_thumb_text_item = {}
        self.graph_edges = []
        self.graph_selected_node = None
        self.graph_drag_node = None
        self.graph_drag_last_xy = None
        self.graph_zoom = 1.0
        self.graph_pan_active = False
        self.rooted_expanded_direct_pids = set()
        self.rooted_expanded_all_pids = set()
        self.rooted_visible_process_children = defaultdict(list)
        self.view_mode = "chain"
        self.view_toggle_text = tk.StringVar(value="Switch to Rooted Tree View")
        self.graph_title_font = tkfont.Font(root=self.root, font="TkDefaultFont")
        self.graph_title_font.configure(size=10, weight="bold")
        self.graph_detail_font = tkfont.Font(root=self.root, font="TkDefaultFont")
        self.graph_detail_font.configure(size=10)
        self.thumbnail_cache = {}
        self.thumbnail_inflight = set()
        self.thumbnail_tool_available = command_exists("import")
        self.pillow_enabled = False
        self.pillow_image_module = None
        self.pillow_imagetk_module = None
        self.pillow_resample_lanczos = None
        self.thumb_placeholder_photo = tk.PhotoImage(
            width=GRAPH_WINDOW_THUMB_WIDTH,
            height=GRAPH_WINDOW_THUMB_HEIGHT,
        )
        self.thumb_placeholder_photo.put(
            GRAPH_WINDOW_THUMB_BG,
            to=(0, 0, GRAPH_WINDOW_THUMB_WIDTH, GRAPH_WINDOW_THUMB_HEIGHT),
        )

        if self.thumbnail_tool_available:
            try:
                from PIL import Image as pillow_image_module
                from PIL import ImageTk as pillow_imagetk_module

                self.pillow_image_module = pillow_image_module
                self.pillow_imagetk_module = pillow_imagetk_module
                self.pillow_enabled = True
                self.pillow_resample_lanczos = (
                    pillow_image_module.Resampling.LANCZOS
                    if hasattr(pillow_image_module, "Resampling")
                    else pillow_image_module.LANCZOS
                )
            except Exception:
                self.pillow_enabled = False

        self.root.title("X11 Related Client Finder. Powered by www.icinfra.cn")
        self.root.geometry("1520x760")

        self.build_layout()
        self.build_initial_tree()

    def build_layout(self):
        tk = self.tk
        ttk = self.ttk

        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        summary_text = (
            "Seed window: machine={machine}, pid={pid}, name={name}, class={klass}\n"
            "Remote host: ssh={machine}, hostname={remote_hostname}\n"
            "Double-click a window row, or a process row with windows, to bring the GUI window to the front. "
            "Right-click a process row to expand child processes."
        ).format(
            machine=self.context["machine"],
            pid=self.context["seed_pid"],
            name=self.context["seed_props"].get("WM_NAME", ""),
            klass=self.context["seed_props"].get("WM_CLASS", ""),
            remote_hostname=self.context["remote_hostname"],
        )

        summary = ttk.Label(main, text=summary_text, justify=tk.LEFT)
        summary.pack(fill=tk.X, pady=(0, 10))

        tree_frame = ttk.Frame(main)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        self.tree_frame = tree_frame

        columns = (
            "type",
            "pid",
            "ppid",
            "role",
            "user",
            "stat",
            "comm",
            "windows",
            "window_id",
            "machine",
            "name",
            "class",
            "command",
        )

        self.tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="tree headings",
            selectmode="browse",
            height=24,
        )

        headings = {
            "type": "Type",
            "pid": "PID",
            "ppid": "PPID",
            "role": "Role",
            "user": "User",
            "stat": "Stat",
            "comm": "Comm",
            "windows": "Windows",
            "window_id": "Window ID",
            "machine": "WM_CLIENT_MACHINE",
            "name": "WM_NAME",
            "class": "WM_CLASS",
            "command": "Command",
        }

        widths = {
            "#0": 300,
            "type": 90,
            "pid": 90,
            "ppid": 90,
            "role": 120,
            "user": 90,
            "stat": 70,
            "comm": 160,
            "windows": 80,
            "window_id": 110,
            "machine": 240,
            "name": 420,
            "class": 260,
            "command": 650,
        }

        self.tree.heading("#0", text="Process / X Client Tree")
        self.tree.column("#0", width=widths["#0"], anchor=tk.W, stretch=True)

        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor=tk.W, stretch=True)

        yscroll = ttk.Scrollbar(
            tree_frame,
            orient=tk.VERTICAL,
            command=self.tree.yview,
        )

        xscroll = ttk.Scrollbar(
            tree_frame,
            orient=tk.HORIZONTAL,
            command=self.tree.xview,
        )

        self.tree.configure(
            yscrollcommand=yscroll.set,
            xscrollcommand=xscroll.set,
        )

        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        self.tree_yscroll = yscroll
        self.tree_xscroll = xscroll

        self.graph_canvas = tk.Canvas(
            tree_frame,
            background="white",
            highlightthickness=1,
            highlightbackground="#9a9a9a",
        )

        graph_yscroll = ttk.Scrollbar(
            tree_frame,
            orient=tk.VERTICAL,
            command=self.graph_canvas.yview,
        )

        graph_xscroll = ttk.Scrollbar(
            tree_frame,
            orient=tk.HORIZONTAL,
            command=self.graph_canvas.xview,
        )

        self.graph_canvas.configure(
            yscrollcommand=graph_yscroll.set,
            xscrollcommand=graph_xscroll.set,
        )

        self.graph_yscroll = graph_yscroll
        self.graph_xscroll = graph_xscroll

        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.tree.tag_configure("killed", foreground="gray")

        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Return>", lambda event: self.activate_selected())
        self.tree.bind("<Button-3>", self.on_right_click)
        self.tree.bind("<Button-2>", self.on_right_click)
        self.graph_canvas.bind("<ButtonPress-1>", self.on_graph_press)
        self.graph_canvas.bind("<B1-Motion>", self.on_graph_drag)
        self.graph_canvas.bind("<ButtonRelease-1>", self.on_graph_release)
        self.graph_canvas.bind("<Double-1>", self.on_graph_double_click)
        self.graph_canvas.bind("<Button-3>", self.on_graph_right_click)
        self.graph_canvas.bind("<MouseWheel>", self.on_graph_mousewheel)
        self.graph_canvas.bind("<Button-4>", self.on_graph_mousewheel)
        self.graph_canvas.bind("<Button-5>", self.on_graph_mousewheel)
        self.graph_canvas.bind("<ButtonPress-2>", self.on_graph_pan_start)
        self.graph_canvas.bind("<B2-Motion>", self.on_graph_pan_drag)
        self.graph_canvas.bind("<ButtonRelease-2>", self.on_graph_pan_end)

        button_frame = ttk.Frame(main)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(
            button_frame,
            text="Activate Selected",
            command=self.activate_selected,
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            button_frame,
            text="Flash Visible Windows",
            command=self.flash_visible_windows,
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            button_frame,
            text="Expand Direct Children",
            command=self.expand_selected_direct_children,
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            button_frame,
            text="Expand All Descendants",
            command=self.expand_selected_all_descendants,
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            button_frame,
            text="Expand Direct Children (Re-SSH)",
            command=self.refresh_then_expand_selected_direct_children,
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            button_frame,
            text="Expand All Descendants (Re-SSH)",
            command=self.refresh_then_expand_selected_all_descendants,
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            button_frame,
            textvariable=self.view_toggle_text,
            command=self.toggle_view_mode,
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            button_frame,
            text="Refresh All",
            command=self.refresh_all,
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            button_frame,
            text="Close",
            command=self.root.destroy,
        ).pack(side=tk.RIGHT)

        info_text = (
            "Initial tree shows the ancestor chain from the top non-PID-1 ancestor down to the seed PID. "
            "PID 1 is excluded from X Client matching. "
            "Right-click any process row to expand direct children or all descendants. "
            "Use the switch button to toggle between ancestor-chain rows and a drawn process/window node-link tree."
        )

        footer = ttk.Label(main, text=info_text, justify=tk.LEFT)
        footer.pack(fill=tk.X, pady=(10, 0))

    def clear_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.row_type.clear()
        self.row_pid.clear()
        self.row_window_ids.clear()
        self.pid_item.clear()
        self.inserted_pid_under_parent.clear()
        self.window_row_seq = 0
        self.killed_rows.clear()

    def clear_graph(self):
        self.graph_canvas.delete("all")
        self.graph_node_type.clear()
        self.graph_node_pid.clear()
        self.graph_node_window_ids.clear()
        self.graph_node_canvas_items.clear()
        self.graph_canvas_item_node.clear()
        self.graph_node_boxes.clear()
        self.graph_node_window_id.clear()
        self.graph_node_thumb_image_item.clear()
        self.graph_node_thumb_text_item.clear()
        self.graph_edges.clear()
        self.graph_selected_node = None
        self.graph_drag_node = None
        self.graph_drag_last_xy = None
        self.graph_zoom = 1.0
        self.graph_pan_active = False
        self.rooted_visible_process_children.clear()

    def clear_display_state(self):
        self.clear_tree()
        self.clear_graph()

    def role_for_pid(self, pid, role_hint=None):
        seed_pid = self.context["seed_pid"]
        ancestor_chain = self.context["ancestor_chain"]
        ancestor_set = set(pid for pid in ancestor_chain if pid != INIT_PID)

        roles = []

        if pid == seed_pid:
            roles.append("seed")

        if pid in ancestor_set and pid != seed_pid:
            roles.append("ancestor")

        if role_hint and role_hint not in roles:
            roles.append(role_hint)

        if not roles:
            roles.append("process")

        return "+".join(roles)

    def process_text(self, pid, role):
        info = self.context["procs"].get(pid)

        if not info:
            return "PID {} <missing>".format(pid)

        windows = self.context["pid_to_windows"].get(pid, [])
        suffix = ""

        if windows:
            suffix = " [{} X Client window(s)]".format(len(windows))

        return "PID {}  {}{}".format(pid, role, suffix)

    def insert_window_rows_for_process(self, process_item, pid):
        windows = self.context["pid_to_windows"].get(pid, [])

        for window in windows:
            self.window_row_seq += 1
            window_id = window.get("WINDOW_ID", "")
            row_id = "win_{}_{}_{}".format(pid, self.window_row_seq, re.sub(r"[^A-Za-z0-9_]", "_", window_id))

            text = "Window {}  {}".format(
                window_id,
                window.get("WM_NAME", ""),
            )

            self.tree.insert(
                process_item,
                "end",
                iid=row_id,
                text=text,
                values=(
                    "window",
                    pid,
                    "",
                    "xclient",
                    "",
                    "",
                    "",
                    "",
                    window_id,
                    window.get("WM_CLIENT_MACHINE", ""),
                    window.get("WM_NAME", ""),
                    window.get("WM_CLASS", ""),
                    window.get("WM_COMMAND", ""),
                ),
            )

            self.row_type[row_id] = "window"
            self.row_pid[row_id] = pid
            self.row_window_ids[row_id] = [window_id]

    def insert_process_row(self, pid, parent_item, role_hint=None, open_item=False):
        if pid not in self.context["procs"]:
            return None

        key = (parent_item, pid)
        if key in self.inserted_pid_under_parent:
            return self.pid_item.get(pid)

        if pid in self.pid_item:
            existing = self.pid_item[pid]
            try:
                self.tree.item(existing, open=True)
            except Exception:
                pass
            return existing

        info = self.context["procs"][pid]
        windows = self.context["pid_to_windows"].get(pid, [])
        window_ids = [item.get("WINDOW_ID", "") for item in windows if item.get("WINDOW_ID", "")]

        role = self.role_for_pid(pid, role_hint)

        item_id = "pid_{}".format(pid)
        self.inserted_pid_under_parent.add(key)
        self.pid_item[pid] = item_id

        self.tree.insert(
            parent_item,
            "end",
            iid=item_id,
            text=self.process_text(pid, role),
            open=open_item,
            values=(
                "process",
                pid,
                info.get("ppid", ""),
                role,
                info.get("user", ""),
                info.get("stat", ""),
                info.get("comm", ""),
                len(windows),
                "",
                self.context["machine"],
                "",
                "",
                info.get("args", ""),
            ),
        )

        self.row_type[item_id] = "process"
        self.row_pid[item_id] = pid
        self.row_window_ids[item_id] = window_ids

        self.insert_window_rows_for_process(item_id, pid)

        return item_id

    def build_chain_tree(self):
        chain = list(self.context["ancestor_chain"])
        chain = [pid for pid in chain if pid != INIT_PID]
        chain.reverse()

        parent = ""

        for index, pid in enumerate(chain):
            item = self.insert_process_row(
                pid=pid,
                parent_item=parent,
                role_hint=None,
                open_item=True,
            )

            if item:
                parent = item

        if not chain:
            seed_pid = self.context["seed_pid"]
            self.insert_process_row(
                pid=seed_pid,
                parent_item="",
                role_hint="seed",
                open_item=True,
            )

    def build_rooted_tree(self):
        chain = [pid for pid in self.context["ancestor_chain"] if pid != INIT_PID]
        chain.reverse()
        parent = ""

        for index, pid in enumerate(chain):
            role_hint = "root" if index == 0 else "descendant"
            item = self.insert_process_row(
                pid=pid,
                parent_item=parent,
                role_hint=role_hint,
                open_item=True,
            )

            if item:
                parent = item

        if not chain:
            self.insert_process_row(
                pid=self.context["seed_pid"],
                parent_item="",
                role_hint="seed",
                open_item=True,
            )

    def graph_node_text_and_size(self, title, details):
        title_text = str(title or "")
        detail_text = str(details or "")
        has_detail = bool(detail_text.strip())
        title_width = self.graph_title_font.measure(title_text)
        detail_width = self.graph_detail_font.measure(detail_text) if has_detail else 0
        content_width = max(title_width, detail_width)
        width = max(
            GRAPH_NODE_MIN_WIDTH,
            content_width + GRAPH_NODE_TEXT_PADDING_X * 2,
        )
        height = GRAPH_NODE_HEIGHT_DOUBLE_LINE if has_detail else GRAPH_NODE_HEIGHT_SINGLE_LINE
        return title_text, detail_text, has_detail, width, height

    def create_graph_node(self, node_id, node_type, pid, window_ids, x, y, title, details, width=None, height=None, window_id=""):
        canvas = self.graph_canvas
        fill = GRAPH_PROCESS_FILL_COLOR if node_type == "process" else GRAPH_WINDOW_FILL_COLOR
        outline = GRAPH_PROCESS_OUTLINE_COLOR if node_type == "process" else GRAPH_WINDOW_OUTLINE_COLOR

        if node_type == "window":
            title_text = str(title or "")
            width = GRAPH_WINDOW_NODE_WIDTH if width is None else width
            height = GRAPH_WINDOW_NODE_HEIGHT if height is None else height
            thumb_top = y + GRAPH_WINDOW_THUMB_TOP_PADDING
            thumb_left = x + (width - GRAPH_WINDOW_THUMB_WIDTH) / 2
            thumb_right = thumb_left + GRAPH_WINDOW_THUMB_WIDTH
            thumb_bottom = thumb_top + GRAPH_WINDOW_THUMB_HEIGHT
            title_y = thumb_bottom + 20
            has_detail = False
        else:
            title_text, detail_text, has_detail, default_width, default_height = self.graph_node_text_and_size(title, details)
            width = default_width if width is None else width
            height = default_height if height is None else height

        shadow = canvas.create_rectangle(
            x + 3,
            y + 3,
            x + width + 3,
            y + height + 3,
            fill=GRAPH_CARD_SHADOW_COLOR,
            outline="",
            tags=("graph_node",),
        )
        rect = canvas.create_rectangle(
            x,
            y,
            x + width,
            y + height,
            fill=fill,
            outline=outline,
            width=GRAPH_NODE_OUTLINE_WIDTH,
            tags=("graph_node",),
        )
        if node_type == "window":
            title_item = canvas.create_text(
                x + (width / 2.0),
                title_y,
                text=title_text,
                anchor="center",
                font=self.graph_title_font,
                tags=("graph_node",),
            )
        else:
            title_item = canvas.create_text(
                x + 10,
                y + (GRAPH_NODE_TITLE_Y_WITH_DETAIL if has_detail else (height / 2.0)),
                text=title_text,
                anchor="w",
                font=self.graph_title_font,
                tags=("graph_node",),
            )
        items = [rect, title_item, shadow]

        if node_type == "window":
            thumb_rect = canvas.create_rectangle(
                thumb_left,
                thumb_top,
                thumb_right,
                thumb_bottom,
                fill=GRAPH_WINDOW_THUMB_BG,
                outline=GRAPH_WINDOW_OUTLINE_COLOR,
                width=1,
                tags=("graph_node",),
            )
            thumb_image = canvas.create_image(
                (thumb_left + thumb_right) / 2,
                (thumb_top + thumb_bottom) / 2,
                image=self.thumb_placeholder_photo,
                tags=("graph_node",),
            )
            thumb_text = canvas.create_text(
                (thumb_left + thumb_right) / 2,
                (thumb_top + thumb_bottom) / 2,
                text=GRAPH_WINDOW_THUMB_PENDING_TEXT,
                anchor="center",
                font=self.graph_detail_font,
                tags=("graph_node",),
            )
            items.extend([thumb_rect, thumb_image, thumb_text])
            self.graph_node_thumb_image_item[node_id] = thumb_image
            self.graph_node_thumb_text_item[node_id] = thumb_text
            self.graph_node_window_id[node_id] = str(window_id or "")
        elif has_detail:
            separator = canvas.create_line(
                x + 10,
                y + GRAPH_NODE_SEPARATOR_Y,
                x + width - 10,
                y + GRAPH_NODE_SEPARATOR_Y,
                fill=GRAPH_CARD_SEPARATOR_COLOR,
                width=1,
                tags=("graph_node",),
            )
            detail_item = canvas.create_text(
                x + 10,
                y + GRAPH_NODE_DETAIL_Y,
                text=detail_text,
                anchor="w",
                font=self.graph_detail_font,
                tags=("graph_node",),
            )
            items.extend([detail_item, separator])
        self.graph_node_type[node_id] = node_type
        self.graph_node_pid[node_id] = pid
        self.graph_node_window_ids[node_id] = window_ids
        self.graph_node_canvas_items[node_id] = items
        self.graph_node_boxes[node_id] = (x, y, x + width, y + height)

        for item in items:
            self.graph_canvas_item_node[item] = node_id

        return (x, y, x + width, y + height)

    def graph_edge_points(self, source_box, target_box):
        source_center_x = (source_box[0] + source_box[2]) / 2
        source_center_y = (source_box[1] + source_box[3]) / 2
        target_center_x = (target_box[0] + target_box[2]) / 2
        target_center_y = (target_box[1] + target_box[3]) / 2

        if abs(target_center_x - source_center_x) >= abs(target_center_y - source_center_y):
            if target_center_x >= source_center_x:
                sx = source_box[2]
                sy = source_center_y
                tx = target_box[0]
                ty = target_center_y
            else:
                sx = source_box[0]
                sy = source_center_y
                tx = target_box[2]
                ty = target_center_y
        else:
            if target_center_y >= source_center_y:
                sx = source_center_x
                sy = source_box[3]
                tx = target_center_x
                ty = target_box[1]
            else:
                sx = source_center_x
                sy = source_box[1]
                tx = target_center_x
                ty = target_box[3]

        dx = tx - sx
        dy = ty - sy
        c1x = sx + dx * 0.35
        c1y = sy + dy * 0.10
        c2x = sx + dx * 0.65
        c2y = sy + dy * 0.90
        return (sx, sy, c1x, c1y, c2x, c2y, tx, ty)

    def redraw_graph_edge(self, edge):
        source_box = self.graph_node_boxes.get(edge["source"])
        target_box = self.graph_node_boxes.get(edge["target"])

        if not source_box or not target_box:
            return

        self.graph_canvas.coords(
            edge["item"],
            *self.graph_edge_points(source_box, target_box),
        )
        self.graph_canvas.tag_lower(edge["item"])

    def redraw_graph_edges_for_node(self, node_id):
        for edge in self.graph_edges:
            if edge["source"] == node_id or edge["target"] == node_id:
                self.redraw_graph_edge(edge)

    def create_graph_edge(self, source_node_id, target_node_id):
        source_box = self.graph_node_boxes.get(source_node_id)
        target_box = self.graph_node_boxes.get(target_node_id)

        if not source_box or not target_box:
            return

        line = self.graph_canvas.create_line(
            *self.graph_edge_points(source_box, target_box),
            fill="#555555",
            width=2,
            arrow="last",
            smooth=True,
            splinesteps=28,
        )
        self.graph_canvas.tag_lower(line)
        self.graph_edges.append({
            "item": line,
            "source": source_node_id,
            "target": target_node_id,
        })

    def render_thumbnail_placeholder_state(self, node_id, message):
        text_item = self.graph_node_thumb_text_item.get(node_id)
        image_item = self.graph_node_thumb_image_item.get(node_id)

        if image_item:
            self.graph_canvas.itemconfigure(image_item, image=self.thumb_placeholder_photo)

        if text_item:
            self.graph_canvas.itemconfigure(text_item, text=message, state="normal")

    def apply_cached_thumbnail_to_node(self, node_id):
        window_id = self.graph_node_window_id.get(node_id, "")
        entry = self.thumbnail_cache.get(window_id)

        if not window_id:
            self.render_thumbnail_placeholder_state(node_id, GRAPH_WINDOW_THUMB_MISSING_TEXT)
            return

        if not entry:
            self.render_thumbnail_placeholder_state(node_id, GRAPH_WINDOW_THUMB_PENDING_TEXT)
            return

        text_item = self.graph_node_thumb_text_item.get(node_id)
        image_item = self.graph_node_thumb_image_item.get(node_id)

        if entry.get("status") == "ok":
            photo = entry.get("photo")
            if image_item and photo is not None:
                self.graph_canvas.itemconfigure(image_item, image=photo)
            if text_item:
                self.graph_canvas.itemconfigure(text_item, state="hidden")
            return

        self.render_thumbnail_placeholder_state(node_id, GRAPH_WINDOW_THUMB_MISSING_TEXT)

    def mark_window_thumbnail_missing(self, window_id):
        if not window_id:
            return

        self.thumbnail_cache[window_id] = {"status": "failed", "photo": None}
        self.thumbnail_inflight.discard(window_id)

        for node_id, node_window_id in list(self.graph_node_window_id.items()):
            if node_window_id == window_id:
                self.apply_cached_thumbnail_to_node(node_id)

    def capture_window_thumbnail_bytes(self, window_id):
        if not window_id or not self.thumbnail_tool_available or not self.pillow_enabled:
            return None

        temp_file = None

        try:
            with tempfile.NamedTemporaryFile(
                suffix=".png",
                delete=False,
            ) as handle:
                temp_file = handle.name

            rc, out, err = run_cmd(
                ["import", "-window", window_id, temp_file],
                timeout=GRAPH_WINDOW_THUMB_CAPTURE_TIMEOUT_SECONDS,
            )

            if rc != 0:
                return None

            with self.pillow_image_module.open(temp_file) as image:
                image = image.convert("RGB")
                image.thumbnail(
                    (GRAPH_WINDOW_THUMB_WIDTH, GRAPH_WINDOW_THUMB_HEIGHT),
                    self.pillow_resample_lanczos,
                )
                board = self.pillow_image_module.new(
                    "RGB",
                    (GRAPH_WINDOW_THUMB_WIDTH, GRAPH_WINDOW_THUMB_HEIGHT),
                    GRAPH_WINDOW_THUMB_BG,
                )
                left = max(0, (GRAPH_WINDOW_THUMB_WIDTH - image.width) // 2)
                top = max(0, (GRAPH_WINDOW_THUMB_HEIGHT - image.height) // 2)
                board.paste(image, (left, top))
                stream = io.BytesIO()
                board.save(stream, format="PNG")
                return stream.getvalue()
        except Exception:
            return None
        finally:
            if temp_file:
                try:
                    os.remove(temp_file)
                except Exception:
                    pass

    def on_window_thumbnail_loaded(self, window_id, image_bytes):
        self.thumbnail_inflight.discard(window_id)

        if not image_bytes:
            self.thumbnail_cache[window_id] = {"status": "failed", "photo": None}
        else:
            photo = None
            try:
                with self.pillow_image_module.open(io.BytesIO(image_bytes)) as img:
                    photo = self.pillow_imagetk_module.PhotoImage(image=img.copy(), master=self.root)
            except Exception:
                photo = None

            if photo is None:
                self.thumbnail_cache[window_id] = {"status": "failed", "photo": None}
            else:
                self.thumbnail_cache[window_id] = {"status": "ok", "photo": photo}

        for node_id, node_window_id in list(self.graph_node_window_id.items()):
            if node_window_id == window_id:
                self.apply_cached_thumbnail_to_node(node_id)

        self.graph_canvas.configure(scrollregion=self.graph_canvas.bbox("all"))

    def start_window_thumbnail_worker(self, window_id):
        if not window_id or window_id in self.thumbnail_inflight:
            return

        self.thumbnail_inflight.add(window_id)

        def worker():
            image_bytes = self.capture_window_thumbnail_bytes(window_id)
            self.root.after(
                0,
                lambda window_id=window_id, image_bytes=image_bytes: self.on_window_thumbnail_loaded(window_id, image_bytes),
            )

        threading.Thread(target=worker, daemon=True).start()

    def schedule_rooted_window_thumbnails(self):
        for node_id, node_type in list(self.graph_node_type.items()):
            if node_type != "window":
                continue

            window_id = self.graph_node_window_id.get(node_id, "")
            self.apply_cached_thumbnail_to_node(node_id)

            if (
                window_id
                and self.thumbnail_tool_available
                and self.pillow_enabled
                and window_id not in self.thumbnail_cache
            ):
                self.start_window_thumbnail_worker(window_id)

    def build_rooted_graph(self):
        chain = [pid for pid in self.context["ancestor_chain"] if pid != INIT_PID]
        chain.reverse()

        if not chain:
            chain = [self.context["seed_pid"]]

        self.rooted_visible_process_children.clear()
        node_specs = {}
        child_map = defaultdict(list)
        depth_map = {}
        root_node_id = None
        parent_of = {}

        for index, pid in enumerate(chain):
            if index > 0:
                parent_of[pid] = chain[index - 1]

        pending = list(chain)
        processed = set()

        while pending:
            pid = pending.pop(0)

            if pid in processed:
                continue

            processed.add(pid)
            children = self.context["children"].get(pid, [])

            if pid in self.rooted_expanded_all_pids:
                stack = [(pid, child_pid) for child_pid in children]
                local_seen = set()

                while stack:
                    parent_pid, child_pid = stack.pop(0)
                    pair = (parent_pid, child_pid)

                    if pair in local_seen:
                        continue

                    local_seen.add(pair)

                    if child_pid not in parent_of:
                        parent_of[child_pid] = parent_pid
                        pending.append(child_pid)

                    grandchildren = self.context["children"].get(child_pid, [])
                    stack.extend((child_pid, grandchild_pid) for grandchild_pid in grandchildren)
            elif pid in self.rooted_expanded_direct_pids:
                for child_pid in children:
                    if child_pid not in parent_of:
                        parent_of[child_pid] = pid
                        pending.append(child_pid)

        process_children = defaultdict(list)
        process_children[None].append(chain[0])

        for child_pid, parent_pid in parent_of.items():
            process_children[parent_pid].append(child_pid)

        for parent_pid in process_children:
            process_children[parent_pid] = sorted(set(process_children[parent_pid]))

        process_depth = {}
        queue = [(chain[0], 0)]
        seen = set()

        while queue:
            pid, depth = queue.pop(0)

            if pid in seen:
                continue

            seen.add(pid)
            process_depth[pid] = depth

            for child_pid in process_children.get(pid, []):
                if child_pid not in seen:
                    queue.append((child_pid, depth + 1))

        for pid in sorted(process_depth.keys(), key=lambda value: (process_depth[value], value)):
            info = self.context["procs"].get(pid, {})
            depth = process_depth[pid]
            process_node_id = "g_pid_{}".format(pid)
            windows = self.context["pid_to_windows"].get(pid, [])
            window_ids = [item.get("WINDOW_ID", "") for item in windows if item.get("WINDOW_ID", "")]
            comm = info.get("comm", "")
            comm_display = comm if str(comm).strip() else "PID {}".format(pid)
            role_hint = "root" if depth == 0 else "descendant"
            role = self.role_for_pid(pid, role_hint)

            if depth == 0:
                root_node_id = process_node_id

            node_specs[process_node_id] = {
                "node_type": "process",
                "pid": pid,
                "window_ids": window_ids,
                "window_id": "",
                "title": comm_display,
                "details": "",
            }
            depth_map[process_node_id] = depth

            child_processes = process_children.get(pid, [])
            self.rooted_visible_process_children[pid] = list(child_processes)

            for child_pid in child_processes:
                child_map[process_node_id].append("g_pid_{}".format(child_pid))

            for seq, window in enumerate(windows, 1):
                window_id = window.get("WINDOW_ID", "")
                wm_class_first = wm_class_first_field(window.get("WM_CLASS", ""))
                wm_class_display = wm_class_first if str(wm_class_first).strip() else (window_id or "Window {}".format(seq))
                window_node_id = "g_win_{}_{}".format(pid, seq)
                node_specs[window_node_id] = {
                    "node_type": "window",
                    "pid": pid,
                    "window_ids": [window_id] if window_id else [],
                    "window_id": window_id,
                    "title": wm_class_display,
                    "details": "",
                }
                child_map[process_node_id].append(window_node_id)
                depth_map[window_node_id] = depth + 1

        if not root_node_id:
            return

        levels = defaultdict(list)
        queue = [root_node_id]
        seen = set()

        while queue:
            node_id = queue.pop(0)

            if node_id in seen:
                continue

            seen.add(node_id)
            depth = depth_map.get(node_id, 0)
            levels[depth].append(node_id)
            queue.extend(child_map.get(node_id, []))

        if not levels:
            return

        for spec in node_specs.values():
            if spec["node_type"] == "window":
                width = GRAPH_WINDOW_NODE_WIDTH
                height = GRAPH_WINDOW_NODE_HEIGHT
            else:
                _, _, _, width, height = self.graph_node_text_and_size(spec["title"], spec["details"])
            spec["width"] = width
            spec["height"] = height

        def level_total_width(node_ids):
            if not node_ids:
                return 0
            return (
                sum(node_specs[node_id]["width"] for node_id in node_ids)
                + max(0, len(node_ids) - 1) * GRAPH_NODE_X_GAP
            )

        level_heights = {
            depth: max(node_specs[node_id]["height"] for node_id in node_ids)
            for depth, node_ids in levels.items()
        }
        max_level_width = max(level_total_width(items) for items in levels.values())
        current_y = GRAPH_START_Y

        for depth in sorted(levels.keys()):
            node_ids = levels[depth]
            level_width = level_total_width(node_ids)
            start_x = GRAPH_LAYOUT_MARGIN_X + (max_level_width - level_width) / 2
            y = current_y
            x = start_x

            for node_id in node_ids:
                spec = node_specs[node_id]
                self.create_graph_node(
                    node_id,
                    spec["node_type"],
                    spec["pid"],
                    spec["window_ids"],
                    x,
                    y,
                    spec["title"],
                    spec["details"],
                    spec["width"],
                    spec["height"],
                    spec.get("window_id", ""),
                )
                x += spec["width"] + GRAPH_NODE_X_GAP
            current_y += level_heights[depth] + GRAPH_LEVEL_Y_GAP

        for parent_node_id, child_node_ids in child_map.items():
            for child_node_id in child_node_ids:
                self.create_graph_edge(parent_node_id, child_node_id)

        self.graph_canvas.configure(scrollregion=self.graph_canvas.bbox("all"))
        self.schedule_rooted_window_thumbnails()

    def build_initial_tree(self):
        self.clear_display_state()

        if self.view_mode == "rooted":
            self.build_rooted_graph()
        else:
            self.build_chain_tree()

        self.configure_tree_display_mode()

    def configure_tree_display_mode(self):
        if self.view_mode == "rooted":
            self.tree.grid_remove()
            self.tree_yscroll.grid_remove()
            self.tree_xscroll.grid_remove()
            self.graph_canvas.grid(row=0, column=0, sticky="nsew")
            self.graph_yscroll.grid(row=0, column=1, sticky="ns")
            self.graph_xscroll.grid(row=1, column=0, sticky="ew")
        else:
            self.graph_canvas.grid_remove()
            self.graph_yscroll.grid_remove()
            self.graph_xscroll.grid_remove()
            self.tree.grid(row=0, column=0, sticky="nsew")
            self.tree_yscroll.grid(row=0, column=1, sticky="ns")
            self.tree_xscroll.grid(row=1, column=0, sticky="ew")
            self.tree.configure(show="tree headings")

    def update_view_toggle_text(self):
        if self.view_mode == "chain":
            self.view_toggle_text.set("Switch to Rooted Tree View")
        else:
            self.view_toggle_text.set("Switch to Ancestor Chain View")

    def toggle_view_mode(self):
        self.view_mode = "rooted" if self.view_mode == "chain" else "chain"
        self.update_view_toggle_text()
        self.build_initial_tree()

    def get_selected_item(self):
        if self.view_mode == "rooted":
            return self.graph_selected_node

        selected = self.tree.selection()

        if not selected:
            return None

        return selected[0]

    def get_selected_pid(self):
        item = self.get_selected_item()

        if not item:
            return None

        if self.view_mode == "rooted":
            return self.graph_node_pid.get(item)

        return self.row_pid.get(item)

    def get_selected_window_ids(self):
        item = self.get_selected_item()

        if not item:
            return []

        if self.view_mode == "rooted":
            return self.graph_node_window_ids.get(item, [])

        return self.row_window_ids.get(item, [])

    def is_window_item(self, item):
        if self.view_mode == "rooted":
            return self.graph_node_type.get(item) == "window"

        return self.row_type.get(item) == "window"

    def activate_selected(self):
        item = self.get_selected_item()

        if item is None or item in self.killed_rows:
            return

        window_ids = self.get_selected_window_ids()

        if not window_ids:
            return

        # Only window rows get auto-grayed on failure. A process row's first
        # window being gone doesn't mean the process is dead.
        is_window_row = self.is_window_item(item)

        def on_done(ok, item=item):
            if ok or not is_window_row:
                return
            self.root.after(0, self.mark_row_dead, item)

        activate_window_async(
            window_ids[0],
            self.activate_mode,
            on_done=on_done,
        )

    def mark_row_dead(self, item):
        if item in self.killed_rows:
            return

        if item in self.graph_node_canvas_items:
            self.killed_rows.add(item)
            for canvas_item in self.graph_node_canvas_items.get(item, []):
                canvas_item_type = self.graph_canvas.type(canvas_item)
                if canvas_item_type in CANVAS_ITEM_TYPES_SUPPORTING_FILL:
                    self.graph_canvas.itemconfigure(canvas_item, fill=GRAPH_DEAD_ITEM_COLOR)
            return

        if not self.tree.exists(item):
            return

        self.killed_rows.add(item)
        self.tree.item(item, tags=("killed",))

    def select_graph_node(self, node_id):
        if self.graph_selected_node in self.graph_node_canvas_items:
            items = self.graph_node_canvas_items[self.graph_selected_node]
            node_type = self.graph_node_type.get(self.graph_selected_node)
            normal_outline = (
                GRAPH_PROCESS_OUTLINE_COLOR
                if node_type == "process"
                else GRAPH_WINDOW_OUTLINE_COLOR
            )
            self.graph_canvas.itemconfigure(items[0], outline=normal_outline, width=GRAPH_NODE_OUTLINE_WIDTH)

        self.graph_selected_node = node_id

        if not node_id:
            return

        items = self.graph_node_canvas_items.get(node_id, [])

        if items:
            self.graph_canvas.itemconfigure(
                items[0],
                outline=GRAPH_SELECTION_OUTLINE_COLOR,
                width=GRAPH_SELECTION_OUTLINE_WIDTH,
            )

    def graph_node_at_event(self, event):
        canvas = self.graph_canvas
        x = canvas.canvasx(event.x)
        y = canvas.canvasy(event.y)

        # Tk returns overlapping canvas items in stacking order; text and its
        # rectangle share the same node_id, so the first node hit is sufficient.
        for canvas_item in canvas.find_overlapping(x, y, x, y):
            node_id = self.graph_canvas_item_node.get(canvas_item)

            if node_id:
                return node_id

        return None

    def move_graph_node(self, node_id, dx, dy):
        if not node_id or node_id not in self.graph_node_canvas_items:
            return

        for canvas_item in self.graph_node_canvas_items.get(node_id, []):
            self.graph_canvas.move(canvas_item, dx, dy)

        box = self.graph_node_boxes.get(node_id)

        if box:
            self.graph_node_boxes[node_id] = (
                box[0] + dx,
                box[1] + dy,
                box[2] + dx,
                box[3] + dy,
            )

        self.redraw_graph_edges_for_node(node_id)

    def on_graph_press(self, event):
        node_id = self.graph_node_at_event(event)
        self.select_graph_node(node_id)

        if not node_id:
            self.graph_drag_node = None
            self.graph_drag_last_xy = None
            return

        self.graph_drag_node = node_id
        self.graph_drag_last_xy = (
            self.graph_canvas.canvasx(event.x),
            self.graph_canvas.canvasy(event.y),
        )

    def on_graph_drag(self, event):
        if not self.graph_drag_node or not self.graph_drag_last_xy:
            return

        current = (
            self.graph_canvas.canvasx(event.x),
            self.graph_canvas.canvasy(event.y),
        )
        dx = current[0] - self.graph_drag_last_xy[0]
        dy = current[1] - self.graph_drag_last_xy[1]

        if dx == 0 and dy == 0:
            return

        self.move_graph_node(self.graph_drag_node, dx, dy)
        self.graph_drag_last_xy = current

    def on_graph_release(self, event):
        self.graph_drag_node = None
        self.graph_drag_last_xy = None

    def on_graph_double_click(self, event):
        self.select_graph_node(self.graph_node_at_event(event))
        self.activate_selected()

    def on_graph_right_click(self, event):
        tk = self.tk
        node_id = self.graph_node_at_event(event)

        if not node_id:
            return

        self.select_graph_node(node_id)

        node_type = self.graph_node_type.get(node_id)

        if node_type == "process":
            pid = self.graph_node_pid.get(node_id)
            if pid is None:
                return

            menu = tk.Menu(self.root, tearoff=0)
            visible_process_children = self.rooted_visible_process_children.get(pid, [])

            if visible_process_children:
                is_expanded = (
                    pid in self.rooted_expanded_direct_pids
                    or pid in self.rooted_expanded_all_pids
                )
                is_expanded_all = pid in self.rooted_expanded_all_pids
                label_one = "Collapse" if is_expanded else "Expand"
                label_all = "Collapse All" if is_expanded_all else "Expand All"

                menu.add_command(
                    label=label_one,
                    command=lambda node_id=node_id: self.toggle_rooted_expand_node(node_id),
                )
                menu.add_command(
                    label=label_all,
                    command=lambda node_id=node_id: self.toggle_rooted_expand_all_node(node_id),
                )
                menu.add_separator()

            menu.add_command(
                label="Expand direct child processes",
                command=lambda node_id=node_id: self.expand_rooted_direct_node(node_id),
            )
            menu.add_command(
                label="Expand all descendant processes",
                command=lambda node_id=node_id: self.expand_rooted_all_node(node_id),
            )
            menu.add_separator()
            menu.add_command(
                label="Activate first related window",
                command=self.activate_selected,
            )
        elif node_type == "window":
            if node_id in self.killed_rows:
                return

            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(
                label="Activate this window",
                command=self.activate_selected,
            )
            menu.add_separator()
            menu.add_command(
                label="xkill this window",
                command=lambda node_id=node_id: self.xkill_graph_window_node(node_id),
            )
        else:
            return

        menu.tk_popup(event.x_root, event.y_root)

    def rooted_descendants(self, root_pid):
        descendants = set()
        queue = [root_pid]

        while queue:
            pid = queue.pop(0)

            for child_pid in self.context["children"].get(pid, []):
                if child_pid in descendants:
                    continue

                descendants.add(child_pid)
                queue.append(child_pid)

        return descendants

    def collapse_rooted_pid(self, pid):
        self.rooted_expanded_direct_pids.discard(pid)
        self.rooted_expanded_all_pids.discard(pid)

        for child_pid in self.rooted_descendants(pid):
            self.rooted_expanded_direct_pids.discard(child_pid)
            self.rooted_expanded_all_pids.discard(child_pid)

    def rerender_rooted_graph(self):
        if self.view_mode != "rooted":
            return

        self.build_initial_tree()

    def expand_rooted_direct_pid(self, pid):
        if pid is None:
            return

        self.rooted_expanded_all_pids.discard(pid)
        self.rooted_expanded_direct_pids.add(pid)
        self.rerender_rooted_graph()

    def expand_rooted_all_pid(self, pid):
        if pid is None:
            return

        self.rooted_expanded_direct_pids.discard(pid)
        self.rooted_expanded_all_pids.add(pid)
        self.rerender_rooted_graph()

    def toggle_rooted_expand_pid(self, pid):
        if pid is None:
            return

        if pid in self.rooted_expanded_direct_pids or pid in self.rooted_expanded_all_pids:
            self.collapse_rooted_pid(pid)
            self.rerender_rooted_graph()
            return

        self.expand_rooted_direct_pid(pid)

    def toggle_rooted_expand_all_pid(self, pid):
        if pid is None:
            return

        if pid in self.rooted_expanded_all_pids:
            self.collapse_rooted_pid(pid)
            self.rerender_rooted_graph()
            return

        self.expand_rooted_all_pid(pid)

    def expand_rooted_direct_node(self, node_id):
        self.expand_rooted_direct_pid(self.graph_node_pid.get(node_id))

    def expand_rooted_all_node(self, node_id):
        self.expand_rooted_all_pid(self.graph_node_pid.get(node_id))

    def toggle_rooted_expand_node(self, node_id):
        self.toggle_rooted_expand_pid(self.graph_node_pid.get(node_id))

    def toggle_rooted_expand_all_node(self, node_id):
        self.toggle_rooted_expand_all_pid(self.graph_node_pid.get(node_id))

    def sync_graph_node_boxes_from_canvas(self):
        for node_id, items in self.graph_node_canvas_items.items():
            if not items:
                continue

            coords = self.graph_canvas.coords(items[0])
            if len(coords) == 4:
                self.graph_node_boxes[node_id] = tuple(coords)

    def on_graph_mousewheel(self, event):
        if not self.graph_node_canvas_items:
            return

        if getattr(event, "num", None) in (4, 5):
            zoom_in = event.num == 4
        else:
            zoom_in = getattr(event, "delta", 0) > 0

        factor = GRAPH_ZOOM_STEP if zoom_in else (1.0 / GRAPH_ZOOM_STEP)
        new_zoom = max(GRAPH_ZOOM_MIN, min(GRAPH_ZOOM_MAX, self.graph_zoom * factor))
        applied = new_zoom / self.graph_zoom

        if abs(applied - 1.0) < GRAPH_ZOOM_EPSILON:
            return

        # Record canvas coords of the mouse BEFORE scaling (the zoom anchor).
        # canvas.scale() preserves this point in canvas coordinate space —
        # it remains at the same canvas coordinate (cx, cy) after the transform.
        cx = self.graph_canvas.canvasx(event.x)
        cy = self.graph_canvas.canvasy(event.y)
        self.graph_canvas.scale("all", cx, cy, applied, applied)
        self.graph_zoom = new_zoom
        self.sync_graph_node_boxes_from_canvas()

        # Update scrollregion to cover all scaled items.
        bbox = self.graph_canvas.bbox("all")
        if not bbox:
            return

        self.graph_canvas.configure(scrollregion=bbox)

        # Updating the scrollregion can cause Tkinter to clamp/shift the view
        # (e.g. when the old view position falls outside the new, smaller
        # scrollregion after a zoom-out).  Restore the viewport explicitly so
        # that the zoom anchor (cx, cy) stays exactly under the mouse cursor.
        #
        # The left canvas edge shown in the viewport must equal (cx - event.x)
        # so that canvas coord cx lines up with widget coord event.x.
        # xview_moveto takes a fraction: (desired_left - sr_x1) / sr_width.
        scrollregion_x1, scrollregion_y1, scrollregion_x2, scrollregion_y2 = bbox
        scrollregion_width = scrollregion_x2 - scrollregion_x1
        scrollregion_height = scrollregion_y2 - scrollregion_y1

        if scrollregion_width > 0:
            viewport_x_fraction = max(0.0, (cx - event.x - scrollregion_x1) / scrollregion_width)
            self.graph_canvas.xview_moveto(viewport_x_fraction)

        if scrollregion_height > 0:
            viewport_y_fraction = max(0.0, (cy - event.y - scrollregion_y1) / scrollregion_height)
            self.graph_canvas.yview_moveto(viewport_y_fraction)

    def on_graph_pan_start(self, event):
        self.graph_pan_active = True
        self.graph_canvas.scan_mark(event.x, event.y)

    def on_graph_pan_drag(self, event):
        if not self.graph_pan_active:
            return

        self.graph_canvas.scan_dragto(event.x, event.y, gain=1)

    def on_graph_pan_end(self, event):
        self.graph_pan_active = False

    def xkill_window_row(self, item):
        if not item or item in self.killed_rows:
            return

        if self.row_type.get(item) != "window":
            return

        window_ids = self.row_window_ids.get(item, [])
        if not window_ids:
            return

        # Gray out immediately; xkill runs in background.
        self.killed_rows.add(item)
        self.tree.item(item, tags=("killed",))
        self.mark_window_thumbnail_missing(window_ids[0])

        xkill_window_async(window_ids[0])

    def xkill_graph_window_node(self, node_id):
        if not node_id or node_id in self.killed_rows:
            return

        if self.graph_node_type.get(node_id) != "window":
            return

        window_ids = self.graph_node_window_ids.get(node_id, [])
        if not window_ids:
            return

        self.mark_row_dead(node_id)
        self.mark_window_thumbnail_missing(window_ids[0])
        xkill_window_async(window_ids[0])

    def on_double_click(self, event):
        item = self.tree.identify_row(event.y)

        if item:
            self.tree.selection_set(item)

        self.activate_selected()

    def visible_window_ids(self):
        window_ids = []
        source = self.graph_node_window_ids if self.view_mode == "rooted" else self.row_window_ids

        for item in source:
            for window_id in source.get(item, []):
                if window_id and window_id not in window_ids:
                    window_ids.append(window_id)

        return window_ids

    def flash_visible_windows(self):
        window_ids = self.visible_window_ids()

        threading.Thread(
            target=flash_window_ids,
            kwargs={
                "window_ids": window_ids,
                "rounds": self.flash_rounds,
                "interval": self.flash_interval,
                "mode": self.activate_mode,
                "restore_focus": self.restore_focus,
            },
            daemon=True,
        ).start()

    def expand_direct_children(self, item):
        if not item:
            return

        if self.view_mode == "rooted":
            if self.graph_node_type.get(item) != "process":
                return
            self.expand_rooted_direct_node(item)
            return

        if self.row_type.get(item) != "process":
            return

        pid = self.row_pid.get(item)
        if pid is None:
            return

        children = self.context["children"].get(pid, [])

        for child_pid in children:
            self.insert_process_row(
                pid=child_pid,
                parent_item=item,
                role_hint="child",
                open_item=False,
            )

        self.tree.item(item, open=True)

    def expand_all_descendants(self, item):
        if not item:
            return

        if self.view_mode == "rooted":
            if self.graph_node_type.get(item) != "process":
                return
            self.expand_rooted_all_node(item)
            return

        if self.row_type.get(item) != "process":
            return

        root_pid = self.row_pid.get(item)
        if root_pid is None:
            return

        def recurse(parent_item, pid, depth):
            if depth > MAX_TREE_NODES:
                return

            children = self.context["children"].get(pid, [])

            for child_pid in children:
                child_item = self.insert_process_row(
                    pid=child_pid,
                    parent_item=parent_item,
                    role_hint="descendant",
                    open_item=False,
                )

                if child_item:
                    recurse(child_item, child_pid, depth + 1)

        recurse(item, root_pid, 0)
        self.tree.item(item, open=True)

    def expand_selected_direct_children(self):
        self.expand_direct_children(self.get_selected_item())

    def expand_selected_all_descendants(self):
        self.expand_all_descendants(self.get_selected_item())

    def get_selected_process_pid(self):
        item = self.get_selected_item()

        if not item:
            return None

        if self.view_mode == "rooted":
            if self.graph_node_type.get(item) != "process":
                return None
            return self.graph_node_pid.get(item)

        if self.row_type.get(item) != "process":
            return None

        return self.row_pid.get(item)

    def process_item_for_pid(self, pid):
        if pid is None:
            return None

        if self.view_mode == "rooted":
            for node_id, node_pid in self.graph_node_pid.items():
                if (
                    node_pid == pid
                    and self.graph_node_type.get(node_id) == "process"
                ):
                    return node_id
            return None

        return self.pid_item.get(pid)

    def refresh_then_expand_selected_direct_children(self):
        pid = self.get_selected_process_pid()

        if pid is None:
            return

        self.refresh_all()
        process_item = self.process_item_for_pid(pid)
        self.expand_direct_children(process_item)

    def refresh_then_expand_selected_all_descendants(self):
        pid = self.get_selected_process_pid()

        if pid is None:
            return

        self.refresh_all()
        process_item = self.process_item_for_pid(pid)
        self.expand_all_descendants(process_item)

    def row_is_open(self, item):
        # Tk may return "0"/"1" strings, ints, or bools depending on version —
        # bool("0") is True, so normalize via str() first.
        return str(self.tree.item(item, "open")).lower() in ("1", "true")

    def toggle_expand_row(self, item):
        if not item:
            return
        self.tree.item(item, open=not self.row_is_open(item))

    def set_open_recursive(self, item, target):
        self.tree.item(item, open=target)
        for child in self.tree.get_children(item):
            self.set_open_recursive(child, target)

    def toggle_expand_all_rows(self, item):
        if not item:
            return
        target = not self.row_is_open(item)
        self.set_open_recursive(item, target)

    def on_right_click(self, event):
        tk = self.tk

        item = self.tree.identify_row(event.y)

        if not item:
            return

        self.tree.selection_set(item)

        row_type = self.row_type.get(item)

        if row_type == "process":
            menu = tk.Menu(self.root, tearoff=0)

            if self.tree.get_children(item):
                is_open = self.row_is_open(item)
                label_one = "Collapse" if is_open else "Expand"
                label_all = "Collapse All" if is_open else "Expand All"

                menu.add_command(
                    label=label_one,
                    command=lambda item=item: self.toggle_expand_row(item),
                )

                menu.add_command(
                    label=label_all,
                    command=lambda item=item: self.toggle_expand_all_rows(item),
                )

                menu.add_separator()

            menu.add_command(
                label="Expand direct child processes",
                command=lambda item=item: self.expand_direct_children(item),
            )

            menu.add_command(
                label="Expand all descendant processes",
                command=lambda item=item: self.expand_all_descendants(item),
            )

            menu.add_separator()

            menu.add_command(
                label="Activate first related window",
                command=self.activate_selected,
            )

        elif row_type == "window":
            if item in self.killed_rows:
                return

            menu = tk.Menu(self.root, tearoff=0)

            menu.add_command(
                label="Activate this window",
                command=self.activate_selected,
            )

            menu.add_separator()

            menu.add_command(
                label="xkill this window",
                command=lambda item=item: self.xkill_window_row(item),
            )

        else:
            return

        menu.tk_popup(event.x_root, event.y_root)

    def refresh_all(self):
        new_context = self.reload_callback()
        self.context.clear()
        self.context.update(new_context)
        self.thumbnail_cache.clear()
        self.thumbnail_inflight.clear()
        valid_pids = set(self.context["procs"].keys())
        self.rooted_expanded_direct_pids = set(
            pid for pid in self.rooted_expanded_direct_pids if pid in valid_pids
        )
        self.rooted_expanded_all_pids = set(
            pid for pid in self.rooted_expanded_all_pids if pid in valid_pids
        )
        self.build_initial_tree()


def load_context(
    seed_props,
    machine,
    seed_pid,
    host_match_mode,
    ssh_connect_timeout,
    ssh_batch_mode,
):
    remote_hostname = fetch_remote_hostname(
        machine,
        ssh_connect_timeout,
        ssh_batch_mode,
    )

    ps_output = fetch_remote_process_table(
        machine,
        ssh_connect_timeout,
        ssh_batch_mode,
    )

    procs, children = parse_ps_output(ps_output)

    if seed_pid not in procs:
        raise RuntimeError(
            "The seed PID from the clicked window was not found on the remote host.\n\n"
            "Remote host: {}\n"
            "Seed PID   : {}\n\n"
            "Possible reasons:\n"
            "1. The process has exited.\n"
            "2. WM_CLIENT_MACHINE does not match the real SSH host.\n"
            "3. _NET_WM_PID is stale.".format(machine, seed_pid)
        )

    ancestor_chain = build_ancestor_chain_to_pid1(seed_pid, procs)

    pid_to_windows, all_windows = enumerate_x_clients_for_machine(
        machine,
        host_match_mode,
    )

    return {
        "seed_props": seed_props,
        "machine": machine,
        "remote_hostname": remote_hostname,
        "seed_pid": seed_pid,
        "procs": procs,
        "children": children,
        "ancestor_chain": ancestor_chain,
        "pid_to_windows": pid_to_windows,
        "all_windows": all_windows,
    }


def launch_gui(
    context,
    activate_mode,
    flash_rounds,
    flash_interval,
    restore_focus,
    reload_callback,
):
    try:
        import tkinter as tk
    except Exception as exc:
        raise RuntimeError(
            "Python tkinter is not available. Please install the Tkinter package "
            "that matches your Python 3 installation.\n\n{}".format(exc)
        )

    root = tk.Tk()

    XClientTreeApp(
        root=root,
        context=context,
        activate_mode=activate_mode,
        flash_rounds=flash_rounds,
        flash_interval=flash_interval,
        restore_focus=restore_focus,
        reload_callback=reload_callback,
    )

    root.mainloop()


def main():
    parser = argparse.ArgumentParser(
        description="Click one X11 window, build a remote process tree, and manage related X Client windows."
    )

    parser.add_argument(
        "--host-match",
        choices=["strict", "loose"],
        default=DEFAULT_HOST_MATCH_MODE,
        help="Hostname matching mode for WM_CLIENT_MACHINE.",
    )

    parser.add_argument(
        "--activate-mode",
        choices=["activate", "raise", "focus"],
        default=DEFAULT_ACTIVATE_MODE,
        help="Action used when activating a selected X Client window.",
    )

    parser.add_argument(
        "--flash-rounds",
        type=int,
        default=DEFAULT_FLASH_ROUNDS,
        help="Number of rounds used by Flash Visible Windows.",
    )

    parser.add_argument(
        "--flash-interval",
        type=float,
        default=DEFAULT_FLASH_INTERVAL,
        help="Seconds between window activations when flashing visible windows.",
    )

    parser.add_argument(
        "--restore-focus",
        action="store_true",
        help="Restore the originally active window after flashing windows.",
    )

    parser.add_argument(
        "--ssh-connect-timeout",
        type=int,
        default=DEFAULT_SSH_CONNECT_TIMEOUT,
        help="SSH connect timeout in seconds.",
    )

    parser.add_argument(
        "--ssh-batch-mode",
        choices=["yes", "no"],
        default=DEFAULT_SSH_BATCH_MODE,
        help="SSH BatchMode. yes means no password prompt.",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print discovered context and exit without opening the GUI.",
    )

    args = parser.parse_args()

    for cmd in ["xprop", "ssh", "xdotool", "xkill"]:
        if not command_exists(cmd):
            show_error(
                "Missing command: {}\n\n"
                "Please install it on the local Xfce desktop host.".format(cmd)
            )
            return 1

    try:
        seed_props = get_xprop_from_clicked_window()

        machine = normalize_host(seed_props.get("WM_CLIENT_MACHINE", ""))
        seed_pid = seed_props.get("_NET_WM_PID", None)

        if not machine or not seed_pid:
            raise RuntimeError(
                "The clicked window does not provide a valid WM_CLIENT_MACHINE or _NET_WM_PID.\n\n"
                "WM_CLIENT_MACHINE = {}\n"
                "_NET_WM_PID       = {}\n\n"
                "Possible reasons:\n"
                "1. The clicked object is not the real application client window.\n"
                "2. The application did not set _NET_WM_PID.\n"
                "3. The window is not an X11 client window.".format(
                    seed_props.get("WM_CLIENT_MACHINE", ""),
                    seed_props.get("_NET_WM_PID", ""),
                )
            )

        def reload_callback():
            return load_context(
                seed_props=seed_props,
                machine=machine,
                seed_pid=seed_pid,
                host_match_mode=args.host_match,
                ssh_connect_timeout=args.ssh_connect_timeout,
                ssh_batch_mode=args.ssh_batch_mode,
            )

        context = reload_callback()

        print_console_summary(
            seed_props=seed_props,
            machine=machine,
            remote_hostname=context["remote_hostname"],
            seed_pid=seed_pid,
            procs=context["procs"],
            ancestor_chain=context["ancestor_chain"],
            pid_to_windows=context["pid_to_windows"],
        )

        if args.dry_run:
            return 0

        launch_gui(
            context=context,
            activate_mode=args.activate_mode,
            flash_rounds=args.flash_rounds,
            flash_interval=args.flash_interval,
            restore_focus=args.restore_focus,
            reload_callback=reload_callback,
        )

        return 0

    except Exception as exc:
        show_error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
