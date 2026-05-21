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
import os
import re
import shlex
import shutil
import subprocess
import sys
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

MAX_TREE_NODES = 30000


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

        if current == 1:
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

        self.tk = tk
        self.ttk = ttk

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
        self.view_mode = "chain"
        self.view_toggle_text = tk.StringVar(value="Switch to Rooted Tree View")

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

        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.tree.tag_configure("killed", foreground="gray")

        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Return>", lambda event: self.activate_selected())
        self.tree.bind("<Button-3>", self.on_right_click)
        self.tree.bind("<Button-2>", self.on_right_click)

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
            "Use the switch button to toggle between ancestor-chain view and rooted node-link tree view."
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

    def role_for_pid(self, pid, role_hint=None):
        seed_pid = self.context["seed_pid"]
        ancestor_chain = self.context["ancestor_chain"]
        ancestor_set = set(pid for pid in ancestor_chain if pid != 1)

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
        chain = [pid for pid in chain if pid != 1]
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
        chain = [pid for pid in self.context["ancestor_chain"] if pid != 1]
        seed_root_pid = chain[-1] if chain else self.context["seed_pid"]
        seen = set()

        def top_non_pid1_ancestor(pid):
            if pid not in self.context["procs"]:
                return None

            current = pid
            parent = self.context["procs"][current]["ppid"]

            while parent in self.context["procs"] and parent != 1:
                current = parent
                parent = self.context["procs"][current]["ppid"]

            return current

        def recurse(parent_item, pid):
            if len(seen) > MAX_TREE_NODES or pid in seen:
                return
            seen.add(pid)

            role_hint = "root" if parent_item == "" else "descendant"
            item = self.insert_process_row(
                pid=pid,
                parent_item=parent_item,
                role_hint=role_hint,
                open_item=True,
            )

            if not item:
                return

            for child_pid in self.context["children"].get(pid, []):
                recurse(item, child_pid)

        root_pids = []
        root_pid_seen = set()

        if seed_root_pid:
            root_pids.append(seed_root_pid)
            root_pid_seen.add(seed_root_pid)

        for xclient_pid in sorted(self.context["pid_to_windows"].keys()):
            root_pid = top_non_pid1_ancestor(xclient_pid)
            if root_pid and root_pid not in root_pid_seen:
                root_pids.append(root_pid)
                root_pid_seen.add(root_pid)

        for root_pid in root_pids:
            recurse("", root_pid)

    def build_initial_tree(self):
        self.clear_tree()

        if self.view_mode == "rooted":
            self.build_rooted_tree()
        else:
            self.build_chain_tree()

        self.configure_tree_display_mode()

    def configure_tree_display_mode(self):
        if self.view_mode == "rooted":
            self.tree.configure(show="tree")
        else:
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
        selected = self.tree.selection()

        if not selected:
            return None

        return selected[0]

    def get_selected_pid(self):
        item = self.get_selected_item()

        if not item:
            return None

        return self.row_pid.get(item)

    def get_selected_window_ids(self):
        item = self.get_selected_item()

        if not item:
            return []

        return self.row_window_ids.get(item, [])

    def activate_selected(self):
        item = self.get_selected_item()

        if item is None or item in self.killed_rows:
            return

        window_ids = self.get_selected_window_ids()

        if not window_ids:
            return

        # Only window rows get auto-grayed on failure. A process row's first
        # window being gone doesn't mean the process is dead.
        is_window_row = self.row_type.get(item) == "window"

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
        if not self.tree.exists(item):
            return
        self.killed_rows.add(item)
        self.tree.item(item, tags=("killed",))

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

        xkill_window_async(window_ids[0])

    def on_double_click(self, event):
        item = self.tree.identify_row(event.y)

        if item:
            self.tree.selection_set(item)

        self.activate_selected()

    def visible_window_ids(self):
        window_ids = []

        for item in self.row_window_ids:
            for window_id in self.row_window_ids.get(item, []):
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

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def refresh_all(self):
        new_context = self.reload_callback()
        self.context.clear()
        self.context.update(new_context)
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
