# X11 Related Client Finder

Click any X11 window on your desktop, and this tool will SSH to the remote host that owns it, walk the process ancestry up to PID 1, and show every related X Client window grouped under its process — all in an interactive Tk tree.

Powered by [www.icinfra.cn](https://www.icinfra.cn).

## What it does

1. You click a target window. `xprop` reads its `WM_CLIENT_MACHINE` and `_NET_WM_PID`.
2. The tool SSHes to that machine and reads the full process table (`ps -eo pid,ppid,user,stat,comm,args`).
3. It builds the ancestor PID chain from the clicked PID up to PID 1.
4. It enumerates all top-level X windows on the local display, keeps the ones whose `WM_CLIENT_MACHINE` matches the same remote host, and groups them by PID.
5. A Tk GUI shows the ancestor chain as a tree, with related X Client windows attached under each process row.

From the GUI you can:

- **Double-click** a window row (or a process row that owns windows) to bring that GUI window to the front.
- **Right-click** a process row to expand its direct children or all descendants.
- **Flash Visible Windows** to cycle activation across every window currently shown in the tree.
- **Switch View Mode** to toggle the same ancestor-chain data between table-style rows and a rooted node-link tree view.
- **Refresh All** to re-read the remote process table without re-picking the seed window.

## Requirements

**Local host** (where you run the script — typically an Xfce/X11 desktop):

- Python 3 with `tkinter`
- `xprop`
- `xdotool`
- `ssh`
- Optional: `zenity` or `xmessage` for nicer info/error dialogs

**Remote host** (the one named by `WM_CLIENT_MACHINE`):

- `ps` (POSIX `-eo` format)
- Reachable via `ssh` with key-based auth if you keep `--ssh-batch-mode yes`
- Login shell is invoked as `/bin/sh -lc ...`, so `csh`/`tcsh` users are fine

## Usage

```sh
python3 x11_related_cleints_tree.py
```

After launch, click the target application window when prompted. A console summary is printed, and the GUI opens.

### Common options

| Option | Default | Description |
| --- | --- | --- |
| `--host-match {strict,loose}` | `loose` | `loose` also matches on the short hostname (before the first dot). |
| `--activate-mode {activate,raise,focus}` | `activate` | `xdotool` action used to bring a window to the front. |
| `--flash-rounds N` | `1` | How many times "Flash Visible Windows" cycles through every visible window. |
| `--flash-interval S` | `0.45` | Seconds between activations during flashing. |
| `--restore-focus` | off | After flashing, restore the previously active window. |
| `--ssh-connect-timeout N` | `8` | Passed to `ssh -o ConnectTimeout=`. |
| `--ssh-batch-mode {yes,no}` | `yes` | `yes` disables interactive SSH password prompts. |
| `--dry-run` | off | Print the discovered context and exit without opening the GUI. |

### Example

```sh
python3 x11_related_cleints_tree.py \
    --host-match strict \
    --activate-mode raise \
    --flash-rounds 2 \
    --restore-focus
```

## Troubleshooting

- **"The clicked window does not provide a valid WM_CLIENT_MACHINE or _NET_WM_PID."** The app you clicked did not set `_NET_WM_PID`, or you clicked decoration/root instead of the real client window. Try clicking the application's main content area.
- **"The seed PID from the clicked window was not found on the remote host."** Either the process exited, `WM_CLIENT_MACHINE` doesn't match the real SSH-reachable hostname (try `--host-match loose` or fix DNS), or `_NET_WM_PID` is stale.
- **SSH fails with no output.** With `--ssh-batch-mode yes` (default), no password prompt is shown. Set up key-based auth, or pass `--ssh-batch-mode no`.
- **`tkinter` import error.** Install the Tk bindings for your Python 3 (e.g. `python3-tk` on Debian/Ubuntu, `python3-tkinter` on RHEL).

## Files

- [x11_related_cleints_tree.py](x11_related_cleints_tree.py) — the entire tool, single file, standard library only.
