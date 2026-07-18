"""A tiny arrow-key selection menu.

rich renders the frames, but has no interactive arrow-key selector, so key input is
read directly from the terminal via termios (POSIX). On a non-interactive stdin/stdout
(or non-POSIX), selection is unavailable and callers should fall back to an explicit
argument.
"""

import os
import select as _select
import sys

from rich.live import Live

try:
    import termios

    _HAVE_TERMIOS = True
except ImportError:  # non-POSIX
    _HAVE_TERMIOS = False


def is_interactive() -> bool:
    return _HAVE_TERMIOS and sys.stdin.isatty() and sys.stdout.isatty()


def _read_key(fd: int) -> str | None:
    """Read one logical keypress from a raw fd.

    Returns 'up' | 'down' | 'enter' | 'q' | 'esc' | a single character. Uses
    os.read (not buffered sys.stdin) so escape-sequence disambiguation via select
    works — a buffered reader would slurp the whole sequence and defeat select.
    """
    ch = os.read(fd, 1)
    if ch == b"\x1b":  # escape — maybe an arrow sequence (\x1b[A / \x1bOA)
        ready, _, _ = _select.select([fd], [], [], 0.05)
        if not ready:
            return "esc"
        seq = os.read(fd, 2)
        if seq[:1] in (b"[", b"O") and len(seq) > 1:
            return {ord("A"): "up", ord("B"): "down"}.get(seq[1])
        return None
    if ch in (b"\r", b"\n"):
        return "enter"
    try:
        return ch.decode()
    except UnicodeDecodeError:
        return None


def _apply_key(idx: int, key: str | None, count: int) -> tuple[int, str | None]:
    """Return (new_index, action) where action is None | 'select' | 'cancel'."""
    if key in ("up", "k"):
        return (idx - 1) % count, None
    if key in ("down", "j"):
        return (idx + 1) % count, None
    if key == "enter":
        return idx, "select"
    if key in ("q", "esc"):
        return idx, "cancel"
    return idx, None


def select_index(console, build_renderable, count: int, start: int = 0) -> int | None:
    """Show an interactive menu and return the chosen index, or None if cancelled.

    `build_renderable(index)` returns a rich renderable for the given cursor position.
    Returns None on cancel (q / Esc / Ctrl-C) or when not interactive.
    """
    if count == 0 or not is_interactive():
        return None
    idx = start % count
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        new = termios.tcgetattr(fd)
        new[3] &= ~(termios.ICANON | termios.ECHO)  # keep ISIG so Ctrl-C still works
        new[6][termios.VMIN] = 1
        new[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSANOW, new)
        with Live(
            build_renderable(idx), console=console, auto_refresh=False, transient=True
        ) as live:
            while True:
                try:
                    key = _read_key(fd)
                except KeyboardInterrupt:
                    return None
                idx, action = _apply_key(idx, key, count)
                if action == "select":
                    return idx
                if action == "cancel":
                    return None
                live.update(build_renderable(idx), refresh=True)
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, old)
