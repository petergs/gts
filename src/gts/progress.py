"""Small progress-reporting abstraction so the enum data layer can show progress without
importing rich or knowing about the terminal.

`operations.py` takes a `Progress` and drives it:

    with progress.task("Service principals", total=len(sps)) as advance:
        ...
        advance()   # once per completed item

The default is `NullProgress` (does nothing), so operations stay UI-agnostic and easy to
test. The CLI passes `for_stderr()`, which renders a rich bar on stderr only when stderr is a
TTY -- enum writes JSON to stdout, so the bar must never touch stdout, and a redirected run
should stay silent.
"""

import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager


class NullProgress:
    """No-op progress. `advance()` does nothing."""

    @contextmanager
    def task(self, description: str, total: int) -> Iterator[Callable[[], None]]:
        yield lambda: None


class RichProgress:
    """Renders a determinate bar on stderr via rich."""

    def __init__(self) -> None:
        from rich.console import Console

        self._console = Console(stderr=True)

    @contextmanager
    def task(self, description: str, total: int) -> Iterator[Callable[[], None]]:
        from rich.progress import (
            BarColumn,
            MofNCompleteColumn,
            Progress,
            TextColumn,
            TimeElapsedColumn,
        )

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self._console,
            transient=True,
        ) as bar:
            task_id = bar.add_task(description, total=total)
            yield lambda: bar.advance(task_id)


def for_stderr() -> NullProgress | RichProgress:
    """A rich bar when stderr is a TTY, else a silent no-op (piped/redirected runs)."""
    return RichProgress() if sys.stderr.isatty() else NullProgress()
