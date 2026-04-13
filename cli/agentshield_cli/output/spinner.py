"""Loading spinners for CLI long operations."""
from __future__ import annotations

import sys
import threading
import time
from contextlib import contextmanager
from typing import Optional

SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class Spinner:
    """
    Context manager / callable for terminal spinners.

    Usage::

        with Spinner("Loading data..."):
            time.sleep(2)

        # Or as a context manager with status updates:
        with Spinner("Processing...") as spinner:
            for i in range(100):
                spinner.update(f"Processing item {i}...")
                time.sleep(0.01)
    """

    def __init__(self, message: str = "", delay: float = 0.1) -> None:
        self.message = message
        self.delay = delay
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._current_message = message

    def __enter__(self) -> "Spinner":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop(success=exc_type is None)

    def start(self) -> None:
        """Start the spinner."""
        if not sys.stdout.isatty():
            print(self.message)
            return
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self, success: bool = True) -> None:
        """Stop the spinner."""
        if not sys.stdout.isatty():
            return
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)
        sys.stdout.write("\r\033[K")  # Clear line
        if success:
            try:
                from rich.console import Console
                Console().print(f"[green]✓[/green] {self._current_message}")
            except ImportError:
                print(f"✓ {self._current_message}")
        sys.stdout.flush()

    def update(self, message: str) -> None:
        """Update the spinner message."""
        self._current_message = message

    def _spin(self) -> None:
        i = 0
        while self._running:
            frame = SPINNER_FRAMES[i % len(SPINNER_FRAMES)]
            sys.stdout.write(f"\r{frame} {self._current_message}")
            sys.stdout.flush()
            time.sleep(self.delay)
            i += 1
