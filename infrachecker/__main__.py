"""Entry point: GUI by default, ``--cli`` for terminal mode."""
from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0].lower() == "--cli":
        from .cli import main as cli_main
        return cli_main(argv[1:])
    from .ui.main_window import run_gui
    return run_gui(argv)


if __name__ == "__main__":
    sys.exit(main())
