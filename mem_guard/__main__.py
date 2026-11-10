"""``python -m mem_guard`` entry point."""

from mem_guard.cli import main

__all__ = ["main"]

if __name__ == "__main__":
    raise SystemExit(main())
