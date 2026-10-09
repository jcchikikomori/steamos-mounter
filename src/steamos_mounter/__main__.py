"""``python -m steamos_mounter`` (development only).

The installed entry point is ``bin/steamos-mounter``. The ``cli`` import stays
inside the guard so the package imports cleanly on its own.
"""

if __name__ == "__main__":
    import sys

    from steamos_mounter.cli import main

    sys.exit(main())
