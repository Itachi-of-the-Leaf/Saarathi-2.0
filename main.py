"""Backward-compatible executable entry point.

The implementation lives in :mod:`saarathi.services.auditor`; this shim keeps
``python main.py`` and legacy imports working while the repository uses the
package layout.
"""

import asyncio

from saarathi.services.auditor import *  # noqa: F401,F403
from saarathi.services.auditor import main


if __name__ == "__main__":
    asyncio.run(main())
