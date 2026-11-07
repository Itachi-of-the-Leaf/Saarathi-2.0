"""Run Saarathi with ``python -m saarathi``."""

import asyncio

from .services.auditor import main


if __name__ == "__main__":
    asyncio.run(main())
