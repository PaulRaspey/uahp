"""Entry point for `python -m uahp`"""
from .mcp_server import main
import asyncio

if __name__ == "__main__":
    asyncio.run(main())
