import asyncio
from app import main
from app.logger import setup_logger

if __name__ == "__main__":
    setup_logger()
    asyncio.run(main())

