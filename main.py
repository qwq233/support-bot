import asyncio
from app.main import main
from app.logger import setup_logger

if __name__ == "__main__":
    setup_logger()
    asyncio.run(main())
