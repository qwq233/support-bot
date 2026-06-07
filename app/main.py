import asyncio

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.redis import RedisStorage

from .bot import commands
from .bot.handlers import include_routers
from .bot.middlewares import register_middlewares
from .bot.utils.captcha import CaptchaService
from .bot.utils.redis import RedisStorage as UserRedisStorage
from .config import load_config, Config
from .logger import setup_logger


async def on_shutdown(
    dispatcher: Dispatcher,
    config: Config,
    bot: Bot,
    captcha_service: CaptchaService,
) -> None:
    """
    Shutdown event handler. This runs when the bot shuts down.

    :param dispatcher: Dispatcher: The bot dispatcher.
    :param config: Config: The config instance.
    :param bot: Bot: The bot instance.
    """
    # Stop captcha web server
    await captcha_service.stop()
    # Delete commands and close storage when shutting down
    await commands.delete(bot, config)
    await dispatcher.storage.close()
    await bot.delete_webhook()
    await bot.session.close()


async def on_startup(
    config: Config,
    bot: Bot,
    captcha_service: CaptchaService,
) -> None:
    """
    Startup event handler. This runs when the bot starts up.

    :param config: Config: The config instance.
    :param bot: Bot: The bot instance.
    """
    # Setup commands when starting up
    await commands.setup(bot, config)
    # Start captcha web server when enabled
    await captcha_service.start()


async def main() -> None:
    """
    Main function that initializes the bot and starts the event loop.
    """
    # Load config
    config = load_config()

    # Initialize Redis storage
    storage = RedisStorage.from_url(
        url=config.redis.dsn(),
    )

    # Create Bot and Dispatcher instances
    bot = Bot(
        token=config.bot.TOKEN,
        default=DefaultBotProperties(
            parse_mode=ParseMode.HTML,
        ),
    )
    captcha_service = CaptchaService(
        config=config,
        bot=bot,
        redis=UserRedisStorage(storage.redis),
    )
    dp = Dispatcher(
        storage=storage,
        config=config,
        bot=bot,
        captcha_service=captcha_service,
    )

    # Register startup handler
    dp.startup.register(on_startup)
    # Register shutdown handler
    dp.shutdown.register(on_shutdown)

    # Include routes
    include_routers(dp)
    # Register middlewares
    register_middlewares(
        dp,
        config=config,
        redis=storage.redis,
        captcha_service=captcha_service,
    )

    # Start the bot
    await bot.delete_webhook()
    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())


if __name__ == "__main__":
    # Set up logging
    setup_logger()
    # Run the bot
    asyncio.run(main())
