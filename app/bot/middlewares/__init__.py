from aiogram import Dispatcher
from aiogram_newsletter.middleware import AiogramNewsletterMiddleware

from .album import AlbumMiddleware
from .captcha import CaptchaMiddleware
from .manager import ManagerMiddleware
from .redis import RedisMiddleware
from .throttling import ThrottlingMiddleware


def register_middlewares(dp: Dispatcher, **kwargs) -> None:
    """
    Register bot middlewares.

    Args:
        dp (Dispatcher): The Aiogram Dispatcher instance.
        **kwargs: Additional keyword arguments.

    Returns:
        None
    """
    # Register RedisMiddleware with the provided Redis instance
    dp.update.outer_middleware.register(RedisMiddleware(kwargs["redis"]))
    # Register ManagerMiddleware
    dp.update.outer_middleware.register(ManagerMiddleware())
    # Register CaptchaMiddleware
    dp.update.outer_middleware.register(CaptchaMiddleware(kwargs["captcha_service"]))

    # Register AlbumMiddleware for message processing
    dp.message.middleware.register(AlbumMiddleware())
    # Register ThrottlingMiddleware for message processing
    dp.message.middleware.register(ThrottlingMiddleware())

    # Register AiogramNewsletterMiddleware for newsletter processing
    dp.update.middleware.register(AiogramNewsletterMiddleware(kwargs["apscheduler"]))


__all__ = [
    "register_middlewares",
]
