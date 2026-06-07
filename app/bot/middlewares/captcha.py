import asyncio
from contextlib import suppress
from typing import Any, Awaitable, Callable, Dict

from aiogram import BaseMiddleware, Bot
from aiogram.types import CallbackQuery, Message, TelegramObject, User

from app.bot.manager import Manager
from app.bot.utils.captcha import CaptchaService, needs_captcha
from app.bot.utils.redis.models import UserData
from app.bot.utils.texts import TextMessage
from app.config import Config


class CaptchaMiddleware(BaseMiddleware):
    """
    Blocks private user interaction until Cloudflare Turnstile is passed.
    """

    def __init__(self, captcha: CaptchaService) -> None:
        self.captcha = captcha

    async def __call__(
            self,
            handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
            event: TelegramObject,
            data: Dict[str, Any],
    ) -> Any:
        if not self.captcha.enabled:
            return await handler(event, data)

        if not isinstance(event, (Message, CallbackQuery)):
            return await handler(event, data)

        user: User | None = data.get("event_from_user")
        user_data: UserData | None = data.get("user_data")
        manager: Manager | None = data.get("manager")
        config: Config | None = data.get("config")
        bot: Bot | None = data.get("bot")
        if manager is not None:
            config = manager.config
            bot = manager.bot

        if user is None or user_data is None or config is None or bot is None:
            return await handler(event, data)

        if not needs_captcha(config, user.id, user_data):
            return await handler(event, data)

        text_message = TextMessage(user_data.language_code or user.language_code)
        if user_data.is_banned:
            await self.reply_and_delete(event, bot, user.id, text_message.get("captcha_banned"))
            return None

        if not self.captcha.configured:
            await self.reply_and_delete(event, bot, user.id, text_message.get("captcha_unavailable"))
            return None

        url = await self.captcha.get_or_create_challenge_url(
            user_data,
            self.extract_event_text(event),
        )
        if url is None:
            await self.reply_and_delete(event, bot, user.id, text_message.get("captcha_banned"))
            return None

        text = text_message.get("captcha_required").format(url=url)
        await self.reply_and_delete(event, bot, user.id, text)
        return None

    @staticmethod
    def extract_event_text(event: Message | CallbackQuery) -> str | None:
        if isinstance(event, Message):
            return event.text or event.caption
        return None

    @staticmethod
    async def reply_and_delete(
            event: Message | CallbackQuery,
            bot: Bot,
            user_id: int,
            text: str,
            ttl: int = 30,
    ) -> None:
        if isinstance(event, CallbackQuery):
            with suppress(Exception):
                await event.answer()
            message = await bot.send_message(
                chat_id=user_id,
                text=text,
                disable_web_page_preview=True,
            )
        else:
            message = await event.reply(
                text,
                disable_web_page_preview=True,
            )

        asyncio.create_task(CaptchaMiddleware.delete_later(message, ttl))

    @staticmethod
    async def delete_later(message: Message, ttl: int) -> None:
        await asyncio.sleep(ttl)
        with suppress(Exception):
            await message.delete()
