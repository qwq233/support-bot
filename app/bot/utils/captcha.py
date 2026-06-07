import asyncio
import hashlib
import hmac
import html
import logging
import re
import secrets
import string
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from aiohttp import ClientSession, ClientTimeout, web
from aiogram import Bot
from aiogram.utils.markdown import hbold

from app.bot.utils.create_forum_topic import get_or_create_forum_topic
from app.bot.utils.redis import RedisStorage
from app.bot.utils.redis.models import UserData
from app.bot.utils.texts import TextMessage
from app.config import Config


URL_RE = re.compile(
    r"(?i)\b(?:https?://|www\.|t\.me/|telegram\.me/|[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+\.[a-z]{2,})(?:[/?#][^\s]*)?"
)


def needs_captcha(config: Config, user_id: int, user_data: UserData) -> bool:
    return (
        config.captcha.ENABLED
        and user_id != config.bot.DEV_ID
        and not user_data.captcha_verified
    )


@dataclass
class CaptchaChallenge:
    user_id: int
    issued_at: int
    random_word: str
    first_message_has_url: bool


@dataclass
class CaptchaFirstMessagePolicy:
    seen: bool = False
    has_url: bool = False


class CaptchaService:
    SECRET_KEY = "captcha:hmac_secret"
    TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    TURNSTILE_ACTION = "support_bot"

    def __init__(self, config: Config, bot: Bot, redis: RedisStorage) -> None:
        self.config = config
        self.bot = bot
        self.redis = redis
        self._challenges: dict[int, CaptchaChallenge] = {}
        self._first_message_policies: dict[int, CaptchaFirstMessagePolicy] = {}
        self._hmac_secret: str | None = None
        self._secret_lock = asyncio.Lock()
        self._runner: web.AppRunner | None = None
        self._cleanup_task: asyncio.Task | None = None

    @property
    def enabled(self) -> bool:
        return self.config.captcha.ENABLED

    @property
    def configured(self) -> bool:
        captcha = self.config.captcha
        return all(
            [
                captcha.PUBLIC_URL,
                captcha.TURNSTILE_SITE_KEY,
                captcha.TURNSTILE_SECRET_KEY,
            ]
        )

    async def start(self) -> None:
        if not self.enabled:
            return

        await self.ensure_hmac_secret()
        self._cleanup_task = asyncio.create_task(self._cleanup_expired_challenges())

        app = web.Application()
        app.add_routes(
            [
                web.get("/captcha", self.handle_captcha_page),
                web.post("/captcha/verify", self.handle_captcha_verify),
            ]
        )
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(
            self._runner,
            host=self.config.captcha.WEB_HOST,
            port=self.config.captcha.WEB_PORT,
        )
        await site.start()

    async def stop(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._cleanup_task
        if self._runner:
            await self._runner.cleanup()

    async def ensure_hmac_secret(self) -> str:
        if self._hmac_secret:
            return self._hmac_secret

        async with self._secret_lock:
            if self._hmac_secret:
                return self._hmac_secret

            configured_secret = self.config.captcha.HMAC_SECRET
            async with self.redis.redis.client() as client:
                if configured_secret:
                    await client.set(self.SECRET_KEY, configured_secret)
                    self._hmac_secret = configured_secret
                    return configured_secret

                stored_secret = await client.get(self.SECRET_KEY)
                if stored_secret is None:
                    generated_secret = secrets.token_urlsafe(32)
                    await client.setnx(self.SECRET_KEY, generated_secret)
                    stored_secret = await client.get(self.SECRET_KEY)

            if isinstance(stored_secret, bytes):
                stored_secret = stored_secret.decode()
            self._hmac_secret = str(stored_secret)
            return self._hmac_secret

    async def get_or_create_challenge_url(
            self,
            user_data: UserData,
            first_message_text: str | None,
    ) -> str | None:
        if user_data.is_banned:
            return None

        challenge = self._challenges.get(user_data.id)
        if challenge:
            if self.is_expired(challenge):
                await self.expire_challenge(user_data, challenge)
                if user_data.is_banned:
                    return None
            else:
                challenge.first_message_has_url = self.update_first_message_url_policy(
                    user_data.id,
                    first_message_text,
                )
                return await self.build_challenge_url(challenge)

        if user_data.captcha_attempts >= self.config.captcha.MAX_ATTEMPTS:
            user_data.is_banned = True
            await self.redis.update_user(user_data.id, user_data)
            return None

        challenge = CaptchaChallenge(
            user_id=user_data.id,
            issued_at=int(time.time()),
            random_word=self.generate_random_word(),
            first_message_has_url=self.update_first_message_url_policy(
                user_data.id,
                first_message_text,
            ),
        )
        self._challenges[user_data.id] = challenge
        return await self.build_challenge_url(challenge)

    async def build_challenge_url(self, challenge: CaptchaChallenge) -> str:
        token = await self.sign(challenge)
        query = urlencode(
            {
                "uid": str(challenge.user_id),
                "ts": str(challenge.issued_at),
                "token": token,
            }
        )
        return f"{self.config.captcha.PUBLIC_URL.rstrip('/')}/captcha?{query}"

    async def sign(self, challenge: CaptchaChallenge) -> str:
        secret = await self.ensure_hmac_secret()
        payload = f"{challenge.user_id}{challenge.issued_at}{challenge.random_word}"
        return hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

    async def verify_active_challenge(
            self,
            user_id: int,
            issued_at: int,
            token: str,
            *,
            expire: bool,
    ) -> tuple[UserData | None, CaptchaChallenge | None, str | None]:
        user_data = await self.redis.get_user(user_id)
        if user_data is None:
            return None, None, "User is unknown."
        if user_data.is_banned:
            return user_data, None, "Verification is blocked."
        if user_data.captcha_verified:
            return user_data, None, None

        challenge = self._challenges.get(user_id)
        if challenge is None or challenge.issued_at != issued_at:
            return user_data, None, "Verification link is no longer active."

        expected_token = await self.sign(challenge)
        if not hmac.compare_digest(expected_token, token):
            return user_data, None, "Verification link is invalid."

        if self.is_expired(challenge):
            if expire:
                await self.expire_challenge(user_data, challenge)
            return user_data, None, "Verification link has expired."

        return user_data, challenge, None

    async def expire_challenge(
            self,
            user_data: UserData,
            challenge: CaptchaChallenge,
    ) -> None:
        self._challenges.pop(user_data.id, None)
        user_data.captcha_attempts += 1
        if (
                challenge.first_message_has_url
                or user_data.captcha_attempts >= self.config.captcha.MAX_ATTEMPTS
        ):
            user_data.is_banned = True
            self._first_message_policies.pop(user_data.id, None)
        await self.redis.update_user(user_data.id, user_data)

    async def ban_user(self, user_id: int) -> None:
        self._challenges.pop(user_id, None)
        self._first_message_policies.pop(user_id, None)
        user_data = await self.redis.get_user(user_id)
        if user_data is None:
            return
        user_data.is_banned = True
        await self.redis.update_user(user_id, user_data)

    async def mark_verified(self, user_data: UserData) -> None:
        self._challenges.pop(user_data.id, None)
        self._first_message_policies.pop(user_data.id, None)
        user_data.captcha_verified = True
        user_data.captcha_attempts = 0
        await self.redis.update_user(user_data.id, user_data)

        await get_or_create_forum_topic(
            self.bot,
            self.redis,
            self.config,
            user_data,
        )
        await self.send_continue_prompt(user_data)

    async def send_continue_prompt(self, user_data: UserData) -> None:
        text_message = TextMessage(user_data.language_code)
        text = text_message.get("main_menu")
        with suppress(IndexError, KeyError):
            text = text.format(full_name=hbold(user_data.full_name))
        with suppress(Exception):
            await self.bot.send_message(chat_id=user_data.id, text=text)

    async def handle_captcha_page(self, request: web.Request) -> web.Response:
        parsed = self.parse_request_identity(request.query)
        if parsed is None:
            return self.html_response("Invalid verification link.")

        user_id, issued_at, token = parsed
        user_data, challenge, error = await self.verify_active_challenge(
            user_id,
            issued_at,
            token,
            expire=True,
        )
        if user_data and user_data.captcha_verified:
            return self.html_response("Verification is already complete.")
        if error:
            return self.html_response(error)
        if challenge is None:
            return self.html_response("Verification link is no longer active.")

        page = self.render_captcha_page(user_id, issued_at, token)
        return web.Response(text=page, content_type="text/html")

    async def handle_captcha_verify(self, request: web.Request) -> web.Response:
        form = await request.post()
        parsed = self.parse_request_identity(form)
        if parsed is None:
            return self.html_response("Invalid verification request.", status=400)

        user_id, issued_at, token = parsed
        user_data, challenge, error = await self.verify_active_challenge(
            user_id,
            issued_at,
            token,
            expire=True,
        )
        if user_data and user_data.captcha_verified:
            return self.html_response("Verification is already complete.")
        if error:
            return self.html_response(error, status=400)
        if challenge is None:
            return self.html_response("Verification link is no longer active.", status=400)

        turnstile_token = str(form.get("cf-turnstile-response", ""))
        if not turnstile_token:
            await self.ban_user(user_id)
            return self.html_response("Verification failed. You have been banned.", status=403)

        verified = await self.verify_turnstile(
            turnstile_token,
            user_id,
            self.get_remote_ip(request),
        )
        if verified is None:
            return self.html_response("Verification is temporarily unavailable.", status=503)
        if not verified:
            await self.ban_user(user_id)
            return self.html_response("Verification failed. You have been banned.", status=403)

        await self.mark_verified(user_data)
        return self.html_response("Verification complete. Return to Telegram.")

    async def verify_turnstile(
            self,
            token: str,
            user_id: int,
            remote_ip: str | None,
    ) -> bool | None:
        data = {
            "secret": self.config.captcha.TURNSTILE_SECRET_KEY,
            "response": token,
        }
        if remote_ip:
            data["remoteip"] = remote_ip

        try:
            timeout = ClientTimeout(total=10)
            async with ClientSession(timeout=timeout) as session:
                async with session.post(self.TURNSTILE_VERIFY_URL, data=data) as response:
                    body = await response.json(content_type=None)
        except Exception as ex:
            logging.exception(ex)
            return None

        if not body.get("success"):
            return False
        if body.get("action") != self.TURNSTILE_ACTION:
            return False
        if body.get("cdata") != str(user_id):
            return False
        return True

    async def _cleanup_expired_challenges(self) -> None:
        while True:
            await asyncio.sleep(5)
            for user_id, challenge in list(self._challenges.items()):
                if not self.is_expired(challenge):
                    continue
                user_data = await self.redis.get_user(user_id)
                if user_data is None or user_data.is_banned or user_data.captcha_verified:
                    self._challenges.pop(user_id, None)
                    continue
                await self.expire_challenge(user_data, challenge)

    @staticmethod
    def generate_random_word() -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(8))

    def update_first_message_url_policy(
            self,
            user_id: int,
            text: str | None,
    ) -> bool:
        policy = self._first_message_policies.setdefault(
            user_id,
            CaptchaFirstMessagePolicy(),
        )
        if policy.seen or not text:
            return policy.has_url
        policy.seen = True
        policy.has_url = bool(URL_RE.search(text))
        return policy.has_url

    def is_expired(self, challenge: CaptchaChallenge) -> bool:
        return int(time.time()) - challenge.issued_at >= self.config.captcha.WINDOW_SECONDS

    @staticmethod
    def parse_request_identity(data: Any) -> tuple[int, int, str] | None:
        try:
            user_id = int(data.get("uid", ""))
            issued_at = int(data.get("ts", ""))
            token = str(data.get("token", ""))
        except (TypeError, ValueError):
            return None
        if not user_id or not issued_at or not token:
            return None
        return user_id, issued_at, token

    @staticmethod
    def get_remote_ip(request: web.Request) -> str | None:
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip:
            return cf_ip
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",", 1)[0].strip()
        return request.remote

    def render_captcha_page(self, user_id: int, issued_at: int, token: str) -> str:
        site_key = html.escape(self.config.captcha.TURNSTILE_SITE_KEY)
        verify_url = html.escape(
            f"{self.config.captcha.PUBLIC_URL.rstrip('/')}/captcha/verify",
            quote=True,
        )
        escaped_token = html.escape(token)
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Verification</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    body {{
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #f6f7f9;
      color: #1f2933;
    }}
    main {{
      width: min(420px, calc(100vw - 32px));
      padding: 24px;
      background: #ffffff;
      border: 1px solid #d9dee7;
      border-radius: 8px;
    }}
    h1 {{
      margin: 0 0 16px;
      font-size: 20px;
      line-height: 1.25;
    }}
    .fallback {{
      margin-top: 16px;
      font-size: 13px;
      color: #52606d;
    }}
  </style>
  <script>
    function onTurnstileSuccess(token) {{
      const form = document.getElementById("captcha-form");
      const response = document.getElementById("cf-turnstile-response");
      response.value = token;
      form.requestSubmit();
    }}
  </script>
</head>
<body>
  <main>
    <h1>Complete verification</h1>
    <form id="captcha-form" method="post" action="{verify_url}">
      <input type="hidden" name="uid" value="{user_id}">
      <input type="hidden" name="ts" value="{issued_at}">
      <input type="hidden" name="token" value="{escaped_token}">
      <input id="cf-turnstile-response" type="hidden" name="cf-turnstile-response" value="">
      <div
        class="cf-turnstile"
        data-sitekey="{site_key}"
        data-action="{self.TURNSTILE_ACTION}"
        data-cdata="{user_id}"
        data-callback="onTurnstileSuccess">
      </div>
      <div class="fallback">The page continues automatically after verification.</div>
    </form>
  </main>
</body>
</html>"""

    @staticmethod
    def html_response(message: str, status: int = 200) -> web.Response:
        escaped_message = html.escape(message)
        page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Verification</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #f6f7f9;
      color: #1f2933;
    }}
    main {{
      width: min(420px, calc(100vw - 32px));
      padding: 24px;
      background: #ffffff;
      border: 1px solid #d9dee7;
      border-radius: 8px;
      text-align: center;
    }}
  </style>
</head>
<body>
  <main>{escaped_message}</main>
</body>
</html>"""
        return web.Response(text=page, status=status, content_type="text/html")
