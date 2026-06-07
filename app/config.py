from dataclasses import dataclass

from environs import Env


@dataclass
class BotConfig:
    """
    Data class representing the configuration for the bot.

    Attributes:
    - TOKEN (str): The bot token.
    - DEV_ID (int): The developer's user ID.
    - GROUP_ID (int): The group chat ID.
    - BOT_EMOJI_ID (str): The custom emoji ID for the group's topic.
    """
    TOKEN: str
    DEV_ID: int
    GROUP_ID: int
    BOT_EMOJI_ID: str


@dataclass
class RedisConfig:
    """
    Data class representing the configuration for Redis.

    Attributes:
    - HOST (str): The Redis host.
    - PORT (int): The Redis port.
    - DB (int): The Redis database number.
    """
    HOST: str
    PORT: int
    DB: int

    def dsn(self) -> str:
        """
        Generates a Redis connection DSN (Data Source Name) using the provided host, port, and database.

        :return: The generated DSN.
        """
        return f"redis://{self.HOST}:{self.PORT}/{self.DB}"


@dataclass
class CaptchaConfig:
    """
    Data class representing the captcha configuration.
    """
    ENABLED: bool
    PUBLIC_URL: str
    TURNSTILE_SITE_KEY: str
    TURNSTILE_SECRET_KEY: str
    HMAC_SECRET: str
    WEB_HOST: str
    WEB_PORT: int
    WINDOW_SECONDS: int = 300
    MAX_ATTEMPTS: int = 3


@dataclass
class Config:
    """
    Data class representing the overall configuration for the application.

    Attributes:
    - bot (BotConfig): The bot configuration.
    - redis (RedisConfig): The Redis configuration.
    - captcha (CaptchaConfig): The captcha configuration.
    """
    bot: BotConfig
    redis: RedisConfig
    captcha: CaptchaConfig


def load_config() -> Config:
    """
    Load the configuration from environment variables and return a Config object.

    :return: The Config object with loaded configuration.
    """
    env = Env()
    env.read_env()

    return Config(
        bot=BotConfig(
            TOKEN=env.str("BOT_TOKEN"),
            DEV_ID=env.int("BOT_DEV_ID"),
            GROUP_ID=env.int("BOT_GROUP_ID"),
            BOT_EMOJI_ID=env.str("BOT_EMOJI_ID"),
        ),
        redis=RedisConfig(
            HOST=env.str("REDIS_HOST"),
            PORT=env.int("REDIS_PORT"),
            DB=env.int("REDIS_DB"),
        ),
        captcha=CaptchaConfig(
            ENABLED=env.bool("CAPTCHA_ENABLED", True),
            PUBLIC_URL=env.str("CAPTCHA_PUBLIC_URL", ""),
            TURNSTILE_SITE_KEY=env.str("TURNSTILE_SITE_KEY", ""),
            TURNSTILE_SECRET_KEY=env.str("TURNSTILE_SECRET_KEY", ""),
            HMAC_SECRET=env.str("CAPTCHA_HMAC_SECRET", ""),
            WEB_HOST=env.str("CAPTCHA_WEB_HOST", "127.0.0.1"),
            WEB_PORT=env.int("CAPTCHA_WEB_PORT", 33804),
        ),
    )
