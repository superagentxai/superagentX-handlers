import logging
import os

import pyshorteners
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async
from tweepy.asynchronous import AsyncClient

logger = logging.getLogger(__name__)


class TwitterHandler(BaseHandler):

    def __init__(
            self,
            *,
            api_key: str | None = None,
            api_secret_key: str | None = None,
            access_token: str | None = None,
            access_token_secret: str | None = None
    ):
        super().__init__()
        # Define client as an instance attribute
        self.client = AsyncClient(
            consumer_key=api_key or os.getenv("CONSUMER_KEY"),
            consumer_secret=api_secret_key or os.getenv("CONSUMER_SECRET"),
            access_token=access_token or os.getenv("ACCESS_TOKEN"),
            access_token_secret=access_token_secret or os.getenv("ACCESS_TOKEN_SECRET")
        )
        self._tinyurl = pyshorteners.Shortener(timeout=5).tinyurl

    async def _get_shortener_url(self, link: str):
        return await sync_to_async(
            self._tinyurl.short,
            link
        )

    @tool
    async def post_tweet(
            self,
            text: str,
            link: str = None,
            hash_tags: list[str] = None,
            user_tags: list[str] = None
    ):
        """
        posts a tweet with optional hashtags and user tags.

        Parameters:
        -----------
        text : str
            The main content of the tweet. This is a required parameter.

        link: str, optional
            A valid website link to include in the tweet. Default to None.

        hash_tags : list[str], optional
            A list of hashtags to include in the tweet. Each hashtag should be a string without the `#` symbol.
            Defaults to an empty.

        user_tags : list[str], optional
            A list of Twitter usernames (without the `@` symbol) to mention in the tweet.
            Defaults to an empty.

        Returns:
        dict
            A dictionary containing the response from the tweet ID, text, and meta etc...
        ```
        """
        if not text:
            logger.error("Tweet text cannot be empty.")
            raise ValueError("Tweet text cannot be empty.")

        join_hashtags = " ".join(f"#{x}" for x in hash_tags or [])
        join_user_tags = " ".join(f"@{x}" for x in user_tags or [])

        if link:
            text = f'{text} {await self._get_shortener_url(link)}'
        if join_user_tags:
            text = f'{join_user_tags} {text}'
        if join_hashtags:
            text = f'{join_hashtags} {text}'

        logger.debug(f'Tweet Text Length {len(text)} and Text => \n\t{text}')
        response = await self.client.create_tweet(text=text)
        return response.data
