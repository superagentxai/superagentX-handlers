import logging
import os

import tweepy

from superagentx.handler.base import BaseHandler
from superagentx.utils.helper import sync_to_async

from superagentx_handlers.google.exceptions import AuthException

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
        self.client = tweepy.Client(
            consumer_key=api_key or os.getenv("CONSUMER_KEY"),
            consumer_secret=api_secret_key or os.getenv("CONSUMER_SECRET"),
            access_token=access_token or os.getenv("ACCESS_TOKEN"),
            access_token_secret=access_token_secret or os.getenv("ACCESS_TOKEN_SECRET")
        )

    async def post_tweet(
            self,
            text: str,
            hash_tags: list[str] = None,
            user_tags: list[str] = None
    ):
        """
                posts a tweet with optional hashtags and user tags.

                Parameters:
                -----------
                text : str
                    The main content of the tweet. This is a required parameter.

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

        try:
            # Post the tweet
            join_hashtags = " ".join(f"#{x}" for x in hash_tags if isinstance(x, str)) if hash_tags else ""
            join_user_tags = " ".join(f"@{x}" for x in user_tags if isinstance(x, str)) if user_tags else ""

            tweet_text = f"{join_hashtags}  {join_user_tags}  {text}"
            response = await sync_to_async(
                self.client.create_tweet,
                text=tweet_text
            )
            return response.data
        except tweepy.TweepyException as e:
            logger.debug("Error posting tweet: %s", e)
            raise AuthException(f"Failed to post tweet: {e}")
