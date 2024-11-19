import logging
import os

import tweepy

from superagentx.handler.base import BaseHandler
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
            hash_tags: list[str] = "",
            user_tags: list[str] = ""
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
            hash_list = ["#" + x for x in hash_tags if isinstance(x, str)]
            join_hashtags = " ".join(hash_list)

            user_list = ["@" + x for x in user_tags if isinstance(x, str)]
            join_user_tags = " ".join(user_list)

            tweet_text = f"{join_hashtags}  {join_user_tags}  {text}"
            response = self.client.create_tweet(
                text=tweet_text
            )
            return response.data
        except tweepy.TweepyException as e:
            logger.debug("Error posting tweet: %s", e)
            raise AuthException(f"Failed to post tweet: {e}")
