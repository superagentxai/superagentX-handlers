import logging
from requests_oauthlib import OAuth1Session
import os
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)

API_BASE_URL = "https://api.twitter.com/2"
REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token?oauth_callback=oob&x_auth_access_type=write"


class AuthException(Exception):
    pass


class TwitterHandler(BaseHandler):

    def __init__(
        self,
        *,
        consumer_key: str | None = None,
        consumer_secret: str | None = None,
        request_token_url: str = REQUEST_TOKEN_URL,
    ):
        super().__init__()
        self.consumer_key = consumer_key or os.getenv("TWITTER_CONSUMER_KEY")
        self.consumer_secret = consumer_secret or os.getenv("TWITTER_CONSUMER_SECRET")
        self.oauth = OAuth1Session(self.consumer_key, client_secret=self.consumer_secret)

        try:
            fetch_response = self.oauth.fetch_request_token(request_token_url)
            self.resource_owner_key = fetch_response.get("oauth_token")
            self.resource_owner_secret = fetch_response.get("oauth_token_secret")

            if not self.resource_owner_key or not self.resource_owner_secret:
                raise AuthException("OAuth tokens not retrieved.")
            logger.debug("Authentication Success")
        except Exception as ex:
            message = f"Twitter Handler Authentication Problem: {ex}"
            logger.error(message, exc_info=True)
            raise AuthException(message)

    @tool
    async def post_tweet(
        self,
        payload: str | dict,
        base_authorization_url: str = "https://api.twitter.com/oauth/authorize",
        verifier: str | None = None,
    ):
        authorization_url = self.oauth.authorization_url(base_authorization_url)
        logger.info("Please go here and authorize: %s", authorization_url)

        if verifier is None:
            verifier = input("Paste the PIN here: ")

        try:
            access_token_url = "https://api.twitter.com/oauth/access_token"
            self.oauth = OAuth1Session(
                self.consumer_key,
                client_secret=self.consumer_secret,
                resource_owner_key=self.resource_owner_key,
                resource_owner_secret=self.resource_owner_secret,
                verifier=verifier,
            )
            oauth_tokens = self.oauth.fetch_access_token(access_token_url)
            access_token = oauth_tokens["oauth_token"]
            access_token_secret = oauth_tokens["oauth_token_secret"]

            self.oauth = OAuth1Session(
                self.consumer_key,
                client_secret=self.consumer_secret,
                resource_owner_key=access_token,
                resource_owner_secret=access_token_secret,
            )
            logger.info("Authorization successful")
        except Exception as ex:
            logger.error("Error during authorization: %s", ex, exc_info=True)
            raise AuthException("Authorization failed.")

        url = f"{API_BASE_URL}/tweets"
        headers = {"Content-Type": "application/json"}
        tweet_data = payload if isinstance(payload, dict) else {"text": payload}

        try:
            response = self.oauth.post(url, json=tweet_data, headers=headers)
            response.raise_for_status()
            logger.info("Tweet posted successfully: %s", response.json())
            return response.json()
        except Exception as ex:
            logger.error("Failed to post tweet: %s", ex, exc_info=True)
            raise AuthException("Failed to post tweet.")
