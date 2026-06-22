import logging
import os
from typing import Optional
import httpx

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class TeamsHandler(BaseHandler):
    GRAPH_BASE_URL = (
        "https://graph.microsoft.com/v1.0"
    )

    def __init__(
            self,
            access_token:Optional[str] = None,
            team_id:Optional[str] = None,
            channel_id:Optional[str] = None,
            **kwargs
    ):
        """
           Initializes the Teams handler.

           Args:
               access_token (str, optional):
                   Microsoft Graph access token.

               team_id (str, optional):
                   Microsoft Teams Team ID.

               channel_id (str, optional):
                   Microsoft Teams Channel ID.

               **kwargs:
                   Additional arguments passed to BaseHandler.

           """

        super().__init__(**kwargs)

        self.access_token = access_token or os.getenv("TEAMS_ACCESS_TOKEN")
        self.team_id = team_id or os.getenv("TEAMS_TEAM_ID")
        self.channel_id = channel_id or os.getenv("TEAMS_CHANNEL_ID")

        if not self.access_token:
            raise ValueError(
                "TEAMS_ACCESS_TOKEN is required"
            )

        if not self.team_id:
            raise ValueError(
                "TEAMS_TEAM_ID is required"
            )

        if not self.channel_id:
            raise ValueError(
                "TEAMS_CHANNEL_ID is required"
            )

        self.headers = {
            "Authorization":
                f"Bearer {self.access_token}",
            "Content-Type":
                "application/json"
        }

    async def _get(
            self,
            endpoint: str
    ):
        try:
            async with httpx.AsyncClient(
                    timeout=60
            ) as client:
                response = await client.get(
                    f"{self.GRAPH_BASE_URL}{endpoint}",
                    headers=self.headers
                )

                return response

        except httpx.RequestError as e:
            logger.error(
                f"GET request failed: {str(e)}"
            )
            raise

    async def _post(
            self,
            endpoint: str,
            payload: dict
    ):
        try:
            async with httpx.AsyncClient(
                    timeout=60
            ) as client:
                response = await client.post(
                    f"{self.GRAPH_BASE_URL}{endpoint}",
                    headers=self.headers,
                    json=payload
                )

                return response

        except httpx.RequestError as e:
            logger.error(
                f"POST request failed: {str(e)}"
            )
            raise


    @tool
    async def get_profile_info(self):
        """
        Retrieves the profile information of the authenticated
        Microsoft Teams user.

        Returns:
            dict: User profile details including ID, name,
            email, job title, office location, and language
            preferences.

        """
        try:

            response = await self._get(
                "/me"
            )

            if response.status_code == 200:
                profile = response.json()

                return {
                    "success":True,
                    "id":profile.get("id"),
                    "display_name":profile.get("displayName"),
                    "given_name":profile.get("givenName"),
                    "surname":profile.get("surname"),
                    "email":profile.get("mail"),
                    "user_principal_name":profile.get("userPrincipalName"),
                    "job_title":profile.get("jobTitle"),
                    "mobile_phone":profile.get("mobilePhone"),
                    "office_location":profile.get("officeLocation"),
                    "preferred_language":profile.get("preferredLanguage")
                }

            return {
                "success": False,
                "status_code": response.status_code,
                "error": response.text
            }

        except Exception as e:

            logger.error(
                f"Failed to retrieve profile: {str(e)}"

            )
            return {
                "success": False,
                "error": str(e)
            }

    @tool
    async def send_channel_message(
            self,
            message: str,
            **kwargs
    ):
        """
        Sends a message to the configured Microsoft Teams channel.

        Args:
            message (str): Message content to send.

        Returns:
            dict: Result containing:
            - success (bool)
            - message_id (str) when successful
            - error (str) when failed

        """

        try:

            previous_agent_result = kwargs.get("previous_agent_result")

            if previous_agent_result:
                message = str(
                    previous_agent_result
                )

            payload = {
                "body": {
                    "content": message
                }
            }

            response = await self._post(
                (
                    f"/teams/{self.team_id}"
                    f"/channels/{self.channel_id}"
                    f"/messages"
                ),
                payload
            )

            if response.status_code == 201:
                result = response.json()
                return {
                    "success": True,
                    "message_id":
                        result.get("id")
                }
            return {
                "success": False,
                "status_code": response.status_code,
                "error": response.text
            }

        except Exception as e:

            logger.error(
                f"Failed to send Teams message: "
                f"{str(e)}"
            )

            return {
                "success": False,
                "error": str(e)
            }