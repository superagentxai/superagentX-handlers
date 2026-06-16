import logging
import os
import httpx

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class LinkedInHandler(BaseHandler):

    def __init__(
            self,
            access_token: str = None,
            **kwargs
    ):
        """
           Initialize the LinkedIn handler.

           Args:
               access_token (str, optional):
                   LinkedIn OAuth access token.
                   Falls back to LINKEDIN_ACCESS_TOKEN
                   environment variable.

               **kwargs:
                   Additional arguments passed to BaseHandler.
           """

        super().__init__(**kwargs)

        self.access_token = access_token or os.getenv(
            "LINKEDIN_ACCESS_TOKEN"
        )

        if not self.access_token:
            raise ValueError(
                "LINKEDIN_ACCESS_TOKEN is required"
            )

        self.headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0",
            "Linkedin-Version": "202506"
        }

    @tool
    async def get_profile(self):
        """
        Retrieves the authenticated LinkedIn user's profile.

        Returns:
            dict: LinkedIn user profile information
            including user ID, name, email, and
            profile details.
        """

        try:
            async with httpx.AsyncClient() as client:

                response = await client.get(
                    "https://api.linkedin.com/v2/userinfo",
                    headers={
                        "Authorization":
                            f"Bearer {self.access_token}"
                    }
                )

                response.raise_for_status()

                return response.json()

        except httpx.HTTPError as e:

            logger.error(
                f"Failed to retrieve profile: {str(e)}"
            )

            raise

    @tool
    async def create_post(
            self,
            text: str,
            **kwargs
    ):
        """
        Creates a text post on LinkedIn.

        Args:
            text (str):
                Content of the LinkedIn post.

            **kwargs:
                Additional keyword arguments.

                Supported:
                - previous_agent_result:
                  Uses the previous agent output
                  as the post content.

        Returns:
            dict: Result containing:

                - success (bool)
                - post_urn (str)
                - location (str)

                OR

                - success (bool)
                - status_code (int)
                - error (str)
        """

        try:

            previous_agent_result = kwargs.get(
                "previous_agent_result"
            )

            if previous_agent_result:
                text = str(previous_agent_result)

            profile = await self.get_profile()

            person_urn = (
                f"urn:li:person:{profile['sub']}"
            )

            payload = {
                "author": person_urn,
                "commentary": text,
                "visibility": "PUBLIC",
                "distribution": {
                    "feedDistribution": "MAIN_FEED",
                    "targetEntities": [],
                    "thirdPartyDistributionChannels": []
                },
                "lifecycleState": "PUBLISHED",
                "isReshareDisabledByAuthor": False
            }

            async with httpx.AsyncClient(
                    timeout=60
            ) as client:

                response = await client.post(
                    "https://api.linkedin.com/rest/posts",
                    headers=self.headers,
                    json=payload
                )

                if response.status_code == 201:

                    return {
                        "success": True,
                        "post_urn": response.headers.get(
                            "x-restli-id"
                        ),
                        "location": response.headers.get(
                            "location"
                        )
                    }

                return {
                    "success": False,
                    "status_code": response.status_code,
                    "error": response.text
                }

        except Exception as e:

            logger.error(
                f"Failed to create post: {str(e)}"
            )

            raise

    @tool
    async def upload_image(
            self,
            image_path: str
    ):
        """
        Uploads an image to LinkedIn and returns
        the uploaded asset identifier.

        Args:
            image_path (str):
                Local path to the image file.

        Returns:
            dict: Result containing:

                - success (bool)
                - asset (str)

            Where asset is the LinkedIn asset URN
            that can be used when creating posts.

        """

        try:

            profile = await self.get_profile()

            person_urn = (
                f"urn:li:person:{profile['sub']}"
            )

            register_payload = {
                "registerUploadRequest": {
                    "owner": person_urn,
                    "recipes": [
                        "urn:li:digitalmediaRecipe:feedshare-image"
                    ],
                    "serviceRelationships": [
                        {
                            "relationshipType": "OWNER",
                            "identifier":
                                "urn:li:userGeneratedContent"
                        }
                    ]
                }
            }

            async with httpx.AsyncClient(
                    timeout=120
            ) as client:

                register_response = await client.post(
                    "https://api.linkedin.com/v2/assets?action=registerUpload",
                    headers={
                        "Authorization":
                            f"Bearer {self.access_token}",
                        "Content-Type":
                            "application/json"
                    },
                    json=register_payload
                )

                register_response.raise_for_status()

                upload_data = (
                    register_response.json()
                )

                upload_url = (
                    upload_data["value"]
                    ["uploadMechanism"]
                    ["com.linkedin.digitalmedia.uploading.MediaUploadHttpRequest"]
                    ["uploadUrl"]
                )

                asset = (
                    upload_data["value"]["asset"]
                )

                with open(
                        image_path,
                        "rb"
                ) as image_file:

                    image_bytes = (
                        image_file.read()
                    )

                upload_response = await client.put(
                    upload_url,
                    content=image_bytes
                )

                upload_response.raise_for_status()

                return {
                    "success": True,
                    "asset": asset
                }

        except Exception as e:

            logger.error(
                f"Failed to upload image: {str(e)}"
            )

            raise