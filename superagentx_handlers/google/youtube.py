import asyncio
import logging
from typing import List, Optional, Dict, Any
import os

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from googleapiclient.http import MediaFileUpload

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class YouTubeHandler(BaseHandler):
    """
    YouTube Data API handler using access-token–only authentication.

    This handler provides async-safe utilities for interacting with
    the YouTube Data API v3, including uploading videos, updating
    metadata, managing thumbnails, retrieving comments, and
    fetching channel details.

    """

    def __init__(
            self,
            access_token: str
    ):
        if not access_token:
            raise ValueError("access_token is required")

        super().__init__()

        credentials = Credentials(
            token=access_token,
        )

        # Override refresh to do nothing (no refresh token)
        def _no_refresh(request: Request):
            logger.debug("Refresh skipped (access-token-only)")
            return

        credentials.refresh = _no_refresh
        self.credentials = credentials

        self.service = build(
            "youtube",
            "v3",
            credentials=self.credentials,
            cache_discovery=False
        )

    @staticmethod
    async def sync_to_async(func):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, func)

    @tool
    async def upload_video(
            self,
            video_path: str,
            title: str,
            description: str,
            tags: Optional[List[str]] = None,
            category_id: str = "22",
            privacy_status: str = "private"
    ):
        """
            Upload a video to YouTube.

            The upload is performed using resumable uploads and reports
            progress through logging. The video is uploaded to the
            authenticated user's channel.

            Args:
                video_path: Local filesystem path to the video file.
                title: Video title.
                description: Video description.
                tags: Optional list of video tags.
                category_id: YouTube video category ID (default is "People & Blogs").
                privacy_status: Privacy status of the video
                                ("private", "unlisted", or "public").

            Returns:
                The YouTube API response containing uploaded video metadata.

            Raises:
                FileNotFoundError: If the video file does not exist.
                ValueError: If privacy_status is invalid.
        """
        if not os.path.exists(video_path):
            raise FileNotFoundError("Video file not found")
        if privacy_status not in {"private", "unlisted", "public"}:
            raise ValueError("Invalid privacy_status")

        def _upload():
            body = {
                "snippet": {
                    "title": title,
                    "description": description,
                    "tags": tags or [],
                    "categoryId": category_id
                },
                "status": {"privacyStatus": privacy_status}
            }

            media = MediaFileUpload(video_path, chunksize=-1, resumable=True)
            request = self.service.videos().insert(part="snippet,status", body=body, media_body=media)

            response = None
            while response is None:
                status, response = request.next_chunk()
                if status:
                    logger.info("Upload progress: %d%%", int(status.progress() * 100))
            return response

        return await self.sync_to_async(_upload)

    @tool
    async def update_video_title(
            self,
            video_id: str,
            title: str,
            description: Optional[str] = None,
            tags: Optional[List[str]] = None,
            category_id: str = "22"
    ):
        """
           Update the title and metadata of an existing YouTube video.

           The video must belong to the authenticated user's channel.

           Args:
               video_id: YouTube video ID.
               title: New video title.
               description: Optional new video description.
               tags: Optional list of tags to replace existing ones.
               category_id: YouTube video category ID.

           Returns:
               The updated video resource from the YouTube API.

           Raises:
               ValueError: If the video does not exist or is not owned
                           by the authenticated channel.
           """
        if not video_id or not title:
            raise ValueError("video_id and title are required")

        video_id = video_id.replace("v=", "").strip()

        def _update():
            response = self.service.videos().list(
                part="snippet",
                id=video_id
            ).execute()
            if not response.get("items"):
                raise ValueError("Video not found or not owned by this channel")

            snippet = response["items"][0]["snippet"]
            snippet["title"] = title
            snippet["categoryId"] = category_id
            if description is not None:
                snippet["description"] = description
            if tags is not None:
                snippet["tags"] = tags

            return self.service.videos().update(
                part="snippet",
                body={
                    "id": video_id,
                    "snippet": snippet}
            ).execute()

        return await self.sync_to_async(_update)

    @tool
    async def update_video_thumbnail(
            self,
            video_id: str,
            thumbnail_path: str
    ):
        """
            Update the thumbnail image of a YouTube video.

            Args:
                video_id: YouTube video ID.
                thumbnail_path: Local filesystem path to the thumbnail image.

            Returns:
                The YouTube API response for the thumbnail update.

            Raises:
                FileNotFoundError: If the thumbnail file does not exist.
        """
        if not os.path.exists(thumbnail_path):
            raise FileNotFoundError("Thumbnail file not found")

        def _upload():
            media = MediaFileUpload(
                thumbnail_path,
                mimetype="image/png",
                resumable=False
            )
            return self.service.thumbnails().set(
                videoId=video_id,
                media_body=media
            ).execute()

        return await self.sync_to_async(_upload)

    @tool
    async def get_video_comments(
            self,
            video_id: str,
            max_results: int = 20
    ):
        """
           Retrieve recent comments for a YouTube video.

           Comments are returned in chronological order, starting
           from the most recent.

           Args:
               video_id: YouTube video ID.
               max_results: Maximum number of comments to retrieve.

           Returns:
               A list of dictionaries containing comment metadata,
               including author, text, likes, and publish time.
        """
        def _fetch():
            comments = []
            request = self.service.commentThreads().list(
                part="snippet",
                videoId=video_id,
                maxResults=min(max_results, 100),
                textFormat="plainText",
                order="time"
            )

            while request and len(comments) < max_results:
                response = request.execute()
                for item in response.get("items", []):
                    snippet = item["snippet"]["topLevelComment"]["snippet"]
                    comments.append({
                        "comment_id": item["id"],
                        "author": snippet.get("authorDisplayName"),
                        "text": snippet.get("textDisplay"),
                        "likes": snippet.get("likeCount", 0),
                        "published_at": snippet.get("publishedAt"),
                    })
                    if len(comments) >= max_results:
                        break
                request = self.service.commentThreads().list_next(request, response)

            return comments

        return await self.sync_to_async(_fetch)

    @tool
    async def get_channel_details_by_name(
            self,
            channel_name: str
    ):
        """
           Retrieve public details of a YouTube channel by its name.

           The method performs a search query and returns basic
           channel metadata and statistics if found.

           Args:
               channel_name: Display name of the YouTube channel.

           Returns:
               A dictionary containing channel details such as
               channel ID, title, description, subscriber count,
               video count, and total views. Returns an empty
               dictionary if the channel is not found.
        """
        def _fetch():
            search = self.service.search().list(
                part="snippet",
                q=channel_name,
                type="channel",
                maxResults=1
            ).execute()

            if not search.get("items"):
                return {}

            channel_id = search["items"][0]["snippet"]["channelId"]
            channel = self.service.channels().list(
                part="snippet,statistics",
                id=channel_id
            ).execute()["items"][0]

            return {
                "channel_id": channel["id"],
                "title": channel["snippet"]["title"],
                "description": channel["snippet"].get("description"),
                "subscribers": int(channel["statistics"].get("subscriberCount", 0)),
                "videos": int(channel["statistics"].get("videoCount", 0)),
                "views": int(channel["statistics"].get("viewCount", 0)),
            }

        return await self.sync_to_async(_fetch)

