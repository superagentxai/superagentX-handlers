import asyncio
import logging
import os
from typing import Optional, Dict, Any, List

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)

# SCOPES = ["https://www.googleapis.com/auth/youtube.force-ssl"]


class YouTubeHandler(BaseHandler):
    """
    YouTube handler using YouTube Data API v3 (REAL credentials).
    """

    def __init__(
        self,
        *,
        credentials_path: str,
        token_path: str
    ):
        super().__init__()

        if not os.path.exists(credentials_path):
            raise FileNotFoundError(f"Missing credentials file: {credentials_path}")

        self.credentials_path = credentials_path
        self.token_path = token_path

        self.credentials = self._load_or_create_credentials()
        self.youtube = build(
            "youtube",
            "v3",
            credentials=self.credentials,
            cache_discovery=False
        )

    async def sync_to_async(self, func):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, func)

    def _load_or_create_credentials(self) -> Credentials:
        creds = None

        if os.path.exists(self.token_path):
            creds = Credentials.from_authorized_user_file(
                self.token_path, SCOPES
            )

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_path, SCOPES
                )
                creds = flow.run_local_server(port=0)

            with open(self.token_path, "w") as token:
                token.write(creds.to_json())

        return creds

    @tool
    async def update_video_thumbnail(
        self,
        video_id: str,
        thumbnail_path: str
    ) -> Dict[str, Any]:

        if not os.path.exists(thumbnail_path):
            raise FileNotFoundError("Thumbnail file not found")

        def _upload():
            media = MediaFileUpload(
                thumbnail_path,
                mimetype="image/png",
                resumable=False
            )

            return self.youtube.thumbnails().set(
                videoId=video_id,
                media_body=media
            ).execute()

        return await self.sync_to_async(_upload)

    @tool
    async def update_video_title(
        self,
        video_id: str,
        title: str,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        category_id: str = "22"
    ) -> Dict[str, Any]:

        if not video_id or not title:
            raise ValueError("video_id and title are required")

        video_id = video_id.replace("v=", "").strip()

        def _update():
            response = self.youtube.videos().list(
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

            return self.youtube.videos().update(
                part="snippet",
                body={
                    "id": video_id,
                    "snippet": snippet
                }
            ).execute()

        return await self.sync_to_async(_update)

    @tool
    async def upload_video(
        self,
        video_path: str,
        title: str,
        description: str,
        tags: Optional[List[str]] = None,
        category_id: str = "22",
        privacy_status: str = "private"
    ) -> Dict[str, Any]:

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
                    "categoryId": category_id,
                },
                "status": {
                    "privacyStatus": privacy_status
                }
            }

            media = MediaFileUpload(
                video_path,
                chunksize=-1,
                resumable=True
            )

            request = self.youtube.videos().insert(
                part="snippet,status",
                body=body,
                media_body=media
            )

            response = None
            while response is None:
                status, response = request.next_chunk()
                if status:
                    logger.info("Upload progress: %d%%",
                                int(status.progress() * 100))

            return response

        return await self.sync_to_async(_upload)

    @tool
    async def get_video_comments(
        self,
        video_id: str,
        max_results: int = 20
    ) -> List[Dict[str, Any]]:

        def _fetch():
            comments = []
            request = self.youtube.commentThreads().list(
                part="snippet",
                videoId=video_id,
                maxResults=min(max_results, 100),
                textFormat="plainText"
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

                request = self.youtube.commentThreads().list_next(
                    request, response
                )

            return comments

        return await self.sync_to_async(_fetch)

    @tool
    async def get_channel_details_by_name(
        self,
        channel_name: str
    ) -> Dict[str, Any]:

        def _fetch():
            search = self.youtube.search().list(
                part="snippet",
                q=channel_name,
                type="channel",
                maxResults=1
            ).execute()

            if not search.get("items"):
                return {}

            channel_id = search["items"][0]["snippet"]["channelId"]

            channel = self.youtube.channels().list(
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

