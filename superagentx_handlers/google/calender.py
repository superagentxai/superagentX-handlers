import asyncio
import logging
import os
from datetime import datetime, time
from typing import Dict, Any, Optional, List
from zoneinfo import ZoneInfo

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)



class GoogleCalendarHandler(BaseHandler):
    """
    Async Google Calendar handler using Calendar API v3.

    Supports:
    - Creating meetings
    - Rescheduling meetings
    - Listing upcoming meetings

    Designed to match GmailHandler async + error-handling patterns.
    """

    def __init__(
            self,
            credentials_path: str,
            token_path: str,
            timezone: str = "Asia/Kolkata"
    ):
        super().__init__()
        self.credentials_path = credentials_path
        self.token_path = token_path
        self.timezone = timezone

    # ------------------------------
    # Async helper (same as Gmail)
    # ------------------------------
    @staticmethod
    async def sync_to_async(func):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, func)

    # ------------------------------
    # Internal helpers
    # ------------------------------
    def _get_calendar_service(self):
        creds = None

        if os.path.exists(self.token_path):
            creds = Credentials.from_authorized_user_file(
                self.token_path, SCOPES
            )

        if not creds or not creds.valid:
            flow = InstalledAppFlow.from_client_secrets_file(
                self.credentials_path, SCOPES
            )
            creds = flow.run_local_server(port=0)

            with open(self.token_path, "w") as f:
                f.write(creds.to_json())

        return build("calendar", "v3", credentials=creds)

    def _to_iso(self, value: str) -> str:
        dt = datetime.strptime(value, "%d-%m-%Y T %H:%M")
        return dt.replace(tzinfo=ZoneInfo(self.timezone)).isoformat()

    @tool
    async def create_meeting(
            self,
            subject: str,
            start_time: str,
            end_time: str,
            attendees: str,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Creates a calendar meeting and sends invitations.
        """
        try:
            if not subject or not start_time or not end_time:
                raise ValueError("subject, start_time, and end_time are required.")

            def _create():
                service = self._get_calendar_service()

                event = {
                    "summary": subject,
                    "description": description or "",
                    "start": {
                        "dateTime": self._to_iso(start_time),
                        "timeZone": self.timezone,
                    },
                    "end": {
                        "dateTime": self._to_iso(end_time),
                        "timeZone": self.timezone,
                    },
                    "attendees": [
                        {"email": email} for email in (attendees or [])
                    ],
                }

                return service.events().insert(
                    calendarId="primary",
                    body=event,
                    sendUpdates="all"
                ).execute()

            created = await self.sync_to_async(_create)

            return {
                "status": "success",
                "event_id": created["id"],
                "html_link": created["htmlLink"]
            }

        except Exception as e:
            logger.error(f"Error creating meeting → {e}")
            return {}

    @tool
    async def reschedule_meeting(
            self,
            subject: str,
            search_date: str,
            new_start: str,
            new_end: str
    ) -> Dict[str, Any]:
        """
        Reschedules an existing meeting by subject and date.
        """
        try:
            tz = ZoneInfo(self.timezone)

            def _parse(value: str, fmt: str):
                return datetime.strptime(value, fmt).replace(tzinfo=tz)

            def _day_range(date_str: str):
                date = _parse(date_str, "%d-%m-%Y")
                start = datetime.combine(date.date(), time.min).replace(tzinfo=tz)
                end = datetime.combine(date.date(), time.max).replace(tzinfo=tz)

                return start.isoformat(), end.isoformat()

            def _reschedule():
                service = self._get_calendar_service()
                time_min, time_max = _day_range(search_date)

                events = service.events().list(
                    calendarId="primary",
                    q=subject,
                    timeMin=time_min,
                    timeMax=time_max,
                    singleEvents=True,
                    orderBy="startTime"
                ).execute().get("items", [])

                if not events:
                    raise ValueError("No meeting found.")

                if len(events) > 1:
                    raise ValueError("Multiple meetings found. Use unique subject.")

                event = events[0]

                start_dt = _parse(new_start, "%d-%m-%Y T %H:%M")
                end_dt = _parse(new_end, "%d-%m-%Y T %H:%M")

                if end_dt <= start_dt:
                    raise ValueError("new_end must be after new_start.")

                event["start"]["dateTime"] = start_dt.isoformat()
                event["end"]["dateTime"] = end_dt.isoformat()

                return service.events().update(
                    calendarId="primary",
                    eventId=event["id"],
                    body=event,
                    sendUpdates="all"
                ).execute()

            updated = await self.sync_to_async(_reschedule)

            return {
                "status": "success",
                "event_id": updated["id"],
                "updated_start": updated["start"]["dateTime"],
                "updated_end": updated["end"]["dateTime"]
            }

        except Exception as e:
            logger.error(f"Error rescheduling meeting → {e}")
            raise RuntimeError(str(e)) from e


    @tool
    async def list_meetings(self, max_results: int = 10) -> Dict[str, Any]:
        """
        Lists upcoming calendar meetings.
        """
        try:
            def _list():
                service = self._get_calendar_service()
                return service.events().list(
                    calendarId="primary",
                    maxResults=max_results,
                    singleEvents=True,
                    orderBy="startTime"
                ).execute().get("items", [])

            events = await self.sync_to_async(_list)

            return {
                "status": "success",
                "count": len(events),
                "meetings": [
                    {
                        "event_id": e["id"],
                        "subject": e.get("summary"),
                        "start": e["start"].get("dateTime"),
                        "end": e["end"].get("dateTime"),
                        "status": e.get("status"),
                    }
                    for e in events
                ]
            }

        except Exception as e:
            logger.error(f"Error listing meetings → {e}")
            return {}