import asyncio
import logging
from datetime import datetime, time
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class GoogleCalendarHandler(BaseHandler):
    """
        Google Calendar handler that operates using an access token only.

        This handler provides async-safe utility methods for creating,
        rescheduling, listing, and deleting Google Calendar events using
        the Google Calendar v3 API.

        Design characteristics:
        - Uses access-token–only authentication (no refresh token).
        - Avoids token expiry handling and refresh logic.
        - Wraps blocking Google API calls using asyncio executors.
        - Safe for concurrent execution and pytest environments.

    """

    def __init__(self, access_token: str):
        if not access_token:
            raise ValueError("access_token is required")

        super().__init__()

        credentials = Credentials(
            token=access_token
        )

        def _no_refresh(request: Request):
            logger.debug("Refresh skipped (access-token-only)")
            return

        credentials.refresh = _no_refresh

        self.credentials = credentials

        self.service = build(
            "calendar",
            "v3",
            credentials=self.credentials,
            cache_discovery=False
        )

    @staticmethod
    async def sync_to_async(func):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, func)

    @staticmethod
    def _parse_local_datetime(
            date_str: str,
            time_str: str,
            timezone_name: str
    ) -> datetime:
        """
        Parse date & time strings into a timezone-aware datetime
        without converting to UTC.
        """
        tz = ZoneInfo(timezone_name)
        dt = datetime.strptime(
            f"{date_str} {time_str}",
            "%d-%m-%Y %H:%M"
        )
        return dt.replace(tzinfo=tz)

    @tool
    async def create_meeting(
            self,
            summary: str,
            start_date: str,  # "DD-MM-YYYY"
            start_time: str,  # "HH:MM"
            end_date: str,  # "DD-MM-YYYY"
            end_time: str,  # "HH:MM"
            attendees: Optional[List] = None,
            description: Optional[str] = None,
            timezone: str = "Asia/Kolkata"  # 👈 local timezone
    ) -> Dict[str, Any]:
        """
            Create a new Google Calendar meeting.

            The meeting is created using local timezone-aware datetimes
            and optional attendee notifications.

            Args:
                summary: Event title.
                start_date: Start date in "DD-MM-YYYY" format.
                start_time: Start time in "HH:MM" format.
                end_date: End date in "DD-MM-YYYY" format.
                end_time: End time in "HH:MM" format.
                attendees: Optional list of attendee email addresses.
                description: Optional event description.
                timezone: IANA timezone name for the event.

            Returns:
                A dictionary containing the status and event metadata.
            """
        try:
            start_dt = self._parse_local_datetime(
                start_date, start_time, timezone
            )
            end_dt = self._parse_local_datetime(
                end_date, end_time, timezone
            )

            if end_dt <= start_dt:
                raise ValueError("end time must be after start time")

            event = {
                "summary": summary,
                "description": description,
                "start": {
                    "dateTime": start_dt.isoformat(),  # ISO + offset
                    "timeZone": timezone
                },
                "end": {
                    "dateTime": end_dt.isoformat(),  # ISO + offset
                    "timeZone": timezone
                }
            }

            if attendees:
                event["attendees"] = [{"email": a} for a in attendees]

            created = await self.sync_to_async(
                lambda: self.service.events().insert(
                    calendarId="primary",
                    body=event,
                    sendUpdates="all"
                ).execute()
            )

            return {
                "status": "success",
                "event_id": created["id"],
                "start": created["start"]["dateTime"],
                "end": created["end"]["dateTime"]
            }

        except Exception as e:
            logger.error(f"Error creating meeting → {e}")
            return {"status": "failed", "error": str(e)}

    @tool
    async def reschedule_meeting(
            self,
            summary: str,
            search_date: str,
            new_start_date: str,
            new_start_time: str,
            new_end_date: str,
            new_end_time: str
    ) -> Dict[str, Any]:
        """
            Reschedule an existing meeting identified by its summary and date.

            The method searches for a single matching event on the specified
            date and updates its start and end times using local timezone
            semantics.

            Args:
                summary: Event title to search for.
                search_date: Date to search in "DD-MM-YYYY" format.
                new_start_date: New start date in "DD-MM-YYYY" format.
                new_start_time: New start time in "HH:MM" format.
                new_end_date: New end date in "DD-MM-YYYY" format.
                new_end_time: New end time in "HH:MM" format.

            Returns:
                A dictionary containing the status and updated event metadata.

            Raises:
                ValueError: If no matching event or multiple events are found.
            """
        try:
            tz_name = getattr(self, "timezone", "Asia/Kolkata")
            tz = ZoneInfo(tz_name)

            def _day_range(date_str: str):
                day = datetime.strptime(date_str, "%d-%m-%Y").date()
                start = datetime.combine(day, time.min).replace(tzinfo=tz)
                end = datetime.combine(day, time.max).replace(tzinfo=tz)
                return start.isoformat(), end.isoformat()

            # Find meeting
            time_min, time_max = _day_range(search_date)

            events = await self.sync_to_async(
                lambda: self.service.events().list(
                    calendarId="primary",
                    q=summary,
                    timeMin=time_min,
                    timeMax=time_max,
                    singleEvents=True,
                    orderBy="startTime"
                ).execute()
            )

            items = events.get("items", [])

            if not items:
                raise ValueError(
                    f"No meeting found with subject '{summary}' on {search_date}"
                )

            if len(items) > 1:
                raise ValueError(
                    "Multiple meetings found. Use unique subject or adjust search_date."
                )

            event = items[0]

            start_dt = self._parse_local_datetime(
                new_start_date, new_start_time, tz_name
            )
            end_dt = self._parse_local_datetime(
                new_end_date, new_end_time, tz_name
            )

            if end_dt <= start_dt:
                raise ValueError("new end time must be after new start time")

            event["start"]["dateTime"] = start_dt.isoformat()
            event["start"]["timeZone"] = tz_name
            event["end"]["dateTime"] = end_dt.isoformat()
            event["end"]["timeZone"] = tz_name

            updated = await self.sync_to_async(
                lambda: self.service.events().update(
                    calendarId="primary",
                    eventId=event["id"],
                    body=event,
                    sendUpdates="all"
                ).execute()
            )

            return {
                "status": "success",
                "event_id": updated["id"],
                "updated_start": updated["start"]["dateTime"],
                "updated_end": updated["end"]["dateTime"]
            }

        except Exception as e:
            logger.error(f"Error rescheduling meeting → {e}")
            return {"status": "failed", "error": str(e)}



    @tool
    async def list_meetings(
        self,
        max_results: int = 10,
        from_now: bool = True
    ):
        """
           List upcoming Google Calendar meetings.

           Args:
               max_results: Maximum number of events to return.
               from_now: If True, only events starting from the current
                         UTC time are included.

           Returns:
               A list of meeting dictionaries containing basic event details.
           """
        try:
            params = {
                "calendarId": "primary",
                "maxResults": max_results,
                "singleEvents": True,
                "orderBy": "startTime"
            }

            if from_now:
                params["timeMin"] = datetime.utcnow().isoformat() + "Z"

            result = await self.sync_to_async(
                lambda: self.service.events().list(**params).execute()
            )

            events = result.get("items", [])
            meetings = []

            for event in events:
                meetings.append({
                    "id": event.get("id"),
                    "summary": event.get("summary"),
                    "start": event.get("start"),
                    "end": event.get("end"),
                    "htmlLink": event.get("htmlLink")
                })

            return meetings

        except Exception as e:
            logger.error(f"Error listing meetings → {e}")
            return []

    @tool
    async def clear_all_meetings(
            self,
            start_date: Optional[str] = None  # Optional: "DD-MM-YYYY", if not provided, defaults to today
    ) -> Dict[str, Any]:
        """
        Deletes all Google Calendar events starting from start_date (or today if None).

        Args:
            start_date: Optional start date in "DD-MM-YYYY" format. Defaults to today.

        Returns:
            Dict with status and number of deleted events or errors.
        """
        try:
            # 1️⃣ Determine starting point
            if start_date:
                start_dt = datetime.strptime(start_date, "%d-%m-%Y").replace(
                    hour=0, minute=0, second=0, tzinfo=timezone.utc
                )
            else:
                start_dt = datetime.now(timezone.utc)

            time_min = start_dt.isoformat()

            # 2️⃣ List all events from start_date
            events_result = await self.sync_to_async(
                lambda: self.service.events().list(
                    calendarId="primary",
                    timeMin=time_min,
                    singleEvents=True,
                    orderBy="startTime"
                ).execute()
            )

            events = events_result.get("items", [])

            if not events:
                return {"status": "success", "deleted_count": 0, "message": "No meetings to delete."}

            deleted_events = []

            # 3️⃣ Delete events one by one
            for event in events:
                event_id = event["id"]
                await self.sync_to_async(
                    lambda event_id=event_id: self.service.events().delete(
                        calendarId="primary",
                        eventId=event_id
                    ).execute()
                )
                deleted_events.append(event_id)

            return {
                "status": "success",
                "deleted_count": len(deleted_events),
                "deleted_events": deleted_events
            }

        except Exception as e:
            logger.error(f"Error clearing meetings → {e}")
            return {"status": "failed", "error": str(e)}
