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

# SCOPES = [
#     "https://www.googleapis.com/auth/calendar",
#     "https://www.googleapis.com/auth/calendar.events"
# ]


class GoogleCalendarHandler(BaseHandler):
    """
    Google Calendar handler using ACCESS TOKEN ONLY.

    ✔ No refresh token
    ✔ No expiry math
    ✔ No invalid property assignment
    ✔ pytest + parallel safe
    """

    def __init__(self, access_token: str):
        if not access_token:
            raise ValueError("access_token is required")

        super().__init__()

        credentials = Credentials(
            token=access_token,
            # scopes=SCOPES
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

    @tool
    async def create_meeting(
            self,
            summary: str,
            start_date: str,  # "DD-MM-YYYY"
            start_time: str,  # "HH:MM"
            end_date: str,  # "DD-MM-YYYY"
            end_time: str,  # "HH:MM"
            attendees: Optional[List[str]] = None,
            description: Optional[str] = None,
            timezone: str = "Asia/Kolkata"  # 👈 local timezone
    ) -> Dict[str, Any]:
        try:
            tz = ZoneInfo(timezone)

            def _parse(date_str: str, time_str: str) -> datetime:
                dt = datetime.strptime(
                    f"{date_str} {time_str}",
                    "%d-%m-%Y %H:%M"
                )
                return dt.replace(tzinfo=tz)  # 👈 NO UTC conversion

            start_dt = _parse(start_date, start_time)
            end_dt = _parse(end_date, end_time)

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
            search_date: str,  # "DD-MM-YYYY"
            new_start_date: str,  # "DD-MM-YYYY"
            new_start_time: str,  # "HH:MM"
            new_end_date: str,  # "DD-MM-YYYY"
            new_end_time: str  # "HH:MM"
    ) -> Dict[str, Any]:
        """
        Reschedules an existing meeting by subject and search_date.
        Uses ISO datetime with LOCAL timezone from handler (not UTC).
        """
        try:
            # Use handler's default timezone or fallback
            tz_name = getattr(self, "timezone", "Asia/Kolkata")
            tz = ZoneInfo(tz_name)

            # -----------------------------
            # Helper functions
            # -----------------------------
            def _parse(date_str: str, time_str: str) -> datetime:
                dt = datetime.strptime(
                    f"{date_str} {time_str}",
                    "%d-%m-%Y %H:%M"
                )
                return dt.replace(tzinfo=tz)  # ISO local

            def _day_range(date_str: str):
                day = datetime.strptime(date_str, "%d-%m-%Y").date()
                start = datetime.combine(day, time.min).replace(tzinfo=tz)
                end = datetime.combine(day, time.max).replace(tzinfo=tz)
                return start.isoformat(), end.isoformat()

            def _reschedule():
                service = self.service

                # Find meeting on that day
                time_min, time_max = _day_range(search_date)

                events = service.events().list(
                    calendarId="primary",
                    q=summary,
                    timeMin=time_min,
                    timeMax=time_max,
                    singleEvents=True,
                    orderBy="startTime"
                ).execute().get("items", [])

                if not events:
                    raise ValueError(
                        f"No meeting found with subject '{summary}' on {search_date}"
                    )

                if len(events) > 1:
                    raise ValueError(
                        "Multiple meetings found. Use unique subject or adjust search_date."
                    )

                event = events[0]

                # Parse new times
                start_dt = _parse(new_start_date, new_start_time)
                end_dt = _parse(new_end_date, new_end_time)

                if end_dt <= start_dt:
                    raise ValueError("new end time must be after new start time")

                # Update event
                event["start"]["dateTime"] = start_dt.isoformat()
                event["start"]["timeZone"] = tz_name
                event["end"]["dateTime"] = end_dt.isoformat()
                event["end"]["timeZone"] = tz_name

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
            return {"status": "failed", "error": str(e)}
    @tool
    async def list_meetings(
        self,
        max_results: int = 10,
        from_now: bool = True
    ):
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
            start_date: str = None  # Optional: "DD-MM-YYYY", if not provided, defaults to today
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
