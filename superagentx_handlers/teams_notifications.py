import os
import requests
import logging
from datetime import datetime
from typing import List

from superagentx.handler.decorators import tool
from superagentx.handler.base import BaseHandler
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


class NotificationError(Exception):
    pass


class TeamsNotification(BaseHandler):

    # =========================
    # SEND TEAMS NOTIFICATION
    # =========================
    @tool
    async def send_teams_notification(
        self,
        title: str,
        message_lines: List[str]
    ) -> dict:
        """
        Sends a formatted deployment notification to Microsoft Teams using an Adaptive Card.

        This function constructs an Adaptive Card payload using the provided title and message lines,
        and sends it to a Teams channel via an incoming webhook URL defined in the environment variable
        `TEAMS_WEBHOOK_URL`.

        Args:
            title (str): The title of the notification (e.g., "DEPLOYMENT SUCCESS" or "DEPLOYMENT FAILED").
            message_lines (List[str]): A list of strings where each item represents a line in the message body.

        Returns:
            dict: A dictionary indicating the status of the notification (e.g., {"status": "sent"}).

        Raises:
            NotificationError: If the webhook URL is not set or if the Teams API returns an error response.
        """
        webhook_url = os.getenv("TEAMS_WEBHOOK_URL")

        if not webhook_url:
            raise NotificationError("TEAMS_WEBHOOK_URL not set")

        # -------------------------
        # BUILD ADAPTIVE CARD BODY
        # -------------------------
        body = [
            {
                "type": "TextBlock",
                "text": title,
                "weight": "Bolder",
                "size": "Medium"
            }
        ]

        for line in message_lines:
            body.append({
                "type": "TextBlock",
                "text": line,
                "wrap": True
            })

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.2",
                        "body": body
                    }
                }
            ]
        }

        # -------------------------
        # SEND REQUEST (ASYNC SAFE)
        # -------------------------
        response = await sync_to_async(
            requests.post,
            webhook_url,
            json=payload
        )

        print("STATUS:", response.status_code)
        print("RESPONSE:", response.text)

        if response.status_code >= 400:
            raise NotificationError(response.text)

        print("Teams notification sent")

        return {"status": "sent"}


    # =========================
    # FORMAT SUCCESS MESSAGE
    # =========================
    @tool
    async def format_success_message(
        self,
        repo: str,
        branch: str,
        pr_number: int,
        author: str,
        container: str,
        image: str,
        port: str
    ) -> List[str]:
        """
        Formats a deployment success message for Teams notification.

        This function prepares a structured list of message lines containing deployment details
        such as repository name, branch, PR information, container details, and deployment URL.

        Args:
            repo (str): Name of the repository.
            branch (str): Target branch where the PR was merged.
            pr_number (int): Pull request number.
            author (str): Username of the PR author.
            container (str): Name of the Docker container.
            image (str): Name of the Docker image.
            port (str): Port on which the application is exposed.

        Returns:
            List[str]: A list of formatted strings representing the success message content.
        """
        return [
            f"Repo        : {repo}",
            f"Branch      : {branch}",
            f"PR          : #{pr_number} ({author})",
            f"Container   : {container}",
            f"Image       : {image}:latest",
            f"URL         : http://localhost:{port}",
            f"Time        : {datetime.now().strftime('%Y-%m-%d %I:%M %p')}",
            "Trigger     : PR Merge"
        ]


    # =========================
    # FORMAT FAILURE MESSAGE
    # =========================
    @tool
    async def format_failure_message(
        self,
        repo: str,
        branch: str,
        pr_number: int,
        author: str,
        error: str
    ) -> List[str]:
        """
        Formats a deployment failure message for Teams notification.

        This function prepares a structured list of message lines containing failure details,
        including repository, branch, PR information, and the error message encountered during deployment.

        Args:
            repo (str): Name of the repository.
            branch (str): Target branch where the PR was merged.
            pr_number (int): Pull request number.
            author (str): Username of the PR author.
            error (str): Error message describing the failure.

        Returns:
            List[str]: A list of formatted strings representing the failure message content.
        """
        return [
            f"Repo        : {repo}",
            f"Branch      : {branch}",
            f"PR          : #{pr_number} ({author})",
            f"Error       : {error}",
            f"Time        : {datetime.now().strftime('%Y-%m-%d %I:%M %p')}",
            "Trigger     : PR Merge"
        ]