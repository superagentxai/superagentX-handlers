# gmail_handler.py
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build, logger
from superagentx.handler.base import BaseHandler
import base64
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

from superagentx.handler.decorators import tool

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send"
]


class GmailHandler(BaseHandler):
    """
    GmailHandler provides async utility methods for interacting with Gmail
    using the Gmail REST API.

    This handler supports common Gmail operations such as:
    - Sending emails (with or without attachments)
    - Reading recent emails
    - Fetching email details and attachments
    - Marking emails as read or unread
    - Deleting emails

    Authentication is handled via OAuth 2.0 access tokens, which must be
    valid and have the required Gmail scopes.

    All methods are asynchronous and designed to be used in async workflows
    or AI agent tools (LangChain `@tool`).

    Supported Operations:
        - send_emails
        - send_email_with_attachments
        - read_latest_email
        - read_email_details
        - get_email_attachments
        - mark_email_as_read
        - mark_email_as_unread
        - delete_email

    Notes:
        - Requires Gmail API scopes such as:
          `https://www.googleapis.com/auth/gmail.modify`
          `https://www.googleapis.com/auth/gmail.send`
        - Attachments are handled via multipart MIME encoding.
        - Errors related to expired or invalid tokens should be handled
          by refreshing tokens or re-authorizing the user.

    Raises:
        RuntimeError: If Gmail API calls fail.
        PermissionError: If OAuth scopes are insufficient.
        ValueError: If required parameters are missing or invalid.
    """
    def __init__(
            self,
            access_token: str,
            download_dir: str = "/tmp/gmail_downloads"
    ):
        """
        Initializes the Gmail handler with authentication details and configuration.

        Args:
            access_token (str): OAuth 2.0 access token used to authenticate
                requests to the Gmail API.
            download_dir (str, optional): Local directory path where downloaded
                email attachments will be stored. Defaults to "/tmp/gmail_downloads".

        Raises:
            ValueError: If the access_token is empty or invalid.
        """
        super().__init__()
        self.access_token = access_token
        self.last_seen_id = None

        # Ensure download_dir exists
        self.download_dir = os.path.abspath(download_dir)
        os.makedirs(self.download_dir, exist_ok=True)

        # Build Credentials with access_token only
        self.credentials = Credentials(token=self.access_token)
        self.service = build("gmail", "v1", credentials=self.credentials)

    # ------------------------------
    # Send email
    # ------------------------------
    @tool
    async def send_email(self, to: str, subject: str, body: str, attachments: list = None):
        """
    Sends an email using the Gmail API.

    Args:
        to (str): The recipient's email address.
        subject (str): The subject line of the email.
        body (str): The plain text body of the email.
        attachments (list, optional): A list of file paths to attach to the email. Defaults to None.

    Returns:
        dict: A dictionary containing the status of the send operation and the Gmail message ID if successful.
              Example: {"status": "success", "id": "1234567890"} or {"status": "failed", "error": "..."}.
    """
        try:
            from email.mime.text import MIMEText
            import base64

            message = MIMEText(body)
            message['to'] = to
            message['subject'] = subject

            raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

            sent_msg = self.service.users().messages().send(
                userId="me", body={'raw': raw}
            ).execute()

            return {"status": "success", "id": sent_msg.get("id")}
        except Exception as e:
            logger.error(f"Error sending Gmail → {e}")
            return {"status": "failed", "error": str(e)}

    # ------------------------------
    # Send mail with attachments
    # ------------------------------
    async def send_email_with_attachments(self, to: str, subject: str, body: str, attachments: list = None):
        """
        Sends an email using the Gmail API with optional file attachments.

        This method composes a multipart email message, attaches files if provided,
        encodes the message using Base64, and sends it through the authenticated
        Gmail API client.

        Args:
            to (str): Recipient email address.
            subject (str): Email subject line.
            body (str): Plain text content of the email body.
            attachments (list[str], optional): List of absolute file paths to attach
                to the email. Each file must exist on the local filesystem.
                Defaults to None.

        Returns:
            dict: Result of the email send operation.
                - On success:
                    {"status": "success", "id": "<gmail_message_id>"}
                - On failure:
                    {"status": "failed", "error": "<error_message>"}

        Raises:
            FileNotFoundError: If any attachment path does not exist.
        """
        try:
            # Create multipart email
            message = MIMEMultipart()
            message["to"] = to
            message["subject"] = subject

            # Email body
            message.attach(MIMEText(body, "plain"))

            # Attach files
            if attachments:
                for file_path in attachments:
                    if not os.path.exists(file_path):
                        raise FileNotFoundError(f"Attachment not found: {file_path}")

                    filename = os.path.basename(file_path)
                    with open(file_path, "rb") as f:
                        part = MIMEBase("application", "octet-stream")
                        part.set_payload(f.read())

                    encoders.encode_base64(part)
                    part.add_header(
                        "Content-Disposition",
                        f'attachment; filename="{filename}"'
                    )
                    message.attach(part)

            # Encode message
            raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

            sent_msg = self.service.users().messages().send(
                userId="me",
                body={"raw": raw}
            ).execute()

            return {"status": "success", "id": sent_msg.get("id")}

        except Exception as e:
            logger.error(f"Error sending Gmail → {e}")
            return {"status": "failed", "error": str(e)}

    # ------------------------------
    # Read latest emails
    # ------------------------------
    @tool
    async def read_latest_email(self, max_results: int = 5):
        """
           Reads the latest emails from the Gmail inbox.

           Args:
               max_results (int, optional): The maximum number of emails to fetch. Defaults to 5.

           Returns:
               list[dict] | None: A list of dictionaries representing each email. Each dictionary contains:
                   - id (str): The Gmail message ID.
                   - from (str): The sender's email address.
                   - to (str): The recipient's email address.
                   - subject (str): The subject line of the email.
                   - date (str): The date of the email.
                   - body (str): The plain text body of the email.
               Returns None if there are no new emails or if an error occurs.
           """
        try:
            result = self.service.users().messages().list(
                userId="me", maxResults=max_results
            ).execute()

            messages = result.get("messages", [])
            if not messages:
                return None

            new_emails = []

            for msg in messages:
                msg_id = msg["id"]
                if msg_id == self.last_seen_id:
                    break

                msg_data = self.service.users().messages().get(
                    userId="me", id=msg_id
                ).execute()

                payload = msg_data.get("payload", {})
                headers = payload.get("headers", [])

                email_info = {"id": msg_id}
                for header in headers:
                    name = header["name"].lower()
                    value = header["value"]
                    if name in ("from", "to", "subject", "date"):
                        email_info[name] = value

                # extract body
                body = ""
                if "parts" in payload:
                    for part in payload["parts"]:
                        data = part.get("body", {}).get("data")
                        if data:
                            body = base64.urlsafe_b64decode(data).decode()
                            break
                else:
                    data = payload.get("body", {}).get("data")
                    if data:
                        body = base64.urlsafe_b64decode(data).decode()

                email_info["body"] = body
                new_emails.append(email_info)

            self.last_seen_id = messages[0]["id"]
            return new_emails or None

        except Exception as e:
            logger.error(f"Error reading Gmail → {e}")
            return None

    # ------------------------------
    # Get email attachments
    # ------------------------------
    @tool
    async def get_email_attachments(self, message_id: str):
        """
        Retrieves all attachments from a specific Gmail message.

        Args:
            message_id (str): The Gmail message ID from which to extract attachments.

        Returns:
            list[dict]: A list of dictionaries, each containing:
                - filename (str): Name of the attachment file.
                - mimeType (str): MIME type of the attachment.
                - size (int): Size of the file in bytes.
                - data (bytes): The binary content of the file.
            Returns an empty list if no attachments are found or an error occurs.
        """
        try:
            msg = self.service.users().messages().get(
                userId="me", id=message_id
            ).execute()

            parts = msg.get("payload", {}).get("parts", [])
            attachments = []

            for part in parts:
                if part.get("filename") and part.get("body", {}).get("attachmentId"):
                    attachment_id = part["body"]["attachmentId"]

                    attachment = self.service.users().messages().attachments().get(
                        userId="me", messageId=message_id, id=attachment_id
                    ).execute()

                    data = base64.urlsafe_b64decode(attachment["data"])
                    attachments.append({
                        "filename": part["filename"],
                        "mimeType": part.get("mimeType"),
                        "size": part.get("body", {}).get("size", 0),
                        "data": data
                    })

            return attachments

        except Exception as e:
            logger.error(f"Error retrieving Gmail attachments → {e}")
            return []

    # ------------------------------
    # Delete email
    # ------------------------------
    @tool
    async def delete_email(self, message_id: str):
        """
        Deletes a Gmail message permanently.

        Args:
            message_id (str): The Gmail message ID to delete.

        Returns:
            dict: {"status": "success"} or {"status": "failed", "error": "..."}.
        """
        try:
            self.service.users().messages().delete(
                userId="me", id=message_id
            ).execute()

            return {"status": "success"}

        except Exception as e:
            logger.error(f"Error deleting Gmail → {e}")
            return {"status": "failed", "error": str(e)}

    # ------------------------------
    # Mark email as read
    # ------------------------------
    @tool
    async def mark_email_as_read(self, message_id: str):
        """
        Marks a Gmail message as read by removing the UNREAD label.

        Args:
            message_id (str): The Gmail message ID.

        Returns:
            dict: {"status": "success"} or {"status": "failed", "error": "..."}.
        """
        try:
            self.service.users().messages().modify(
                userId="me",
                id=message_id,
                body={"removeLabelIds": ["UNREAD"]}
            ).execute()

            return {"status": "success"}

        except Exception as e:
            logger.error(f"Error marking email as read → {e}")
            return {"status": "failed", "error": str(e)}

    # ------------------------------
    # Mark email as unread
    # ------------------------------
    @tool
    async def mark_email_as_unread(self, message_id: str):
        """
        Marks a Gmail message as unread by adding the UNREAD label.

        Args:
            message_id (str): The Gmail message ID.

        Returns:
            dict: {"status": "success"} or {"status": "failed", "error": "..."}.
        """
        try:
            self.service.users().messages().modify(
                userId="me",
                id=message_id,
                body={"addLabelIds": ["UNREAD"]}
            ).execute()

            return {"status": "success"}

        except Exception as e:
            logger.error(f"Error marking email as unread → {e}")
            return {"status": "failed", "error": str(e)}

    # ------------------------------
    # Read full email details
    # ------------------------------
    @tool
    async def read_email_details(self, message_id: str):
        """
        Reads the full details of a Gmail message, including headers, body, and attachments.

        Args:
            message_id (str): The Gmail message ID to read.

        Returns:
            dict | None: A dictionary containing:
                - id (str): Email ID
                - headers (dict): Key/value parsed headers
                - body_plain (str): Plain text body
                - body_html (str): HTML body (if available)
                - attachments (list): List of extracted attachments
              Returns None on error.
        """
        try:
            msg = self.service.users().messages().get(
                userId="me", id=message_id, format="full"
            ).execute()

            payload = msg.get("payload", {})
            headers_list = payload.get("headers", [])

            headers = {h["name"]: h["value"] for h in headers_list}

            # extract body
            body_plain, body_html = "", ""

            def extract_parts(parts):
                nonlocal body_plain, body_html
                for part in parts:
                    mime = part.get("mimeType")
                    data = part.get("body", {}).get("data")

                    if data:
                        decoded = base64.urlsafe_b64decode(data).decode(errors="ignore")
                        if mime == "text/plain":
                            body_plain = decoded
                        elif mime == "text/html":
                            body_html = decoded

                    if part.get("parts"):
                        extract_parts(part["parts"])

            if payload.get("parts"):
                extract_parts(payload["parts"])
            else:
                data = payload.get("body", {}).get("data")
                if data:
                    body_plain = base64.urlsafe_b64decode(data).decode(errors="ignore")

            # attachments
            attachments = await self.get_email_attachments(message_id)

            return {
                "id": message_id,
                "headers": headers,
                "body_plain": body_plain,
                "body_html": body_html,
                "attachments": attachments
            }

        except Exception as e:
            logger.error(f"Error reading full Gmail email → {e}")
            return None


