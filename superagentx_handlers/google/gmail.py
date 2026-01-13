import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import logging

logger = logging.getLogger(__name__)


async def send_email_with_attachments(
        self,
        to: str,
        subject: str,
        body: str,
        attachments: list | None = None,
):
    """
    Sends an email using the Gmail API with optional base64 attachments.

    Attachments are expected in the format:
    [
        {
            "name": "file.pdf",
            "type": "application/pdf",
            "base64": "<base64-string>"
        }
    ]
    """

    try:
        # Create multipart email
        message = MIMEMultipart()
        message["to"] = to
        message["subject"] = subject

        # Email body
        message.attach(MIMEText(body, "plain"))

        # Attach base64 files
        if attachments:
            if not isinstance(attachments, list):
                raise TypeError("attachments must be a list")

            for attachment in attachments:
                if not isinstance(attachment, dict):
                    raise TypeError("Each attachment must be a dict")

                filename = attachment.get("name")
                mime_type = attachment.get("type", "application/octet-stream")
                b64_data = attachment.get("base64")

                if not filename or not b64_data:
                    raise ValueError("Attachment must contain 'name' and 'base64'")

                # Split mime type
                main_type, sub_type = mime_type.split("/", 1)

                # Decode base64
                file_bytes = base64.b64decode(b64_data)

                part = MIMEBase(main_type, sub_type)
                part.set_payload(file_bytes)
                encoders.encode_base64(part)

                part.add_header(
                    "Content-Disposition",
                    f'attachment; filename="{filename}"'
                )

                message.attach(part)

        # Encode message for Gmail API
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

        sent_msg = await self.sync_to_async(
            lambda: self.service.users().messages().send(
                userId="me",
                body={"raw": raw}
            ).execute()
        )

        return {
            "status": "success",
            "id": sent_msg.get("id")
        }

    except Exception as e:
        logger.error(f"Error sending Gmail → {e}", exc_info=True)
        return {
            "status": "failed",
            "error": str(e)
        }


# ------------------------------
# Read latest emails
# ------------------------------
@tool
async def read_latest_email(self, max_results: int = 5):
    try:
        result = await self.sync_to_async(
            lambda: self.service.users().messages().list(
                userId="me",
                maxResults=max_results
            ).execute()
        )

        logger.info(f"Read Mail: {result}")

        messages = result.get("messages", [])
        if not messages:
            return None

        new_emails = []

        for msg in messages:
            msg_id = msg["id"]
            if msg_id == self.last_seen_id:
                break

            msg_data = await self.sync_to_async(
                lambda msg_id=msg_id: self.service.users().messages().get(
                    userId="me",
                    id=msg_id
                ).execute()
            )

            payload = msg_data.get("payload", {})
            headers = payload.get("headers", [])

            email_info = {"id": msg_id}
            for header in headers:
                name = header["name"].lower()
                if name in ("from", "to", "subject", "date"):
                    email_info[name] = header["value"]

            # Extract body safely
            body = ""
            if "parts" in payload:
                for part in payload["parts"]:
                    data = part.get("body", {}).get("data")
                    if data:
                        body = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
                        break
            else:
                data = payload.get("body", {}).get("data")
                if data:
                    body = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")

            email_info["body"] = body
            new_emails.append(email_info)

        self.last_seen_id = messages[0]["id"]
        return new_emails or None

    except Exception as e:
        logger.exception("Error reading Gmail")
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
        msg = await self.sync_to_async(self.service.users().messages().get(
            userId="me", id=message_id
        ).execute())

        parts = msg.get("payload", {}).get("parts", [])
        attachments = []

        for part in parts:
            if part.get("filename") and part.get("body", {}).get("attachmentId"):
                attachment_id = part["body"]["attachmentId"]

                attachment = await self.sync_to_async(self.service.users().messages().attachments().get(
                    userId="me", messageId=message_id, id=attachment_id
                ).execute())

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
        await self.sync_to_async(self.service.users().messages().delete(
            userId="me", id=message_id
        ).execute())

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
        await self.sync_to_async(self.service.users().messages().modify(
            userId="me",
            id=message_id,
            body={"removeLabelIds": ["UNREAD"]}
        ).execute())

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
        await self.sync_to_async(self.service.users().messages().modify(
            userId="me",
            id=message_id,
            body={"addLabelIds": ["UNREAD"]}
        ).execute())

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
        msg = await self.sync_to_async(self.service.users().messages().get(
            userId="me", id=message_id, format="full"
        ).execute())

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


@tool
async def download_attachments(
        self,
        download_dir: str,
        max_results: int
):
    """
    Reads latest Gmail messages and downloads attachments from new emails.

    Returns:
        list[dict]: Email metadata with downloaded attachment info
    """

    try:
        # Ensure download directory exists
        os.makedirs(download_dir, exist_ok=True)

        result = await self.sync_to_async(
            lambda: self.service.users().messages().list(
                userId="me",
                maxResults=max_results
            ).execute()
        )

        messages = result.get("messages", [])
        if not messages:
            return None

        new_emails = []

        for msg in messages:
            msg_id = msg["id"]

            # Stop if we reached last seen email
            if msg_id == self.last_seen_id:
                break

            msg_data = await self.sync_to_async(
                lambda msg_id=msg_id: self.service.users().messages().get(
                    userId="me",
                    id=msg_id
                ).execute()
            )

            payload = msg_data.get("payload", {})
            headers = payload.get("headers", [])

            email_info = {
                "id": msg_id,
                "attachments": []
            }

            # Extract headers
            for header in headers:
                name = header["name"].lower()
                if name in ("from", "to", "subject", "date"):
                    email_info[name] = header["value"]

            # Process attachments
            parts = payload.get("parts", [])
            for part in parts:
                filename = part.get("filename")
                attachment_id = part.get("body", {}).get("attachmentId")

                if filename and attachment_id:
                    attachment = await self.sync_to_async(
                        lambda attachment_id=attachment_id: self.service
                        .users()
                        .messages()
                        .attachments()
                        .get(
                            userId="me",
                            messageId=msg_id,
                            id=attachment_id
                        )
                        .execute()
                    )

                    file_data = base64.urlsafe_b64decode(attachment["data"])
                    file_path = os.path.join(download_dir, filename)

                    with open(file_path, "wb") as f:
                        f.write(file_data)

                    email_info["attachments"].append({
                        "filename": filename,
                        "mimeType": part.get("mimeType"),
                        "size": part.get("body", {}).get("size", 0),
                        "path": file_path
                    })

                    logger.info(f"Downloaded attachment → {file_path}")

            new_emails.append(email_info)

        # Update last seen message ID
        self.last_seen_id = messages[0]["id"]

        return new_emails or None

    except Exception as e:
        logger.exception("Error reading emails and downloading attachments")
        return None