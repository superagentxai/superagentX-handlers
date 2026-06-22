import logging
import os

import pytest

from superagentx_handlers.google.gmail import GmailHandler

logger = logging.getLogger(__name__)

'''
  Run Pytest:
    1.pytest --log-cli-level=INFO tests/google/test_gmail_handler.py::TestGmailHandler::test_send_email
    2.pytest --log-cli-level=INFO tests/google/test_gmail_handler.py::TestGmailHandler::test_read_last_mail
    3.pytest --log-cli-level=INFO tests/google/test_gmail_handler.py::TestGmailHandler::test_download_attachments
'''


@pytest.fixture
def gmail_handler_init():
    return GmailHandler(
        access_token=""
    )


class TestGmailHandler:

    @pytest.mark.asyncio
    async def test_send_email(self, gmail_handler_init: GmailHandler):

        res = await gmail_handler_init.send_email(
            to="elangorajen@gmail.com",
            subject=" Test Token",
            body="Testing Gmail send email using DB tokens.",
            attachments=None
        )

        logger.info(f"Send Result => {res}")
        assert res["status"] == "success"

    @pytest.mark.asyncio
    async def test_send_email_with_attachments(self, gmail_handler_init: GmailHandler):

        res = await gmail_handler_init.send_email_with_attachments(
            to="elangorajen@gmail.com",
            subject=" Test Token",
            body="Testing Gmail send email using DB tokens.",
            attachments=[
                "/home/elangovanr/Pictures/Screenshots/Screenshot From 2025-09-17 16-21-07.png"
            ]
        )

        logger.info(f"Send Result => {res}")
        assert res["status"] == "success"

    @pytest.mark.asyncio
    async def test_read_last_mail(self, gmail_handler_init: GmailHandler):
        """
        Test reading the latest emails.
        """
        # Read latest emails
        emails = await gmail_handler_init.read_latest_email(max_results=5)

        # logger.info(f"Latest Emails => {emails}")

        # Basic assertions
        assert emails is not None, "No emails returned"
        assert isinstance(emails, list), "Emails should be a list"
        for email in emails:
            assert "from" in email, "Email must have 'from' field"
            assert "subject" in email, "Email must have 'subject' field"
            assert "body" in email, "Email must have 'body' field"

        # Optionally print the first email details
        if emails:
            logger.info(emails)
            logger.info(f"First email: From={emails[0]['from']}, Subject={emails[0]['subject']}")

    # ------------------------------
    # Test: Read Email Details (Full)
    # ------------------------------
    @pytest.mark.asyncio
    async def test_read_email_details(self, gmail_handler_init: GmailHandler):
        """
        Step 1: Read latest email to get an ID
        Step 2: Read full details of that email
        """
        emails = await gmail_handler_init.read_latest_email(max_results=1)
        assert emails, "No latest emails to fetch details for"

        msg_id = emails[0]["id"]

        details = await gmail_handler_init.read_email_details(msg_id)

        logger.info(f"Full Email Details => {details}")

        assert details is not None
        assert "id" in details
        assert "headers" in details
        assert "body_plain" in details
        assert "body_html" in details
        assert "attachments" in details

    # ------------------------------
    # Test: Download Attachments
    # ------------------------------
    @pytest.mark.asyncio
    async def test_download_attachments(self, gmail_handler_init: GmailHandler, tmp_path):
        """
        Downloads attachments from unread Gmail emails and marks them as read.
        """

        download_dir = ""

        emails = await gmail_handler_init.download_attachments(
            download_dir=str(download_dir),
            max_results=1
        )

        if not emails:
            pytest.skip("No unread emails found or no attachments downloaded")

        assert isinstance(emails, list)

        emails_with_attachments = [
            email for email in emails if email.get("attachments")
        ]

        if not emails_with_attachments:
            pytest.skip("Unread emails found, but none had attachments")

        for email in emails_with_attachments:
            assert "id" in email
            assert isinstance(email["attachments"], list)
            assert len(email["attachments"]) >= 1

            for attachment in email["attachments"]:
                assert attachment["filename"]
                assert attachment["path"].startswith(str(download_dir))
                assert os.path.exists(attachment["path"])
                assert os.path.isfile(attachment["path"])
                assert attachment["size"] >= 0

                logger.info(f"Downloaded attachment => {attachment['path']}")

    @pytest.mark.asyncio
    async def test_delete_email(self, gmail_handler_init: GmailHandler):
        message_id = ''
        delete_res = await gmail_handler_init.delete_email(message_id)
        logger.info(f"Delete Result => {delete_res}")
        assert delete_res["status"] == "success"
