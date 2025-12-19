import logging
import os

import pytest

from superagentx_handlers.google.gmail import GmailHandler

logger = logging.getLogger(__name__)

'''
  Run Pytest:
    1.pytest --log-cli-level=INFO tests/google/test_gmail_handler.py::TestGmailHandler::test_send_email
    2.pytest --log-cli-level=INFO tests/google/test_gmail_handler.py::TestGmailHandler::test_read_last_mail
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
    async def test_download_attachments(self, gmail_handler_init: GmailHandler):
        """
        Finds the first email that has attachments.
        Downloads them into /tmp/gmail_downloads.
        """
        emails = await gmail_handler_init.read_latest_email(max_results=10)
        assert emails, "No emails available"

        attachment_msg_id = None

        # Step 1: find an email with attachments
        for email in emails:
            full = await gmail_handler_init.read_email_details(email["id"])
            if full.get("attachments"):
                attachment_msg_id = email["id"]
                break
        logger.info(attachment_msg_id)
        if attachment_msg_id is None:
            pytest.skip("No email with attachments found — skipping")

        # Step 2: download attachments
        files = await gmail_handler_init.get_email_attachments(attachment_msg_id)

        logger.info(f"Downloaded files => {files}")

        assert isinstance(files, list)
        assert len(files) >= 1
        # for file in files:
        #     logger.info(file['path'])
        #     assert file["path"].startswith("/tmp/gmail_downloads")
        #     assert os.path.exists(file["path"])

    @pytest.mark.asyncio
    async def test_delete_email(self, gmail_handler_init: GmailHandler):
        message_id = ''
        delete_res = await gmail_handler_init.delete_email(message_id)
        logger.info(f"Delete Result => {delete_res}")
        assert delete_res["status"] == "success"
