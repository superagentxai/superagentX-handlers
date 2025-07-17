import asyncio
import logging
from typing import Optional

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)
POWERSHELL = "powershell.exe"

class DefenderO365GetHandler(BaseHandler):
    """
    Microsoft Defender for Office 365 - GET-only tools.
    Supports threat reports, quarantines, user submissions, and policy review.
    """

    def __init__(self):
        super().__init__()

    @tool
    async def list_email_threats(
            self,
            user: Optional[str] = None
    ):
        """
        List recent email threats detected for a specific user or across the organization.

        Args:
            user (str): Optional. Email/UPN to filter threats.

        Returns:
            str: Table of threat metadata.
        """
        ps = (f"Get-MessageTrace{' -RecipientAddress ' + user if user else ''} | Select Received, SenderAddress,"
              f" RecipientAddress, Subject, Status | Format-Table -AutoSize")
        return await self._run_ps(ps)

    @tool
    async def list_user_submissions(
            self,
            user: Optional[str] = None
    ):
        """
        List all user-submitted phishing or malware reports.

        Args:
            user (str): Optional. Filter by submitter.

        Returns:
            str: Submissions with verdicts and metadata.
        """
        user_filter = f" | Where-Object {{ $_.Submitter -like '{user}' }}" if user else ""
        ps = (f"Get-UserSubmission{user_filter} | Select Id, Submitter, Sender, Recipient, Subject, "
              f"SubmissionType, Verdict | Format-Table -AutoSize")
        return await self._run_ps(ps)

    @tool
    async def get_email_trace(
            self,
            message_id: Optional[str] = None
    ):
        """
        Trace the delivery of an email using its Message ID.

        Args:
            message_id (str): Optional. Shows recent trace if empty.

        Returns:
            str: Email trace details or summary.
        """
        if isinstance(message_id, str):
            ps = ("Get-MessageTrace | Select InternetMessageId, Received, SenderAddress, RecipientAddress, Subject, "
                  "Status | Format-Table -AutoSize")
        else:
            ps = (
                f"Get-MessageTraceDetail -MessageTraceId ("f"Get-MessageTrace | Where-Object {{$_.InternetMessageId -eq"
                f" '{message_id}'}} | ""Select -First 1 -ExpandProperty MessageTraceId"") | Format-Table EventDate, "
                "Action, Detail, RecipientAddress -AutoSize"
            )
        return await self._run_ps(ps)

    @tool
    async def list_quarantined_items(
            self,
            user: Optional[str] = None
    ):
        """
        Show quarantined messages for a user or organization.

        Args:
            user (str): Optional. Email to filter.

        Returns:
            str: Quarantine data with sender and subject.
        """
        ps = f"Get-QuarantineMessage{' -RecipientAddress ' + user if user else ''} | Select Received, Subject, SenderAddress, RecipientAddress, MessageId | Format-Table -AutoSize"
        return await self._run_ps(ps)

    @tool
    async def list_safe_links_policy(self):
        """
        List configured Safe Links policies.

        Returns:
            str: Table of policies and actions.
        """
        ps = "Get-SafeLinksPolicy | Select Name, Action, IsEnabled | Format-Table -AutoSize"
        return await self._run_ps(ps)

    @tool
    async def list_safe_attachment_policy(self):
        """
        View Safe Attachments policies.

        Returns:
            str: Policy names, actions, and status.
        """
        ps = "Get-SafeAttachmentPolicy | Select Name, Action, IsEnabled | Format-Table -AutoSize"
        return await self._run_ps(ps)

    @tool
    async def get_mail_detail_atp_report(
            self,
            domain: Optional[str] = None
    ):
        """
        Show ATP mail threat report.

        Args:
            domain (str): Optional. Filter by domain name (e.g., contoso.com).

        Returns:
            str: ATP threat data.
        """
        domain_filter = f" | Where-Object {{ $_.RecipientAddress -like '*@{domain}' }}" if domain else ""
        ps = (f"Get-MailDetailATPReport{domain_filter} | Select Date, EventType, RecipientAddress, SenderAddress, "
              f"Subject | Format-Table -AutoSize")
        return await self._run_ps(ps)

    @staticmethod
    async def _run_ps(
            command: str
    ):
        """Run a PowerShell command and return its output or raise error."""
        proc = await asyncio.create_subprocess_exec(
            POWERSHELL,
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command", command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.error(f"PowerShell error: {stderr.decode().strip()}")
            return []
        return stdout.decode().strip() or "<no data found>"