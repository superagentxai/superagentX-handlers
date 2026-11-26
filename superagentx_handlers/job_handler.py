from __future__ import annotations

import asyncio
import base64
import copy
import json
import logging
import os
import uuid
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


logger = logging.getLogger(__name__)


class JobCustomHandler(BaseHandler):
    """
    Generic job creation handler for file-storage providers.

    Supported providers are not hardcoded. The provider name and credentials
    are read from the previous provider handler result.

    Expected inputs:
        query: Job/orchestrator input.
        data: Previous provider handler result.

    Responsibilities:
        - Extract the provider result from common task/tool wrappers.
        - Encrypt the complete provider credentials.
        - Generate a unique runId for every file.
        - Build common file metadata.
        - Replace the orchestrator cursorData with the latest provider cursorData, preserving provider-specific cursor fields.
        - Preserve the provider handler's agentStatus, including failures.

    Encryption format:
        credentialKey:
            Base64(salt)

        jobInfo.credentials:
            Base64(IV + AES-GCM ciphertext + authentication tag)

    Key derivation:
        PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte key.
    """

    ITERATIONS = 600_000
    SALT_LENGTH = 16
    IV_LENGTH = 12
    KEY_LENGTH = 32

    def __init__(
        self,
        master_key: str | None = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.master_key = master_key or os.getenv("MASTER_KEY")
        logger.info("JobCustomHandler initialized.")

    # ------------------------------------------------------------------
    # ASYNC EXECUTOR
    # ------------------------------------------------------------------

    @staticmethod
    async def sync_to_async(func: Callable[[], Any]) -> Any:
        """Run blocking encryption and payload-building work off the event loop."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, func)

    # ------------------------------------------------------------------
    # PROVIDER RESULT EXTRACTION
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_provider_result(
        previous_result: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Unwrap common agent/task/tool result envelopes.

        Supported examples:
            {"success": True, "result": {"provider": "...", ...}}

            {"some_tool_name": {
                "success": True,
                "result": {"provider": "...", ...}
            }}

            {"provider": "...", ...}

        A provider agentStatus.status == "FAILED" is deliberately NOT raised
        as an exception. The job still needs to be prepared so credentials can
        be encrypted and the original provider failure can be forwarded.
        """

        if not isinstance(previous_result, dict):
            raise ValueError(
                "Previous provider result must be a dictionary."
            )

        result: Any = previous_result

        # Unwrap a limited number of envelopes to avoid accidental infinite
        # loops if malformed/cyclic data is supplied.
        for _ in range(10):
            if not isinstance(result, dict):
                raise ValueError("Invalid provider agent result.")

            if isinstance(result.get("provider"), str):
                break

            nested_result = result.get("result")
            if isinstance(nested_result, dict):
                result = nested_result
                continue

            # Some task engines return a tool-name wrapper. Unwrap only when
            # it is clearly a single wrapper around another result dictionary.
            if len(result) == 1:
                only_value = next(iter(result.values()))
                if isinstance(only_value, dict):
                    result = only_value
                    continue

            break

        if not isinstance(result, dict):
            raise ValueError("Invalid provider agent result.")

        provider = result.get("provider")
        if not isinstance(provider, str) or not provider.strip():
            raise ValueError(
                "Provider is missing from previous agent result."
            )

        agent_status = result.get("agentStatus", {})
        if not isinstance(agent_status, dict):
            raise ValueError(
                "Provider agentStatus must be a dictionary."
            )

        return result

    # ------------------------------------------------------------------
    # KEY DERIVATION
    # ------------------------------------------------------------------

    @classmethod
    def _derive_key(
        cls,
        master_password: str,
        salt: bytes,
    ) -> bytes:
        """Derive a 256-bit AES key using PBKDF2-HMAC-SHA256."""

        if not isinstance(master_password, str) or not master_password:
            raise ValueError("Master password must be a non-empty string.")

        if not isinstance(salt, bytes) or len(salt) != cls.SALT_LENGTH:
            raise ValueError("Invalid encryption salt.")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=cls.KEY_LENGTH,
            salt=salt,
            iterations=cls.ITERATIONS,
        )
        return kdf.derive(master_password.encode("utf-8"))

    # ------------------------------------------------------------------
    # CREDENTIAL ENCRYPTION
    # ------------------------------------------------------------------

    def _encrypt_credentials(
        self,
        credentials: dict[str, Any],
        master_password: str,
    ) -> tuple[str, str]:
        """
        Encrypt the complete provider credentials dictionary.

        Returns:
            encrypted_credentials: Base64(IV + ciphertext + GCM tag)
            credential_key: Base64(salt)
        """

        if not isinstance(credentials, dict) or not credentials:
            raise ValueError(
                "Provider credentials are missing or invalid."
            )

        if not isinstance(master_password, str) or not master_password:
            raise ValueError("Master key is not configured.")

        salt = os.urandom(self.SALT_LENGTH)
        key = self._derive_key(master_password, salt)
        iv = os.urandom(self.IV_LENGTH)

        credentials_json = json.dumps(
            credentials,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        encrypted_bytes = AESGCM(key).encrypt(
            iv,
            credentials_json,
            None,
        )

        encrypted_data = base64.b64encode(
            iv + encrypted_bytes
        ).decode("ascii")

        credential_key = base64.b64encode(salt).decode("ascii")
        return encrypted_data, credential_key

    # ------------------------------------------------------------------
    # RUN ID
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_run_id() -> str:
        """Generate a unique run ID for one file."""
        return str(uuid.uuid4())

    # ------------------------------------------------------------------
    # FILE METADATA
    # ------------------------------------------------------------------

    def _build_file_metadata(
        self,
        files: list[dict[str, Any]],
        credentials: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Normalize common file metadata without provider-specific branching.

        Provider handlers should supply filename/name and remotePath, fileId,
        id, or webUrl. For cloud providers, remotePath may be the file ID.
        """

        if not isinstance(files, list):
            raise ValueError("Provider files must be provided as a list.")

        local_path = credentials.get("localPath")
        batch_metadata: list[dict[str, Any]] = []

        for file_item in files:
            if not isinstance(file_item, dict):
                raise ValueError(
                    "Each file metadata entry must be a dictionary."
                )

            filename = file_item.get("filename") or file_item.get("name")
            remote_path = (
                file_item.get("remotePath")
                or file_item.get("fileId")
                or file_item.get("id")
                or file_item.get("webUrl")
            )

            if not filename:
                raise ValueError(
                    "File metadata is missing filename."
                )

            if not remote_path:
                raise ValueError(
                    "File metadata is missing remotePath or file identifier: "
                    f"{filename}"
                )

            batch_metadata.append(
                {
                    "runId": self._generate_run_id(),
                    "filename": filename,
                    "localPath": file_item.get("localPath") or local_path,
                    "remotePath": remote_path,
                    "size": file_item.get("size"),
                    "modifiedTime": file_item.get("modifiedTime"),
                }
            )

        return batch_metadata

    # ------------------------------------------------------------------
    # CURSOR DATA
    # ------------------------------------------------------------------

    @staticmethod
    def _build_cursor_data(
        cursor: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        """
        Preserve cursorData exactly as supplied by the provider handler.

        Do not rename lastCheckedAt to lastCheckedTime or convert timestamps:
        provider handlers may rely on their original cursor schema (for
        example, SFTP expects an ISO-8601 lastCheckedAt value).
        """

        if cursor is None:
            return None

        if not isinstance(cursor, dict):
            raise ValueError(
                "Provider cursorData must be a dictionary or None."
            )

        return copy.deepcopy(cursor)

    # ------------------------------------------------------------------
    # AGENT STATUS
    # ------------------------------------------------------------------

    @staticmethod
    def _build_agent_status(
        provider_result: dict[str, Any],
    ) -> dict[str, Any]:
        """Preserve provider status fields and provide defaults if absent."""

        agent_status = provider_result.get("agentStatus") or {}

        if not isinstance(agent_status, dict):
            raise ValueError(
                "Provider agentStatus must be a dictionary."
            )

        final_status = copy.deepcopy(agent_status)
        final_status.setdefault("status", "SUCCESS")
        final_status.setdefault("statusCode", 200)

        return final_status

    # ------------------------------------------------------------------
    # JOB PAYLOAD BUILDER
    # ------------------------------------------------------------------

    def _build_job_payload(
        self,
        input_data: dict[str, Any],
        provider_result: dict[str, Any],
        master_password: str,
    ) -> dict[str, Any]:
        """Build the same generic job payload for every provider."""

        provider = provider_result.get("provider")
        if not isinstance(provider, str) or not provider.strip():
            raise ValueError(
                "Provider is missing from previous agent result."
            )

        credentials = provider_result.get("credentials")
        if not isinstance(credentials, dict) or not credentials:
            raise ValueError(
                "Provider credentials are missing or invalid."
            )

        agent_status = self._build_agent_status(provider_result)
        provider_failed = (
            str(agent_status.get("status", "")).upper() == "FAILED"
        )

        # Failed provider scans still create a job. There are no usable files
        # in that case, but credentials and status must be forwarded.
        if provider_failed:
            files: list[dict[str, Any]] = []
        else:
            files = provider_result.get("files")
            if not isinstance(files, list):
                raise ValueError(
                    "Provider files must be provided as a list."
                )

        # The current provider handler result contains the latest cursor
        # generated for this batch, so it must replace the cursor received
        # from the orchestrator. Fall back to the orchestrator cursor only
        # when the provider result does not contain a usable cursor.
        query_job_info = input_data.get("jobInfo") or {}
        if not isinstance(query_job_info, dict):
            raise ValueError("jobInfo must be a dictionary.")

        cursor = provider_result.get("cursorData")
        if cursor is None:
            cursor = query_job_info.get("cursorData")

        if cursor is not None and not isinstance(cursor, dict):
            raise ValueError(
                "cursorData must be a dictionary or None."
            )

        # Encrypt credentials even when the provider scan failed.
        encrypted_credentials, credential_key = self._encrypt_credentials(
            credentials,
            master_password,
        )

        file_metadata = self._build_file_metadata(
            files,
            credentials,
        )
        cursor_data = self._build_cursor_data(cursor)

        return {
            "accountId": input_data.get("accountId"),
            "userId": input_data.get("userId"),
            "locationId": input_data.get("locationId"),
            "clientId": input_data.get("clientId"),
            "jobId": input_data.get("jobId"),
            "jobState": input_data.get("jobState"),
            "provider": provider,
            "controlUrl": input_data.get("controlUrl"),
            "apiToken": input_data.get("apiToken"),
            "contextData": credential_key,
            "jobInfo": {
                "fileMetadata": file_metadata,
                "credentials": encrypted_credentials,
                "cursorData": cursor_data,
            },
            "agentStatus": agent_status,
        }

    # ------------------------------------------------------------------
    # CREATE JOB
    # ------------------------------------------------------------------

    @tool
    async def create_job(
        self,
        query: Any,
        data: Any,
    ) -> dict[str, Any]:
        """
        Prepare a generic job request.

        query:
            Job/orchestrator input dictionary.

        data:
            Previous provider handler result. It may be a direct result or
            wrapped in common task/tool result envelopes.
        """

        try:
            logger.info("Starting generic JobCustomHandler execution.")

            if not self.master_key:
                raise ValueError(
                    "Master key is not configured. "
                    "Provide master_key or set MASTER_KEY environment variable."
                )

            if not isinstance(query, dict):
                raise ValueError(
                    "Query must contain job input as a dictionary."
                )

            if not isinstance(data, dict):
                raise ValueError(
                    "Data must contain previous provider result as a dictionary."
                )

            input_data = query
            provider_result = self._extract_provider_result(data)

            required_fields = [
                "accountId",
                "userId",
                "locationId",
                "clientId",
                "jobId",
                "controlUrl",
                "apiToken",
            ]

            missing_fields = [
                field
                for field in required_fields
                if input_data.get(field) is None
                or input_data.get(field) == ""
            ]

            if missing_fields:
                raise ValueError(
                    "Missing required job input fields: "
                    + ", ".join(missing_fields)
                )

            job_payload = await self.sync_to_async(
                lambda: self._build_job_payload(
                    input_data,
                    provider_result,
                    self.master_key,
                )
            )

            cursor_data = job_payload["jobInfo"]["cursorData"]
            has_more = (
                cursor_data.get("hasMore")
                if isinstance(cursor_data, dict)
                else None
            )

            logger.info(
                "Generic job request prepared. Provider: %s, "
                "Job ID: %s, Files: %s, HasMore: %s, ProviderStatus: %s",
                job_payload["provider"],
                job_payload["jobId"],
                len(job_payload["jobInfo"]["fileMetadata"]),
                has_more,
                job_payload["agentStatus"].get("status"),
            )

            return job_payload

        except Exception as exc:
            # Do not log input query/data: they may contain credentials.
            logger.error(
                "Failed to prepare generic job request: %s",
                str(exc),
                exc_info=True,
            )

            return {
                "success": False,
                "agentStatus": {
                    "status": "FAILED",
                    "statusCode": 500,
                    "reason": str(exc),
                },
            }