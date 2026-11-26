import asyncio
import errno
import logging
import posixpath
import socket
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import paramiko
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class SFTPHandler(BaseHandler):
    """
    SFTPHandler provides asynchronous utility methods for interacting
    with remote SFTP servers using Paramiko.

    Authentication:
        - Private key authentication
        - Password authentication

    Connection credentials are injected through __init__ by the CLI Worker.

    Supported operations:
        - list_files
        - download_file
        - upload_file
        - delete_file
        - create_directory
        - get_file_info
        - scan_sftp_metadata

    Private key:
        The private_key parameter must contain the decrypted private-key
        content, not a local filesystem path.
    """

    CONNECTION_TIMEOUT = 15

    def __init__(
        self,
        host: str,
        username: str,
        private_key: str | None = None,
        password: str | None = None,
        port: int = 22,
        protocol: str = "sftp",
        private_key_passphrase: str | None = None,
        remote_directory: str | None = None,
        local_path: str | None = None,
        **kwargs,
    ):
        """
        Initialize SFTP connection configuration.

        Args:
            host: SFTP server hostname or IP address.
            username: SFTP username.
            private_key: Decrypted SSH private-key content.
            password: SFTP password, if password authentication is used.
            port: SFTP server port. Defaults to 22.
            protocol: Connection protocol. Only sftp is supported.
            private_key_passphrase: Optional private-key passphrase.
            remote_directory: Configured remote directory.
            local_path: Local directory used for downloads.

        Exactly one authentication method must be supplied:
            private_key OR password.
        """

        super().__init__(**kwargs)

        if not isinstance(protocol, str) or protocol.lower() != "sftp":
            raise ValueError("Only SFTP protocol is supported")

        if not isinstance(host, str) or not host.strip():
            raise ValueError("SFTP host is required")

        if not isinstance(username, str) or not username.strip():
            raise ValueError("SFTP username is required")

        try:
            port = int(port)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "SFTP port must be a valid integer"
            ) from exc

        if not 1 <= port <= 65535:
            raise ValueError(
                "SFTP port must be between 1 and 65535"
            )

        if bool(private_key) == bool(password):
            raise ValueError(
                "Provide exactly one authentication method: "
                "private_key or password"
            )

        if private_key_passphrase and not private_key:
            raise ValueError(
                "private_key_passphrase requires private_key authentication"
            )

        self.config = {
            "protocol": protocol.lower(),
            "host": host.strip(),
            "port": port,
            "username": username.strip(),
            "private_key": private_key,
            "private_key_passphrase": private_key_passphrase,
            "password": password,
            "authentication_type": (
                "private_key" if private_key else "password"
            ),
            "remote_directory": remote_directory,
            "local_path": local_path,
        }

    # ---------------------------------------------------------
    # ASYNC EXECUTOR
    # ---------------------------------------------------------

    @staticmethod
    async def sync_to_async(func):
        """
        Execute blocking SFTP operations in a separate thread.

        This follows the same execution pattern as GmailHandler.
        """

        loop = asyncio.get_running_loop()

        return await loop.run_in_executor(None, func)

    # ---------------------------------------------------------
    # CONNECTION CREDENTIALS
    # ---------------------------------------------------------

    def _get_connection_credentials(self) -> dict[str, Any]:
        """
        Return connection credentials for the next agent.

        As agreed, decrypted authentication material is included
        in the credentials object.
        """

        credentials = {
            "protocol": self.config["protocol"],
            "host": self.config["host"],
            "port": self.config["port"],
            "username": self.config["username"],
            "authenticationType": self.config["authentication_type"],
            "remoteDirectory": self.config["remote_directory"],
            "localPath": self.config["local_path"],
        }

        if self.config["private_key"]:
            credentials["privateKey"] = self.config["private_key"]

        if self.config["password"]:
            credentials["password"] = self.config["password"]

        if self.config["private_key_passphrase"]:
            credentials["privateKeyPassphrase"] = (
                self.config["private_key_passphrase"]
            )

        return credentials

    # ---------------------------------------------------------
    # PRIVATE KEY
    # ---------------------------------------------------------

    def _load_private_key(self):
        import base64
        import textwrap
        from io import StringIO

        private_key = self.config.get("private_key")

        if not private_key:
            raise ValueError("SSH private key is required")

        if isinstance(private_key, bytes):
            private_key = private_key.decode("utf-8")

        private_key = private_key.strip()

        # Handle Base64-only OpenSSH private key.
        if "-----BEGIN " not in private_key:
            compact_key = "".join(private_key.split())

            try:
                decoded_key = base64.b64decode(
                    compact_key,
                    validate=True
                )
            except Exception as exc:
                raise ValueError(
                    "Invalid Base64 private key"
                ) from exc

            if not decoded_key.startswith(b"openssh-key-v1\x00"):
                raise ValueError(
                    "Unsupported private key format"
                )

            # Restore PEM envelope internally.
            private_key = (
                    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                    + textwrap.fill(compact_key, 70)
                    + "\n-----END OPENSSH PRIVATE KEY-----\n"
            )

        # Normalize escaped newlines.
        private_key = private_key.replace("\\n", "\n")

        passphrase = self.config.get("private_key_passphrase")

        key_classes = [
            paramiko.Ed25519Key,
            paramiko.RSAKey,
            paramiko.ECDSAKey
        ]

        for key_class in key_classes:
            try:
                key = key_class.from_private_key(
                    StringIO(private_key),
                    password=passphrase
                )

                logger.info(
                    "SSH private key loaded: %s",
                    key_class.__name__
                )

                return key

            except (paramiko.SSHException, ValueError, TypeError):
                continue

        raise ValueError(
            "Unable to load SSH private key. "
            "Check the key format and passphrase."
        )

    # ---------------------------------------------------------
    # CONNECTION
    # ---------------------------------------------------------

    def _connect(
        self,
    ) -> tuple[paramiko.SSHClient, paramiko.SFTPClient]:
        """
        Establish an SSH connection and open an SFTP session.

        Server host keys are verified against system known_hosts.
        Unknown host keys are rejected.
        """

        client = paramiko.SSHClient()

        try:
            client.load_system_host_keys()

            client.set_missing_host_key_policy(
                paramiko.RejectPolicy()
            )

            connection_options = {
                "hostname": self.config["host"],
                "port": self.config["port"],
                "username": self.config["username"],
                "timeout": self.CONNECTION_TIMEOUT,
                "banner_timeout": self.CONNECTION_TIMEOUT,
                "auth_timeout": self.CONNECTION_TIMEOUT,
                "allow_agent": False,
                "look_for_keys": False,
            }

            if self.config["authentication_type"] == "private_key":
                connection_options["pkey"] = self._load_private_key()
            else:
                connection_options["password"] = self.config["password"]

            client.connect(**connection_options)

            sftp = client.open_sftp()

            logger.info(
                "SFTP connection established. Host: %s, port: %s",
                self.config["host"],
                self.config["port"],
            )

            return client, sftp

        except Exception:
            client.close()

            logger.exception(
                "Failed to establish SFTP connection. Host: %s",
                self.config["host"],
            )

            raise

    @staticmethod
    def _close_connection(
        client: paramiko.SSHClient | None,
        sftp: paramiko.SFTPClient | None,
    ) -> None:
        """Close SFTP and SSH connections safely."""

        if sftp is not None:
            try:
                sftp.close()
            except Exception:
                logger.warning("Failed to close SFTP session")

        if client is not None:
            try:
                client.close()
            except Exception:
                logger.warning("Failed to close SSH connection")

    # ---------------------------------------------------------
    # REMOTE DIRECTORY HELPER
    # ---------------------------------------------------------

    @staticmethod
    def _ensure_remote_directory(
        sftp: paramiko.SFTPClient,
        remote_path: str,
    ) -> None:
        """Create a remote directory and missing parent directories."""

        if not remote_path or not remote_path.strip():
            raise ValueError("Remote directory path cannot be empty")

        normalized_path = posixpath.normpath(remote_path)

        if normalized_path in (".", "/"):
            return

        absolute = normalized_path.startswith("/")
        current = "/" if absolute else ""

        for folder in normalized_path.strip("/").split("/"):
            if not folder or folder == ".":
                continue

            if folder == "..":
                raise ValueError(
                    "Parent directory traversal is not allowed"
                )

            current = posixpath.join(current, folder)

            try:
                attributes = sftp.stat(current)

                if not stat.S_ISDIR(attributes.st_mode):
                    raise NotADirectoryError(
                        f"Remote path is not a directory: {current}"
                    )

            except FileNotFoundError:
                sftp.mkdir(current)

    # ---------------------------------------------------------
    # LIST FILES
    # ---------------------------------------------------------

    @tool
    async def list_files(
        self,
        remote_path: str | None = None,
    ):
        """List files and directories in a remote path."""

        remote_path = (
            remote_path
            or self.config["remote_directory"]
            or "."
        )

        def _run():
            client = None
            sftp = None

            try:
                client, sftp = self._connect()

                entries = sftp.listdir_attr(remote_path)

                return {
                    "status": "success",
                    "path": remote_path,
                    "files": [
                        {
                            "name": entry.filename,
                            "size": entry.st_size,
                            "modifiedTime": entry.st_mtime,
                            "isDirectory": stat.S_ISDIR(
                                entry.st_mode
                            ),
                        }
                        for entry in entries
                    ],
                }

            except Exception as exc:
                logger.exception("Error listing SFTP files")

                return {
                    "status": "failed",
                    "error": self._get_failure_details(exc)[1],
                }

            finally:
                self._close_connection(client, sftp)

        return await self.sync_to_async(_run)

    # ---------------------------------------------------------
    # DOWNLOAD FILE
    # ---------------------------------------------------------

    @tool
    async def download_file(
        self,
        remote_path: str,
        local_path: str | None = None,
    ):
        """Download a remote file to the local machine."""

        destination = local_path or self.config["local_path"]

        if not destination:
            raise ValueError(
                "local_path must be provided for downloading"
            )

        def _run():
            client = None
            sftp = None

            try:
                client, sftp = self._connect()

                local_file = Path(destination)
                local_file.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                sftp.get(remote_path, str(local_file))

                return {
                    "status": "success",
                    "remoteFile": remote_path,
                    "localFile": str(local_file),
                }

            except Exception as exc:
                logger.exception("Error downloading SFTP file")

                return {
                    "status": "failed",
                    "error": self._get_failure_details(exc)[1],
                }

            finally:
                self._close_connection(client, sftp)

        return await self.sync_to_async(_run)

    # ---------------------------------------------------------
    # UPLOAD FILES
    # ---------------------------------------------------------

    @tool
    async def upload_file(
        self,
        local_path: str,
        remote_path: str | None = None,
    ):
        """
        Upload regular files inside a local directory.

        This operation is non-recursive.
        Subdirectories are skipped.
        """

        remote_path = (
            remote_path
            or self.config["remote_directory"]
        )

        if not remote_path:
            raise ValueError(
                "remote_path must be provided for uploading"
            )

        def _run():
            local_directory = Path(local_path)

            if not local_directory.is_dir():
                raise ValueError(
                    "Local path is not a directory"
                )

            client = None
            sftp = None

            try:
                client, sftp = self._connect()

                self._ensure_remote_directory(
                    sftp,
                    remote_path,
                )

                uploaded_files = []

                for entry in local_directory.iterdir():
                    if not entry.is_file():
                        continue

                    remote_file = posixpath.join(
                        remote_path,
                        entry.name,
                    )

                    sftp.put(
                        str(entry),
                        remote_file,
                    )

                    uploaded_files.append(remote_file)

                return {
                    "status": "success",
                    "uploadedCount": len(uploaded_files),
                    "uploadedFiles": uploaded_files,
                }

            except Exception as exc:
                logger.exception("Error uploading SFTP files")

                return {
                    "status": "failed",
                    "error": self._get_failure_details(exc)[1],
                }

            finally:
                self._close_connection(client, sftp)

        return await self.sync_to_async(_run)

    # ---------------------------------------------------------
    # DELETE FILE
    # ---------------------------------------------------------

    @tool
    async def delete_file(
        self,
        remote_path: str,
    ):
        """Delete a remote file."""

        def _run():
            client = None
            sftp = None

            try:
                client, sftp = self._connect()

                sftp.remove(remote_path)

                return {
                    "status": "success",
                    "deletedFile": remote_path,
                }

            except Exception as exc:
                logger.exception("Error deleting SFTP file")

                return {
                    "status": "failed",
                    "error": self._get_failure_details(exc)[1],
                }

            finally:
                self._close_connection(client, sftp)

        return await self.sync_to_async(_run)

    # ---------------------------------------------------------
    # CREATE DIRECTORY
    # ---------------------------------------------------------

    @tool
    async def create_directory(
        self,
        remote_path: str,
    ):
        """Create a remote directory, including missing parents."""

        def _run():
            client = None
            sftp = None

            try:
                client, sftp = self._connect()

                self._ensure_remote_directory(
                    sftp,
                    remote_path,
                )

                return {
                    "status": "success",
                    "directoryCreated": remote_path,
                }

            except Exception as exc:
                logger.exception("Error creating SFTP directory")

                return {
                    "status": "failed",
                    "error": self._get_failure_details(exc)[1],
                }

            finally:
                self._close_connection(client, sftp)

        return await self.sync_to_async(_run)

    # ---------------------------------------------------------
    # GET FILE INFO
    # ---------------------------------------------------------

    @tool
    async def get_file_info(
        self,
        remote_path: str,
    ):
        """Get metadata of a remote file or directory."""

        def _run():
            client = None
            sftp = None

            try:
                client, sftp = self._connect()

                attributes = sftp.stat(remote_path)

                return {
                    "status": "success",
                    "file": remote_path,
                    "size": attributes.st_size,
                    "modifiedTime": attributes.st_mtime,
                    "isDirectory": stat.S_ISDIR(
                        attributes.st_mode
                    ),
                }

            except Exception as exc:
                logger.exception("Error getting SFTP file information")

                return {
                    "status": "failed",
                    "error": self._get_failure_details(exc)[1],
                }

            finally:
                self._close_connection(client, sftp)

        return await self.sync_to_async(_run)

    # ---------------------------------------------------------
    # METADATA DISCOVERY
    # ---------------------------------------------------------

    @staticmethod
    def _get_file_metadata(
        remote_path: str,
        file_attr: Any,
    ) -> dict[str, Any]:
        """Extract metadata from an SFTP file."""

        return {
            "filename": posixpath.basename(remote_path),
            "remotePath": remote_path,
            "size": file_attr.st_size,
            "modifiedTime": file_attr.st_mtime,
        }

    def _scan_directory(
        self,
        sftp: paramiko.SFTPClient,
        root_path: str,
    ) -> list[dict[str, Any]]:
        """
        Recursively scan regular files under the given directory.

        Symbolic links are not followed.
        """

        files = []
        directories = [root_path]

        while directories:
            current_path = directories.pop()

            entries = sftp.listdir_attr(current_path)

            for entry in entries:
                remote_path = posixpath.join(
                    current_path,
                    entry.filename,
                )

                if stat.S_ISDIR(entry.st_mode):
                    directories.append(remote_path)

                elif stat.S_ISREG(entry.st_mode):
                    files.append(
                        self._get_file_metadata(
                            remote_path,
                            entry,
                        )
                    )

        return files

    # ---------------------------------------------------------
    # TIMESTAMP HELPERS
    # ---------------------------------------------------------

    @staticmethod
    def _timestamp_to_iso(timestamp: float) -> str:
        """Convert Unix timestamp to ISO-8601 UTC timestamp."""

        return (
            datetime.fromtimestamp(
                timestamp,
                tz=timezone.utc,
            )
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )

    @staticmethod
    def _iso_to_timestamp(value: str) -> float:
        """Convert ISO-8601 timestamp to Unix timestamp."""

        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                "cursor.lastCheckedAt must be a valid ISO timestamp"
            )

        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

        except ValueError as exc:
            raise ValueError(
                "cursor.lastCheckedAt must be a valid ISO-8601 timestamp"
            ) from exc

        if parsed.tzinfo is None:
            raise ValueError(
                "cursor.lastCheckedAt must include a timezone"
            )

        return parsed.timestamp()

    # ---------------------------------------------------------
    # CURSOR VALIDATION
    # ---------------------------------------------------------

    @classmethod
    def _validate_cursor(
        cls,
        cursor: dict[str, Any] | None,
    ) -> tuple[float, str] | None:
        """
        Validate the Controller Tower cursor.

        Expected format:

        {
            "lastCheckedAt": "2026-11-19T10:26:41Z",
            "lastFilePath": "/upload/example.pdf",
            "hasMore": true
        }
        """

        if cursor is None:
            return None

        if not isinstance(cursor, dict):
            raise ValueError("cursor must be a dictionary")

        if "lastCheckedAt" not in cursor:
            raise ValueError(
                "cursor.lastCheckedAt is required"
            )

        if "lastFilePath" not in cursor:
            raise ValueError(
                "cursor.lastFilePath is required"
            )

        timestamp = cls._iso_to_timestamp(
            cursor["lastCheckedAt"]
        )

        last_file_path = cursor["lastFilePath"]

        if last_file_path is None:
            last_file_path = ""

        if not isinstance(last_file_path, str):
            raise ValueError(
                "cursor.lastFilePath must be a string or null"
            )

        return timestamp, last_file_path

    # ---------------------------------------------------------
    # FAILURE DETAILS
    # ---------------------------------------------------------

    @staticmethod
    def _get_failure_details(
        exc: Exception,
    ) -> tuple[int, str]:
        """Map SFTP errors to structured status codes."""

        if isinstance(exc, paramiko.AuthenticationException):
            return 401, "SFTP authentication failed."

        if isinstance(exc, paramiko.BadHostKeyException):
            return 502, "SFTP server host-key verification failed."

        if isinstance(exc, PermissionError):
            return 403, "Permission denied for the requested SFTP operation."

        if isinstance(exc, FileNotFoundError):
            return 404, "The requested remote path was not found."

        if isinstance(exc, OSError):
            if exc.errno in (errno.EACCES, errno.EPERM):
                return 403, "Permission denied for the requested SFTP operation."

            if exc.errno == errno.ENOENT:
                return 404, "The requested remote path was not found."

            if exc.errno in (
                errno.ETIMEDOUT,
                errno.ECONNREFUSED,
                errno.EHOSTUNREACH,
                errno.ENETUNREACH,
            ):
                return 504, "SFTP connection or network operation failed."

        if isinstance(exc, (socket.timeout, TimeoutError)):
            return 504, "SFTP connection timed out."

        if isinstance(exc, paramiko.SSHException):
            return 502, "SFTP SSH protocol or connection error."

        if isinstance(exc, (ValueError, TypeError)):
            return 400, str(exc)

        return 500, "Unexpected error while processing the SFTP operation."

    # ---------------------------------------------------------
    # RESPONSE BUILDER
    # ---------------------------------------------------------

    def _build_response(
        self,
        *,
        files: list[dict[str, Any]],
        cursor_data: dict[str, Any] | None,
        status: str,
        status_code: int,
        reason: str,
        total_files_scanned: int | None = None,
        remaining_files: int | None = None,
        batch_count: int | None = None,
    ) -> dict[str, Any]:
        """Build the standard SFTP metadata scan response."""

        return {
            "provider":"SFTP",
            "credentials": self._get_connection_credentials(),
            "total_files_scanned": total_files_scanned,
            "remaining_files": remaining_files,
            "batch_count": batch_count,
            "files": files,
            "cursorData": cursor_data,
            "agentStatus": {
                "status": status,
                "statusCode": status_code,
                "reason": reason,
            },
        }
    # ---------------------------------------------------------
    # SCAN SFTP METADATA
    # ---------------------------------------------------------

    @tool
    async def scan_sftp_metadata(
        self,
        batch_size: int = 100,
        cursor: dict[str, Any] | None = None,
    ):
        """
        Recursively scan SFTP files and return one batch.

        Controller Tower responsibilities:
            - Send null cursor on the first invocation.
            - Store returned cursorData.
            - Send stored cursorData on subsequent invocations.

        SFTPHandler responsibilities:
            - Scan remote files.
            - Apply cursor pagination.
            - Return file metadata.
            - Return updated cursor.
            - Return structured agent status.

        No runId or per-file localPath is generated here.
        """

        # Use the remote directory configured during handler initialization.
        root_path = self.config["remote_directory"]

        if not isinstance(root_path, str) or not root_path.strip():
            raise ValueError(
                "remote_directory must be configured in SFTPHandler"
            )

        if not isinstance(batch_size, int) or isinstance(batch_size, bool):
            raise ValueError("batch_size must be an integer")

        if batch_size <= 0:
            raise ValueError(
                "batch_size must be greater than zero"
            )

        cursor_key = self._validate_cursor(cursor)

        host = self.config["host"]

        def _run():
            client = None
            sftp = None

            try:
                # 1. Establish SFTP connection.
                client, sftp = self._connect()

                # 2. Recursively discover files.
                all_files = self._scan_directory(
                    sftp,
                    root_path,
                )

                # 3. Sort by modification time and path.
                all_files.sort(
                    key=lambda item: (
                        item["modifiedTime"],
                        item["remotePath"],
                    )
                )

                # 4. Apply cursor filtering.
                if cursor_key is not None:
                    remaining_files = [
                        file
                        for file in all_files
                        if (
                            file["modifiedTime"],
                            file["remotePath"],
                        ) > cursor_key
                    ]

                else:
                    remaining_files = all_files

                # 5. Fetch one extra file to identify another batch.
                selected_files = remaining_files[
                    :batch_size + 1
                ]

                has_more = len(selected_files) > batch_size

                batch_files = selected_files[:batch_size]

                # 6. Preserve the latest cursor position.
                if batch_files:
                    last_file = batch_files[-1]

                    last_checked_at = self._timestamp_to_iso(
                        last_file["modifiedTime"]
                    )

                    last_file_path = last_file["remotePath"]

                elif cursor is not None:
                    # No new files: retain Controller Tower cursor.
                    last_checked_at = cursor["lastCheckedAt"]
                    last_file_path = cursor["lastFilePath"]

                else:
                    # Initial scan with no files.
                    last_checked_at = self._timestamp_to_iso(
                        datetime.now(timezone.utc).timestamp()
                    )

                    last_file_path = None

                cursor_data = {
                    "lastCheckedAt": last_checked_at,
                    "lastFilePath": last_file_path,
                    "hasMore": has_more,
                }

                logger.info(
                    "SFTP scan completed. "
                    "Total files: %s, batch files: %s, hasMore: %s",
                    len(all_files),
                    len(batch_files),
                    has_more,
                )

                return self._build_response(
                    files=batch_files,
                    cursor_data=cursor_data,
                    status="SUCCESS",
                    status_code=200,
                    reason="SFTP metadata scanned successfully.",
                    total_files_scanned=len(all_files),
                    remaining_files=len(all_files) - len(batch_files),
                    batch_count=len(batch_files),
                )

            except Exception as exc:
                status_code, reason = self._get_failure_details(exc)

                logger.exception(
                    "SFTP metadata scan failed. "
                    "Host: %s, directory: %s, status: %s",
                    host,
                    root_path,
                    status_code,
                )

                return self._build_response(
                    files=[],
                    cursor_data=cursor,
                    status="FAILED",
                    status_code=status_code,
                    reason=reason,
                    total_files_scanned=None,
                    remaining_files=None,
                    batch_count=0,
                )

            finally:
                self._close_connection(client, sftp)

        return await self.sync_to_async(_run)