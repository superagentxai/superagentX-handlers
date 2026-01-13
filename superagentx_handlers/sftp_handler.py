import os
import stat
import logging
import paramiko
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


class SFTPHandler(BaseHandler):
    """
    Handles SFTP file operations using Paramiko without requiring host/port.

    Config Options:
        username (str): Username for authentication.
        password (str): Password for authentication.
    """

    def __init__(
            self,
            *,
            username: str | None = None,
            password: str | None = None,
    ):
        super().__init__()
        self.config = {
            "username": username or os.getenv("SFTP_USERNAME"),
            "password": password or os.getenv("SFTP_PASSWORD"),
        }

        missing = [k for k, v in self.config.items() if not v]
        if missing:
            raise RuntimeError(f"Missing SFTP config values: {missing}")

    # -------------------- CONNECTION --------------------

    def _connect(self, host: str, port: int = 22):
        """
        Connect to an SFTP server.
        Args:
            host (str): SFTP server host (passed per method call)
            port (int): SFTP port (default 22)
        """
        transport = paramiko.Transport((host, port))
        transport.connect(
            username=self.config["username"],
            password=self.config["password"]
        )
        sftp = paramiko.SFTPClient.from_transport(transport)
        return transport, sftp

    # -------------------- FILE OPERATIONS --------------------

    @tool
    async def list_files(self, host: str, remote_path: str = ".", port: str = "22"):
        """List files and directories in a remote path."""

        def _run():
            transport, sftp = self._connect(host, port)
            try:
                files = sftp.listdir_attr(remote_path)
                return {
                    "status": "success",
                    "path": remote_path,
                    "files": [
                        {
                            "name": f.filename,
                            "size": f.st_size,
                            "modified_time": f.st_mtime,
                            "is_directory": stat.S_ISDIR(f.st_mode),
                        }
                        for f in files
                    ],
                }
            finally:
                sftp.close()
                transport.close()

        return await sync_to_async(_run)

    @tool
    async def download_file(self, host: str, remote_path: str, local_path: str, port: int = 22):
        """Download a file from remote SFTP to local."""

        def _run():
            transport, sftp = self._connect(host, port)
            try:
                sftp.get(remote_path, local_path)
                return {
                    "status": "success",
                    "remote_file": remote_path,
                    "local_file": local_path,
                }
            finally:
                sftp.close()
                transport.close()

        return await sync_to_async(_run)

    @tool
    async def upload_file(
            self,
            host: str,
            local_path: str,
            remote_path: str,
            port: int = 22
    ):
        """
        Upload all files inside a local directory to a remote directory.
        (Non-recursive: only files in the given directory)
        """

        def _run():
            if not os.path.isdir(local_path):
                raise ValueError(f"Local path is not a directory: {local_path}")

            transport, sftp = self._connect(host, port)

            try:
                # Ensure remote directory exists
                try:
                    sftp.chdir(remote_path)
                except IOError:
                    current = ""
                    for folder in remote_path.strip("/").split("/"):
                        current = f"{current}/{folder}" if current else folder
                        try:
                            sftp.mkdir(current)
                        except IOError:
                            pass

                uploaded_files = []

                for entry in os.listdir(local_path):
                    local_file = os.path.join(local_path, entry)

                    if not os.path.isfile(local_file):
                        continue  # skip subdirectories

                    remote_file = f"{remote_path}/{entry}".replace("\\", "/")
                    sftp.put(local_file, remote_file)
                    uploaded_files.append(remote_file)

                return {
                    "status": "success",
                    "uploaded_count": len(uploaded_files),
                    "uploaded_files": uploaded_files
                }

            finally:
                sftp.close()
                transport.close()

        return await sync_to_async(_run)

    @tool
    async def delete_file(self, host: str, remote_path: str, port: int = 22):
        """Delete a remote file."""

        def _run():
            transport, sftp = self._connect(host, port)
            try:
                sftp.remove(remote_path)
                return {
                    "status": "success",
                    "deleted_file": remote_path,
                }
            finally:
                sftp.close()
                transport.close()

        return await sync_to_async(_run)

    @tool
    async def create_directory(self, host: str, remote_path: str, port: int = 22):
        """Create a directory on the remote server."""

        def _run():
            transport, sftp = self._connect(host, port)
            try:
                sftp.mkdir(remote_path)
                return {
                    "status": "success",
                    "directory_created": remote_path,
                }
            finally:
                sftp.close()
                transport.close()

        return await sync_to_async(_run)

    @tool
    async def get_file_info(self, host: str, remote_path: str, port: int = 22):
        """Get metadata of a remote file or directory."""

        def _run():
            transport, sftp = self._connect(host, port)
            try:
                stat_result = sftp.stat(remote_path)
                return {
                    "status": "success",
                    "file": remote_path,
                    "size": stat_result.st_size,
                    "modified_time": stat_result.st_mtime,
                    "is_directory": stat.S_ISDIR(stat_result.st_mode),
                }
            finally:
                sftp.close()
                transport.close()

        return await sync_to_async(_run)