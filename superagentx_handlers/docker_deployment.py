import asyncio
import logging
import os
import shutil
import subprocess
from typing import Optional

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async


logger = logging.getLogger(__name__)

class DeployError(Exception):
    pass


class DockerRunHandler(BaseHandler):

    @tool
    async def docker_deploy(
            self,
            image: str,
            project_path: str,
            ports: Optional[dict] = None
    ):
        """
        Deploys a Docker-based application from a local project directory or image.

        This handler deploys an application using Docker by automatically selecting
        the appropriate strategy:
        - If a docker-compose file exists in the project path, the application is
          deployed using docker-compose.
        - Otherwise, the application is started using a direct docker run command
          with the provided image.

        Args:
            image (str): Docker image name (with optional tag) to deploy when
                docker-compose is not available.
            project_path (str): Path to the project directory that may contain
                docker-compose configuration files.
            ports (Optional[dict], optional): Port mappings to expose when deploying
                via docker run. The dictionary should map container ports to host
                ports (e.g., {"80": "8080"}). Defaults to None.

        """

        docker_exe = await sync_to_async(shutil.which, "docker")
        if not docker_exe:
            raise DeployError("Docker not installed")

        # ---------- CASE 1: Docker Compose ----------
        if project_path:
            compose_file = os.path.join(project_path, "docker-compose.yml")

            if os.path.isfile(compose_file):
                cmd = [docker_exe, "compose", "up", "-d", "--build"]

                try:
                    await sync_to_async(
                        subprocess.run,
                        cmd,
                        cwd=project_path,
                        check=True
                    )
                except subprocess.CalledProcessError as e:
                    raise DeployError(f"Docker Compose failed: {e}") from e

                logger.info("Docker Compose deployment started")

                return {
                    "mode": "compose",
                    "status": "running",
                    "project_path": project_path
                }

            # ---------- CASE 2: Docker Run ----------
            if image:
                # validate image exists
                img_check = await sync_to_async(
                    subprocess.run,
                    [docker_exe, "images", "-q", image],
                    capture_output=True,
                    text=True
                )

                if not img_check.stdout.strip():
                    raise DeployError(
                        f"Docker image '{image}' not found. Build it before deploying."
                    )

                cmd = [docker_exe, "run", "-d"]

                if ports:
                    for host, container in ports.items():
                        cmd.extend(["-p", f"{host}:{container}"])

                cmd.append(image)

                try:
                    await sync_to_async(
                        subprocess.run,
                        cmd,
                        check=True
                    )
                except subprocess.CalledProcessError as e:
                    raise DeployError(f"Docker run failed: {e}") from e

                logger.info(f"Docker container started: {image}")

                return {
                    "mode": "run",
                    "status": "running",
                    "image": image
                }

            # ---------- INVALID INPUT ----------
            raise DeployError(
                "Provide either 'image' or 'project_path' containing docker-compose.yml"
            )
