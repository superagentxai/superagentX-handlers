import subprocess
import os
import shutil
import sys
import logging

from superagentx.handler.decorators import tool
from superagentx.handler.base import BaseHandler
from superagentx.utils.helper import sync_to_async
from typing import Optional

logger = logging.getLogger(__name__)


class BuildError(Exception):
    pass


class BuildProcessHandler(BaseHandler):

    @tool
    async def compile_react_app(
        self,
        frontend_path: str,
        command: list[str],
        env: Optional[dict] = None
    ):
        """
           Execute a React (or frontend) build_source command inside a local project directory.

           This method runs any frontend-related command (build_source, start, or custom)
           such as `npm run build_source`, `npx vite build_source`, `yarn build_source`, or `pnpm build_source`
           inside the specified frontend path.

        Args:
            frontend_path (str): Local filesystem path to the frontend project
                                 containing `package.json`.
            command (list[str]): Build or run command as a list of strings.
                                 Example:
                                     ["npm", "run", "build_source"]
                                     ["npx", "vite", "build_source"]
                                     ["yarn", "build_source"]
                                     ["pnpm", "build_source"]
            env (dict | None): Optional environment variables to inject
                               during command execution.

        """
        #  Validate frontend path
        if not os.path.isdir(frontend_path):
            raise BuildError(f"Frontend path not found: {frontend_path}")

        #  Validate command
        if not command or not all(isinstance(c, str) for c in command):
            raise BuildError("Command must be a list of strings")

        #  Block obvious dangerous patterns
        DANGEROUS_TOKENS = {"&&", ";", "|", "`", "$(", "sudo", "rm -rf"}
        joined_cmd = " ".join(command)
        if any(token in joined_cmd for token in DANGEROUS_TOKENS):
            raise BuildError("Unsafe shell tokens detected in command")

        #  Resolve executable cross-platform
        exe = await sync_to_async(shutil.which, command[0])
        if not exe:
            raise BuildError(
                f"Executable '{command[0]}' not found in PATH "
                "(install node / npm / yarn / pnpm)"
            )

        cmd = [exe, *command[1:]]

        #  Build environment
        build_env = os.environ.copy()
        if env:
            build_env.update(env)

        #  Install dependencies if package.json exists
        package_json = os.path.join(frontend_path, "package.json")
        node_modules = os.path.join(frontend_path, "node_modules")

        if os.path.exists(package_json) and not os.path.exists(node_modules):
            npm_exe = shutil.which("npm")
            if not npm_exe:
                raise BuildError("npm not found for dependency installation")

            install = await sync_to_async(
                subprocess.run,
                [npm_exe, "install", "--legacy-peer-deps"],
                cwd=frontend_path,
                env=build_env,
                capture_output=True,
                text=True
            )

            if install.returncode != 0:
                raise BuildError(
                    f"npm install failed\n\nSTDERR:\n{install.stderr}"
                )

        #  Run build_source / start / custom command
        result = await sync_to_async(subprocess.run,
            cmd,
            cwd=frontend_path,
            env=build_env,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            raise BuildError(
                f"Command failed\n\nSTDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
            )

        if sys.platform == "win32":
            out = "build_source"
        elif sys.platform == "linux" or sys.platform == "darwin":
            out = "dist"
        else:
            out = "build_source"
        output_path = os.path.join(frontend_path, out)
        if os.path.isdir(output_path):
            logger.info(f"Build Successfully Completed: {output_path}")
            return {
                "status": "success",
                "command": cmd,
                "output_dir": output_path,
                "stdout": result.stdout
            }

        #  Some commands (npm start) don't create output dirs
        return {
            "status": "success",
            "command": cmd,
            "stdout": result.stdout,
            "note": "No build_source output directory detected"
        }

    ## Docker Local Build
    @tool
    async def docker_build(
            self,
            project_path: str,
            image_name: str,
            dockerfile: str = "Dockerfile",
            tag: str = "latest"
    ):
        """
        Builds a Docker image from a given project directory.

        This handler performs a container image build using a specified Dockerfile
        and tags the resulting image for later use (run, push, or deployment).
        It is designed to work with any application type (FastAPI, Python, Java,
        Node.js, etc.) as long as a valid Dockerfile is present.

        Args:
            project_path (str): Absolute or relative path to the project directory
                that contains the Dockerfile and application source.
            image_name (str): Name of the Docker image to be built.
            dockerfile (str, optional): Name or path of the Dockerfile to use.
                Defaults to "Dockerfile".
            tag (str, optional): Tag to apply to the built image.
                Defaults to "latest".
        """

        if not os.path.isdir(project_path):
            raise BuildError(f"Project path not found: {project_path}")

        docker_exe = shutil.which("docker")
        if not docker_exe:
            raise BuildError("Docker not installed or not in PATH")

        dockerfile_path = os.path.join(project_path, dockerfile)
        if not os.path.isfile(dockerfile_path):
            raise BuildError(f"Dockerfile not found: {dockerfile_path}")

        cmd = [
            docker_exe,
            "build",
            "-f", dockerfile_path,
            "-t", f"{image_name}:{tag}",
            "."
        ]

        result = await sync_to_async(
            subprocess.run,
            cmd,
            cwd=project_path,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            raise BuildError(
                f"Docker build failed\n\nSTDERR:\n{result.stderr}"
            )

        return {
            "status": "success",
            "image": f"{image_name}:{tag}",
            "stdout": result.stdout
        }

