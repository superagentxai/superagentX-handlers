import subprocess
import os
import shutil
import sys
import logging

from superagentx.handler.decorators import tool
from superagentx.handler.base import BaseHandler

logger = logging.getLogger(__name__)


class BuildError(Exception):
    pass


class BuildProcessHandler(BaseHandler):

    @tool
    async def compile_react_app(
        self,
        frontend_path: str,
        command: list[str],
        env: dict | None = None
    ):
        """
           Execute a React (or frontend) build command inside a local project directory.

           This method runs any frontend-related command (build, start, or custom)
           such as `npm run build`, `npx vite build`, `yarn build`, or `pnpm build`
           inside the specified frontend path.

        Args:
            frontend_path (str): Local filesystem path to the frontend project
                                 containing `package.json`.
            command (list[str]): Build or run command as a list of strings.
                                 Example:
                                     ["npm", "run", "build"]
                                     ["npx", "vite", "build"]
                                     ["yarn", "build"]
                                     ["pnpm", "build"]
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
        exe = shutil.which(command[0])
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

            install = subprocess.run(
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

        #  Run build / start / custom command
        result = subprocess.run(
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
            out = "build"
        elif sys.platform == "linux" or sys.platform == "darwin":
            out = "dist"
        else:
            out = "build"
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
            "note": "No build output directory detected"
        }
