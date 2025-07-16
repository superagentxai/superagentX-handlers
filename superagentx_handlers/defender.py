import asyncio
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

POWERSHELL = "powershell.exe"


async def _run_ps(
        command: str
):
    """Run a PowerShell command and return its output or raise error."""
    proc = await asyncio.create_subprocess_exec(
        POWERSHELL,
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command", command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"PowerShell error: {stderr.decode().strip()}")
    return stdout.decode().strip() or "<no matching rules>"


class DefenderHandler(BaseHandler):
    """
    Simplified Windows firewall rule handler using PowerShell.
    """

    @tool
    async def list_firewall_rules(
            self,
            *,
            ports: str = "",
            program: str = ""
    ):
        """
        List firewall rules. Filter by ports (e.g., '80,443') or program path.
        Args:
            ports (str): The port number,
            program (str): The name of the program
        Returns:
            Dict: List the Defender Firewall Rules.

        """
        filters = []
        if ports:
            pattern = "|".join(p.strip() for p in ports.split(","))
            filters.append(f"$_.LocalPort -match '({pattern})'")
        if program:
            filters.append(f"$_.Program -like '{program}'")

        where_clause = f" | Where-Object {{ {' -and '.join(filters)} }}" if filters else ""
        ps = (
            "Get-NetFirewallRule | Get-NetFirewallPortFilter"
            f"{where_clause} | Select DisplayName, Direction, Action, "
            "@{Name='Port';Expression={$_.LocalPort}}, "
            "@{Name='Program';Expression={$_.Program}} | Format-Table -AutoSize"
        )
        return await _run_ps(ps)

    @tool
    async def restrict_port_rules(
            self,
            *,
            ports: str = ""
    ):
        """
        Show rules that block traffic. Filter by ports (e.g., '22','3389').
        Args:
            ports (str): The port number
        Returns:
            Dict: The Restrict Block rules of Defender Firewall
        """
        where = ""
        if ports:
            pattern = "|".join(p.strip() for p in ports.split(","))
            where = f" | Where-Object {{ $_.LocalPort -match '({pattern})' }}"

        ps = (
            "Get-NetFirewallRule -Action Block | Get-NetFirewallPortFilter"
            f"{where} | Select DisplayName, Direction, "
            "@{Name='Port';Expression={$_.LocalPort}}, "
            "@{Name='Program';Expression={$_.Program}} | Format-Table -AutoSize"
        )
        return await _run_ps(ps)

    @tool
    async def app_access_rules(
            self,
            *,
            program: str = "",
            action: str = ""
    ):
        """
        List allow/block rules for applications. Filter by program and action.
        Args:
            program (str): The name of the program,
            action (str): The action of the application.
        Returns:
            Dict: The access/block rules for application in Defender Firewall.
        """
        if action and action.capitalize() not in {"Allow", "Block"}:
            raise ValueError("Action must be 'Allow', 'Block', or left empty.")

        action_filter = f" -Action {action.capitalize()}" if action else ""
        program_filter = f" | Where-Object {{ $_.Program -like '{program}' }}" if program else ""

        ps = (
            f"Get-NetFirewallRule{action_filter} | "
            "Where-Object { $_.Program -and $_.Program -ne '' }"
            f"{program_filter} | Select DisplayName, Direction, Action, "
            "@{Name='Program';Expression={$_.Program}} | Format-Table -AutoSize"
        )
        return await _run_ps(ps)