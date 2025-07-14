import os

from pysnc import ServiceNowClient
from superagentx.handler.base import BaseHandler
from superagentx.utils.helper import sync_to_async
from superagentx.handler.decorators import tool


class ServiceNowHandler(BaseHandler):
    def __init__(
            self,
            instance_url: str = None,
            username: str = None,
            password: str = None
    ):
        """
       Initializes the ServiceNowHandler with instance details and authentication.

       Args:
           instance_url (str, optional): The ServiceNow instance URL. If not provided, fetched from environment variable SERVICENOW_INSTANCE_URL.
           username (str, optional): Username for authentication. If not provided, fetched from environment variable SERVICENOW_USERNAME.
           password (str, optional): Password for authentication. If not provided, fetched from environment variable SERVICENOW_PASSWORD.
       """
        super().__init__()
        self.instance = (
                instance_url or os.getenv("SERVICENOW_INSTANCE_URL")
        ).replace("https://", "").replace(".service-now.com", "")
        self.username = username or os.getenv("SERVICENOW_USERNAME")
        self.password = password or os.getenv("SERVICENOW_PASSWORD")

        self.client = ServiceNowClient(self.instance, auth=(self.username, self.password))
        self.asset_table = self.client.GlideRecord('alm_asset')
        self.incident_table = self.client.GlideRecord('incident')
        self.user_table = self.client.GlideRecord('sys_user')

    @tool
    async def get_user_name(self, user_sys_id):
        if not user_sys_id:
            return "Unassigned"
        if await sync_to_async(self.user_table.get, user_sys_id):
            return self.user_table.get_value("name")
        return  "Unknown"

    @tool
    async def get_assets_with_details_and_tickets(self):
        """
        Retrieve a list of all assets along with their associated details and incident tickets.

        Returns:
            list: A list of dictionaries where each dictionary represents an asset with its details and related tickets.
        """
        report = []

        await sync_to_async(
            self.asset_table.query,
        )

        for asset in self.asset_table:
            asset_data = {
                "Asset Name": asset.get_value("name"),
                "Asset Tag": asset.get_value("asset_tag"),
                "Model": asset.get_value("model"),
                "Assigned To": self.get_user_name(asset.get_value("assigned_to")),
                "Owned By": self.get_user_name(asset.get_value("owned_by")),
                "Install Status": asset.get_value("install_status"),
                "Warranty Expiration": asset.get_value("warranty_expiration"),
                "Location": asset.get_value("location"),
                "Company": asset.get_value("company"),
                "Tickets": []
            }

            if asset.get("ci"):
                await sync_to_async(
                    self.incident_table.query,
                    query=f"cmdb_ci={asset['ci']}"
                )
                for ticket in self.incident_table:
                    asset_data["Tickets"].append({
                        "Ticket Number": ticket.get_value("number"),
                        "Short Description": ticket.get_value("short_description"),
                        "State": ticket.get_value("state"),
                        "Priority": ticket.get_value("priority"),
                        "Opened At": ticket.get_value("opened_at")
                    })
            report.append(asset_data)
        return report
