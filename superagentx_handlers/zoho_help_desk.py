import requests
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


class ZohoHelpDeskHandler(BaseHandler):
    """
    ZohoHelpDeskHandler — Zoho Desk ticket management operations handler

    This handler manages authenticated interactions with the Zoho Desk
    (Help Desk) REST API. It authenticates using an OAuth access token
    and organization ID, and exposes tool-decorated methods that allow
    LLMs or agent-based systems to retrieve and mutate support tickets.

    Core capabilities include:
    - Ticket retrieval
    - Ticket updates and field mutation
    - Status and process-stage transitions
    - Blueprint workflow execution

    Available tool methods:

    Tickets
        - get_ticket: retrieve a ticket by ID
        - update_ticket: update arbitrary ticket fields
        - change_status: change the ticket status
        - change_process_stage: move a ticket to a custom process stage

    Blueprints
        - trigger_blueprint_transition: execute a blueprint transition
          for a ticket using a transition ID
    """

    def __init__(
            self,
            org_id: str,
            auth_token: str,
            base_url="https://desk.zoho.com/api/v1"
    ):

        super().__init__()
        self.base_url = base_url
        self.org_id = org_id
        self.token = auth_token

    def _headers(self):
        return {
            "orgId": self.org_id,
            "Authorization": f"Zoho-oauthtoken {self.token}",
            "Content-Type": "application/json"
        }

    # -----------------------
    # 1. Get a ticket
    # -----------------------
    @tool
    def get_ticket(self, ticket_id: str):
        url = f"{self.base_url}/tickets/{ticket_id}"
        r = requests.get(url, headers=self._headers())
        r.raise_for_status()
        return r.json()

    # -----------------------
    # 2. Update a ticket (change process fields)
    # -----------------------
    @tool
    def update_ticket(self, ticket_id: str, fields: dict):
        url = f"{self.base_url}/tickets/{ticket_id}"
        r = requests.put(url, headers=self._headers(), json=fields)
        r.raise_for_status()
        return r.json()

    # -----------------------
    # 3. Change ticket status (Open → In Progress → Closed)
    # -----------------------
    @tool
    def change_status(self, ticket_id: str, status: str):
        return self.update_ticket(ticket_id, {"status": status})

    # -----------------------
    # 4. Move ticket to another process stage (custom field)
    # -----------------------
    @tool
    def change_process_stage(self, ticket_id: str, stage_name: str):
        fields = {"cf_process_stage": stage_name}
        return self.update_ticket(ticket_id, fields)

    # -----------------------
    # 5. Trigger a Blueprint transition
    # -----------------------
    @tool
    def trigger_blueprint_transition(self, ticket_id: str, transition_id: str):
        url = f"{self.base_url}/tickets/{ticket_id}/blueprint/transition"
        r = requests.post(url, headers=self._headers(), json={"transition_id": transition_id})
        r.raise_for_status()
        return r.json()
