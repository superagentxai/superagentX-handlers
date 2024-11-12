import logging
import os

from hubspot import HubSpot
from hubspot.crm.contacts import (SimplePublicObjectInputForCreate as ContactObjectBuilder,
                                  ApiException as ContactCreateException)
from hubspot.crm.companies import (SimplePublicObjectInputForCreate as CompanyObjectBuilder,
                                   ApiException as ApiException)
from hubspot.crm.deals import ApiException as DealCreationException
from hubspot.crm.tickets import (SimplePublicObjectInputForCreate as TicketObjectBuilder,
                                 ApiException as TicketException)

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


class AuthException(Exception):
    pass


class HubSpotHandler(BaseHandler):
    """
        A handler class for managing interactions with the Hubspot API.
        This class extends BaseHandler and provides methods for performing various operations,
        such as creating, updating, retrieving, and managing within a Hubspot environment.
    """
    def __init__(
            self,
            *,
            token: str | None = None
    ):
        super().__init__()
        self.token = token or os.getenv("HUBSPOT_TOKEN")
        self._connection: HubSpot = self._connect()

    def _connect(self) -> HubSpot:
        """
            Establish a connection to the HubSpot API.

            This method initializes and returns an instance of the HubSpot client,
            allowing for subsequent interactions with the HubSpot API. It handles
            any necessary authentication and setup required for the connection.

            Returns:
                HubSpot: An instance of the HubSpot client connected to the API.
            """
        try:
            api_client = HubSpot(
                access_token=self.token
            )
            logger.debug("Authenticate Success")
            return api_client
        except Exception as ex:
            message = f'HubSpot Handler Authentication Problem {ex}'
            logger.error(message, exc_info=ex)
            raise AuthException(message)

    @tool
    async def create_contact(
            self,
            email: str,
            first_name: str = '',
            last_name: str = ''
    ):
        """
            create a new contact in HubSpot.

            This method sends a request to the HubSpot API to create a new contact
            using the provided email address, first name, and last name.

            Args:
                email (str): The email address of the contact. This field is required.
                first_name (str, optional): The first name of the contact. Defaults to an empty string.
                last_name (str, optional): The last name of the contact. Defaults to an empty string.

            Returns:
                dict: A dictionary containing the details of the created contact info.

            """
        try:
            simple_public_object_input_for_create = ContactObjectBuilder(
                properties={
                    "email": email,
                    "firstname": first_name,
                    "lastname": last_name
                }
            )
            return await sync_to_async(
                self._connection.crm.contacts.basic_api.create,
                simple_public_object_input_for_create=simple_public_object_input_for_create
            )
        except ContactCreateException as ex:
            message = f"Exception when creating contact {ex}"
            logger.error(message, exc_info=ex)
            raise

    @tool
    async def get_all_contact(
            self
    ):
        """
            retrieve all contacts from HubSpot.

            This method sends a request to the HubSpot API to fetch a list of all contacts
            associated with the account.

            Returns:
                list: A list of dictionaries, each containing details of a contact, such as
                      email, first name, last name etc

            """
        try:
            return await sync_to_async(
                self._connection.crm.contacts.get_all
            )
        except ContactCreateException as ex:
            message = f"Exception when getting contacts {ex}"
            logger.error(message, exc_info=ex)
            raise

    @tool
    async def create_company(
            self,
            *,
            name: str,
            domain: str = ""
    ):
        """
            create a new company in HubSpot.

            This method sends a request to the HubSpot API to create a new company
            using the provided name and an optional domain.

            Args:
                name (str): The name of the company. This field is required.
                domain (str, optional): The domain of the company. Defaults to an empty string.

            Returns:
                dict: A dictionary containing the details of the created company info
            """
        try:
            simple_public_object_input_for_create = CompanyObjectBuilder(
                properties={
                    "domain": domain,
                    "name": name
                }
            )
            return await sync_to_async(
                self._connection.crm.companies.basic_api.create,
                simple_public_object_input_for_create=simple_public_object_input_for_create
            )
        except ApiException as ex:
            message = f"Exception when creating Company {ex}"
            logger.error(message, exc_info=ex)
            raise

    @tool
    async def get_all_company(
            self
    ):
        """
            retrieve all companies from HubSpot.

            This method sends a request to the HubSpot API to fetch a list of all companies
            associated with the account.

            Returns:
                list: A list of dictionaries, each containing details of a company, such as
                      name, domain, etc...
            """
        try:
            return await sync_to_async(
                self._connection.crm.companies.get_all
            )
        except ApiException as ex:
            message = f"Exception when getting company {ex}"
            logger.error(message, exc_info=ex)
            raise

    @tool
    async def get_all_deals(
            self
    ):
        """
            Get the all Deals from HubSpot.

            This method sends a request to the HubSpot API to fetch a list of all deals
            associated with the account.

            Returns:
                list: A list of dictionaries, each containing details of a deal, such as
                      deal name, amount, stage, etc...
            """
        try:
            return await sync_to_async(
                self._connection.crm.deals.get_all
            )
        except DealCreationException as ex:
            message = f"Exception when getting deals {ex}"
            logger.error(message, exc_info=ex)
            raise

    @tool
    async def get_all_tickets(
            self
    ):
        """
            retrieve all tickets from HubSpot.

            This method sends a request to the HubSpot API to fetch a list of all tickets
            associated with the account.

            Returns:
                list: A list of dictionaries, each containing details of a ticket, such as
                      ticket ID, status, subject, and associated contact.

            """
        try:
            return await sync_to_async(
                self._connection.crm.tickets.get_all
            )
        except TicketException as ex:
            message = f"Exception when getting tickets {ex}"
            logger.error(message, exc_info=ex)
            raise

    @tool
    async def get_ticket_status(
            self,
            *,
            policy_number: str,
            property_name: str = "subject"
    ):
        """
            Retrieve the status of a ticket based on the specified policy number.

            Args:
                policy_number (str): The policy number associated with the ticket.
                property_name (str, optional): The property to filter the ticket by (default is "subject").

            Returns:
                dict: A dictionary containing the status of the ticket and other relevant details.
            """
        try:
            ticket_input = {
                "filterGroups": [{
                    "filters": [
                        {
                            "propertyName": property_name,
                            "operator": "CONTAINS_TOKEN",
                            "value": policy_number
                        }
                    ]
                }]
            }
            return await sync_to_async(
                self._connection.crm.tickets.search_api.do_search,
                public_object_search_request=ticket_input
            )
        except TicketException as ex:
            message = f"Exception when getting Ticket {ex}"
            logger.error(message, exc_info=ex)
            raise

    @tool
    async def create_ticket(
            self,
            *,
            subject: str,
            content: str,
            pipeline: int = 0,
            pipeline_stage: int = 1,
            source_from: str = "EMAIL",
            priority: str = "LOW"
    ):
        """
            Creates a new ticket.

            Args:
                subject (str): The subject of the ticket.
                content (str): The content or description of the ticket.
                pipeline (int, optional): The ID of the pipeline the ticket belongs to. Defaults to 0 (Pipeline name).
                pipeline_stage (int, optional): The stage of the pipeline for this ticket. Defaults to 1 (New).
                source_from (str, optional): The source from which the ticket is created. Defaults to "EMAIL";
                can also be "Chat", etc.
                priority (str, optional): The priority level of the ticket. Defaults to "LOW";
                can also be "Medium" or "High".

            Returns:
                Ticket: The created ticket object or relevant information regarding the ticket.

            """
        try:
            ticket_input = TicketObjectBuilder(
                properties={
                    "subject": subject,
                    "content": content,
                    "hs_pipeline": pipeline,
                    "hs_pipeline_stage": pipeline_stage,
                    "source_type": source_from,
                    "hs_ticket_priority": priority
                }
            )
            return await sync_to_async(
                self._connection.crm.tickets.basic_api.create,
                simple_public_object_input_for_create=ticket_input
            )
        except TicketException as ex:
            message = f"Exception when creating Ticket {ex}"
            logger.error(message, exc_info=ex)
            raise
