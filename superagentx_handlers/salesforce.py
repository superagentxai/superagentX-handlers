import os
import logging
from typing import Optional
from simple_salesforce.aio import AsyncSalesforce
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class SalesforceERPHandler(BaseHandler):
    """
    Handler for interacting with Salesforce in an ERP-style workflow.

    This class provides asynchronous methods to:
    - Fetch Opportunities
    - Create Orders
    - Create Invoices (custom object)
    - Check stock using SOQL queries
    - Create Purchase Orders (custom object)
    - Execute a full ERP flow when an Opportunity is Closed Won
    """

    def __init__(
        self,
        instance_url: Optional[str] = None,
        access_token: Optional[str] = None
    ):
        """
        Initialize the Salesforce ERP handler.

        Args:
            instance_url (Optional[str]): Salesforce instance URL.
                If not provided, it will be read from the environment variable `SF_INSTANCE_URL`.

            access_token (Optional[str]): OAuth access token.
                If not provided, it will be read from the environment variable `SF_ACCESS_TOKEN`.

        Raises:
            ValueError: If instance_url or access_token is missing.
        """
        super().__init__()

        self.instance_url = instance_url or os.getenv("SF_INSTANCE_URL")
        self.access_token = access_token or os.getenv("SF_ACCESS_TOKEN")

        if not self.instance_url or not self.access_token:
            raise ValueError("Salesforce OAuth credentials are required")

        self.sf = AsyncSalesforce(
            instance_url=self.instance_url,
            session_id=self.access_token
        )

    @tool
    async def get_opportunity(self, opportunity_id: str):
        """
        Fetch an Opportunity record from Salesforce.

        Args:
            opportunity_id (str): The Salesforce Opportunity ID.

        Returns:
            dict: Opportunity details including fields like StageName, Amount, AccountId.

        Raises:
            Exception: If the API call fails.
        """
        try:
            return await self.sf.Opportunity.get(opportunity_id)
        except Exception as e:
            logger.error(f"Error fetching opportunity: {str(e)}")
            raise

    @tool
    async def create_order(
        self,
        account_id: str,
        order_data: Optional[dict] = None
    ):
        """
        Create a new Order in Salesforce.

        Args:
            account_id (str): Salesforce Account ID associated with the order.
            order_data (Optional[dict]): Additional fields for the Order object.

        Returns:
            dict: Response from Salesforce containing Order creation details.

        Raises:
            Exception: If order creation fails.
        """
        try:
            order_data = order_data or {}

            order_data.setdefault("EffectiveDate", "2026-04-03")
            order_data.setdefault("Status", "Draft")
            order_data["AccountId"] = account_id

            return await self.sf.Order.create(order_data)

        except Exception as e:
            logger.error(f"Error creating order: {str(e)}")
            raise

    @tool
    async def create_invoice(self, invoice_data: dict):
        """
        Create a new Invoice record (custom object: Invoice__c).

        Args:
            invoice_data (dict): Fields required to create the invoice.

        Returns:
            dict: Response from Salesforce containing Invoice creation details.

        Raises:
            Exception: If invoice creation fails.
        """
        try:
            invoice_data.setdefault("Status__c", "Pending")
            return await self.sf.Invoice__c.create(invoice_data)
        except Exception as e:
            logger.error(f"Error creating invoice: {str(e)}")
            raise

    @tool
    async def check_stock(self, query: str):
        """
        Execute a SOQL query to retrieve stock or inventory details.

        Args:
            query (str): SOQL query string.

        Returns:
            dict: Query result containing records and metadata.

        Raises:
            Exception: If query execution fails.
        """
        try:
            return await self.sf.query(query)
        except Exception as e:
            logger.error(f"Error checking stock: {str(e)}")
            raise

    @tool
    async def create_purchase_order(self, po_data: dict):
        """
        Create a Purchase Order (custom object: Purchase_Order__c).

        Args:
            po_data (dict): Fields required to create the purchase order.

        Returns:
            dict: Response from Salesforce containing Purchase Order creation details.

        Raises:
            Exception: If purchase order creation fails.
        """
        try:
            po_data.setdefault("Status__c", "Draft")
            return await self.sf.Purchase_Order__c.create(po_data)
        except Exception as e:
            logger.error(f"Error creating purchase order: {str(e)}")
            raise

    @tool
    async def process_closed_won(
        self,
        opportunity_id: str,
        order_data: Optional[dict] = None,
        invoice_data: Optional[dict] = None,
        product_query: Optional[str] = None,
        po_data: Optional[dict] = None
    ):
        """
        Execute ERP workflow when an Opportunity reaches 'Closed Won' stage.

        This workflow includes:
        - Fetching the Opportunity
        - Creating an Order
        - Creating an Invoice
        - Checking stock using a SOQL query
        - Optionally creating a Purchase Order

        Args:
            opportunity_id (str): Salesforce Opportunity ID.
            order_data (Optional[dict]): Additional Order fields.
            invoice_data (Optional[dict]): Additional Invoice fields.
            product_query (Optional[str]): SOQL query to check stock.
            po_data (Optional[dict]): Data for creating a Purchase Order.

        Returns:
            dict: Combined result including order, invoice, stock, and purchase order details.

        Raises:
            Exception: If any step in the workflow fails.
        """
        try:
            opp = await self.sf.Opportunity.get(opportunity_id)

            if opp["StageName"] != "Closed Won":
                return {"message": "Opportunity not Closed Won"}

            account_id = opp["AccountId"]
            amount = opp.get("Amount", 0)

            order = await self.create_order(account_id, order_data)

            invoice_payload = invoice_data or {
                "Account__c": account_id,
                "Amount__c": amount
            }
            invoice = await self.create_invoice(invoice_payload)

            stock = await self.check_stock(product_query) if product_query else {}

            po_result = None
            if po_data:
                po_result = await self.create_purchase_order(po_data)

            return {
                "status": "success",
                "order": order,
                "invoice": invoice,
                "stock": stock,
                "purchase_order": po_result
            }

        except Exception as e:
            logger.error(f"Error processing ERP flow: {str(e)}")
            raise