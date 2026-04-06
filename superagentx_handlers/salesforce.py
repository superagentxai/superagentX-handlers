import os
import logging
from simple_salesforce import Salesforce
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class SalesforceERPHandler(BaseHandler):

    def __init__(
        self,
        instance_url: str | None = None,
        access_token: str | None = None
    ):
        """
        Initialize Salesforce handler with instance URL and access token.

        Args:
            instance_url (str): Salesforce instance URL.
            access_token (str): OAuth access token.
        """
        super().__init__()

        self.instance_url = instance_url or os.getenv("SF_INSTANCE_URL")
        self.access_token = access_token or os.getenv("SF_ACCESS_TOKEN")

        if not self.instance_url or not self.access_token:
            raise ValueError("Salesforce OAuth credentials are required")

        self.sf = Salesforce(
            instance_url=self.instance_url,
            session_id=self.access_token
        )

    @tool
    async def get_opportunity(self, opportunity_id: str):
        """
        Fetch an Opportunity record from Salesforce.

        Args:
            opportunity_id (str): Salesforce Opportunity ID.

        Returns:
            dict: Opportunity details.
        """
        try:
            return self.sf.Opportunity.get(opportunity_id)
        except Exception as e:
            logger.error(f"Error fetching opportunity: {str(e)}")
            raise

    @tool
    async def create_order(self, account_id: str, order_data: dict | None = None):
        """
        Create a new Order in Salesforce.

        Args:
            account_id (str): Salesforce Account ID.
            order_data (dict): Optional order fields.

        Returns:
            dict: Created order response.
        """
        try:
            order_data = order_data or {}

            order_data.setdefault("EffectiveDate", "2026-04-03")
            order_data.setdefault("Status", "Draft")

            order_data["AccountId"] = account_id

            result = self.sf.Order.create(order_data)
            logger.info(f"Order created: {result}")
            return result

        except Exception as e:
            logger.error(f"Error creating order: {str(e)}")
            raise

    @tool
    async def create_invoice(self, invoice_data: dict):
        """
        Create a new Invoice (custom object) in Salesforce.

        Args:
            invoice_data (dict): Invoice field data.

        Returns:
            dict: Created invoice response.
        """
        try:
            invoice_data.setdefault("Status__c", "Pending")

            result = self.sf.Invoice__c.create(invoice_data)
            return result

        except Exception as e:
            logger.error(f"Error creating invoice: {str(e)}")
            raise

    @tool
    def check_stock(self, query: str):
        """
        Execute a SOQL query to check stock details.

        Args:
            query (str): SOQL query string.

        Returns:
            dict: Query result containing stock data.
        """
        try:
            result = self.sf.query(query)
            return result
        except Exception as e:
            logger.error(f"Error checking stock: {str(e)}")
            raise

    @tool
    def create_purchase_order(self, po_data: dict):
        """
        Create a Purchase Order (custom object) in Salesforce.

        Args:
            po_data (dict): Purchase order field data.

        Returns:
            dict: Created purchase order response.
        """
        try:
            po_data.setdefault("Status__c", "Draft")

            result = self.sf.Purchase_Order__c.create(po_data)
            return result

        except Exception as e:
            logger.error(f"Error creating purchase order: {str(e)}")
            raise

    @tool
    async def process_closed_won(
            self,
            opportunity_id: str,
            order_data: dict | None = None,
            invoice_data: dict | None = None,
            product_query: str | None = None,
            po_data: dict | None = None
    ):
        """
        Process ERP flow when an Opportunity is marked as Closed Won.

        This includes:
        - Creating an Order
        - Creating an Invoice
        - Checking Stock
        - Creating a Purchase Order (optional)

        Args:
            opportunity_id (str): Salesforce Opportunity ID.
            order_data (dict): Optional order data.
            invoice_data (dict): Optional invoice data.
            product_query (str): SOQL query to check stock.
            po_data (dict): Optional purchase order data.

        Returns:
            dict: Combined result of ERP operations.
        """
        try:
            opp = self.sf.Opportunity.get(opportunity_id)

            if opp["StageName"] != "Closed Won":
                return {"message": "Opportunity not Closed Won"}

            account_id = opp["AccountId"]
            amount = opp.get("Amount", 0)

            order = await self.create_order(account_id, order_data or {})

            invoice_payload = invoice_data or {
                "Account__c": account_id,
                "Amount__c": amount
            }
            invoice = await self.create_invoice(invoice_payload)

            stock = self.check_stock(product_query) if product_query else {}

            if po_data:
                self.create_purchase_order(po_data)

            return {
                "status": "success",
                "order": order,
                "invoice": invoice,
                "stock": stock
            }

        except Exception as e:
            logger.error(f"Error processing ERP flow: {str(e)}")
            raise