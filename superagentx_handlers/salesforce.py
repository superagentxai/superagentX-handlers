import os
import logging
from typing import Optional

from simple_salesforce import Salesforce
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

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
            return await sync_to_async(self.sf.Opportunity.get, opportunity_id)
        except Exception as e:
            logger.error(f"Error fetching opportunity: {str(e)}")
            raise

    @tool
    async def create_order(self, order_data: dict):
        """
        Create a new Order in Salesforce.

        Args:
            order_data (dict): Complete order payload. Must include:

                Required Fields:
                    - AccountId (str): Salesforce Account ID
                    - EffectiveDate (str): Order start date (YYYY-MM-DD)
                    - Status (str): Order status (e.g., "Draft", "Activated")

                Optional Fields:
                    - Pricebook2Id (str): Price Book ID
                    - ContractId (str): Related Contract ID
                    - Description (str): Description of the order
                    - EndDate (str): Order end date (YYYY-MM-DD)
                    - Name (str): Order name

        Returns:
            dict: Created order response from Salesforce.
        """

        result = await sync_to_async(self.sf.Order.create, order_data)
        return result

    # ------------------------------------------------------------------
    # CREATE INVOICE
    # ------------------------------------------------------------------
    @tool
    async def create_invoice(self, invoice_data: dict):
        """
        Create a new Invoice (custom object) in Salesforce.

        Args:
            invoice_data (dict): Complete invoice payload. Must include:

                Required Fields:
                    - Account__c (str): Related Account ID
                    - Amount__c (float): Invoice amount
                    - Invoice_Date (str): Invoice date (YYYY-MM-DD)

                Optional Fields:
                    - Name (str): Invoice name
                    - Order__c (str): Related Order ID
                    - Due_Date__c (str): Payment due date (YYYY-MM-DD)
                    - Status__c (str): Invoice status (e.g., "Draft", "Pending", "Paid")
                    - CurrencyIsoCode (str): Currency code
                    - Description__c (str): Additional notes

        Returns:
            dict: Created invoice response from Salesforce.
        """

        result = await sync_to_async(self.sf.Invoice__c.create, invoice_data)
        return result

    # ------------------------------------------------------------------
    # CHECK STOCK
    # ------------------------------------------------------------------
    @tool
    async def check_stock(self, query: str):
        """
        Execute a SOQL query to check stock details.

        Args:
            query (str): Complete SOQL query.

                Example:
                    SELECT Id, Name, Available_Quantity__c
                    FROM Product__c
                    WHERE Name = 'Laptop'

        Returns:
            dict: Query result containing stock records.
        """

        result = await sync_to_async(self.sf.query, query)
        return result

    # ------------------------------------------------------------------
    # CREATE PURCHASE ORDER
    # ------------------------------------------------------------------
    @tool
    async def create_purchase_order(self, po_data: dict):
        """
        Create a Purchase Order (custom object) in Salesforce.

        Args:
            po_data (dict): Complete purchase order payload. Must include:

                Required Fields:
                    - Supplier__c (str): Supplier/Vendor Account ID
                    - Order_Date__c (str): Purchase order date (YYYY-MM-DD)
                    - Total_Amount__c (float): Total purchase amount

                Optional Fields:
                    - Name (str): Purchase order name
                    - Order__c (str): Related Sales Order ID
                    - Status__c (str): PO status (e.g., "Draft", "Approved", "Ordered")
                    - Expected_Delivery__c (str): Delivery date (YYYY-MM-DD)
                    - Description__c (str): Notes

        Returns:
            dict: Created purchase order response from Salesforce.
        """

        result = await sync_to_async(self.sf.Purchase_Order__c.create, po_data)
        return result

    # ------------------------------------------------------------------
    # PROCESS CLOSED WON FLOW
    # ------------------------------------------------------------------
    @tool
    async def process_closed_won(
            self,
            opportunity_id: str,
            order_data: dict,
            invoice_data: dict,
            product_query: Optional[str] = None,
            po_data: Optional[dict] = None
    ):
        """
        Process ERP workflow when an Opportunity is marked as Closed Won.

        This includes:
            - Creating an Order
            - Creating an Invoice
            - Checking Stock
            - Creating a Purchase Order (optional)

        Args:
            opportunity_id (str): Salesforce Opportunity ID (must be Closed Won)

            order_data (dict): Must include:
                - AccountId
                - EffectiveDate
                - Status

            invoice_data (dict): Must include:
                - Account__c
                - Amount__c
                - Invoice_Date__c

            product_query (str, optional): SOQL query for stock check

            po_data (dict, optional): Must include:
                - Supplier__c
                - Order_Date__c
                - Total_Amount__c

        Returns:
            dict: Combined ERP operation results
        """

        opp = await sync_to_async(self.sf.Opportunity.get, opportunity_id)

        if opp["StageName"] != "Closed Won":
            return {"message": "Opportunity not Closed Won"}

        order = await self.create_order(order_data)
        invoice = await self.create_invoice(invoice_data)
        stock = await self.check_stock(product_query) if product_query else {}

        po = None
        if po_data:
            po = await self.create_purchase_order(po_data)

        return {
            "status": "success",
            "order": order,
            "invoice": invoice,
            "stock": stock,
            "purchase_order": po
        }