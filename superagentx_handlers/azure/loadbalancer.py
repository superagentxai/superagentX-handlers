import logging
import os

from azure.core.exceptions import AzureError
from azure.identity.aio import ClientSecretCredential
from azure.mgmt.network.aio import NetworkManagementClient
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class AzureLoadBalancerHandler(BaseHandler):
    """
    A handler class for managing Azure Load Balancer management class for retrieving and managing load balancers
    within the configured Azure subscription, facilitating server asset detail collection.
    """

    def __init__(
            self,
            *,
            subscription_id: str | None = None,
            tenant_id: str | None = None,
            client_id: str | None = None,
            client_secret: str | None = None
    ):
        super().__init__()
        self.subscription_id = subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID")
        self.tenant_id = tenant_id or os.getenv("AZURE_TENANT_ID")
        self.client_id = client_id or os.getenv("AZURE_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("AZURE_CLIENT_SECRET")

        self.credential = ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret
        )
        self.network_client = NetworkManagementClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )

    @tool
    async def get_all_load_balancers_in_subscription(self) -> list:
        """
        Get all load balancers in the subscription

        Returns:
            list: List of load balancer properties
        """
        try:
            load_balancers = [lb async for lb in self.network_client.load_balancers.list_all()]
            logger.debug(f"Successfully retrieved {len(load_balancers)} load balancers from subscription")
            return load_balancers
        except AzureError as e:
            logger.error(f"Azure error retrieving load balancers from subscription {self.subscription_id}: {str(e)}")
        except Exception as e:
            logger.error(
                f"Unexpected error retrieving load balancers from subscription {self.subscription_id}: {str(e)}"
            )
            raise
        finally:
            if self.network_client:
                await self.network_client.close()
            if self.credential:
                await self.credential.close()
            logger.debug("Closed Azure Load Balancer manager connections")
        return []
