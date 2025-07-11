import logging
import os
from typing import Any, Dict, List, Union

from google.api_core import exceptions
from google.cloud import apigateway_v1
from google.oauth2 import service_account
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async

logger = logging.getLogger(__name__)


def _get_gateway_state(state_value: Union[str, int, apigateway_v1.Gateway.State]) -> apigateway_v1.Gateway.State:
    if isinstance(state_value, apigateway_v1.Gateway.State):
        return state_value
    elif isinstance(state_value, str):
        state_map = {
            'ACTIVE': apigateway_v1.Gateway.State.ACTIVE,
            'CREATING': apigateway_v1.Gateway.State.CREATING,
            'FAILED': apigateway_v1.Gateway.State.FAILED,
            'DELETING': apigateway_v1.Gateway.State.DELETING,
            'UPDATING': apigateway_v1.Gateway.State.UPDATING
        }
        return state_map.get(state_value.upper(), apigateway_v1.Gateway.State.ACTIVE)
    elif isinstance(state_value, int):
        return apigateway_v1.Gateway.State(state_value)
    else:
        return apigateway_v1.Gateway.State.ACTIVE


class GCPAPIGatewayHandler(BaseHandler):
    def __init__(
            self,
            creds: str | dict | None = None
    ):
        super().__init__()

        self.locations = [
            'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2', 'us-west3', 'us-west4',
            'europe-west1', 'europe-west2', 'europe-west3', 'europe-west4', 'europe-west6',
            'europe-central2', 'asia-east1', 'asia-east2', 'asia-northeast1', 'asia-northeast2',
            'asia-northeast3', 'asia-south1', 'asia-southeast1', 'asia-southeast2'
        ]

        creds = creds or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if isinstance(creds, str):
            credentials = service_account.Credentials.from_service_account_file(
                creds
            )
        elif isinstance(creds, dict):
            credentials = service_account.Credentials.from_service_account_info(
                creds
            )
        else:
            raise ValueError("Invalid credentials")

        self.project_id = credentials.project_id
        if not self.project_id:
            raise ValueError("Project ID not found. Set GOOGLE_CLOUD_PROJECT or provide project_id in service account.")

        # Initialize the API Gateway client
        self.client = apigateway_v1.ApiGatewayServiceAsyncClient(credentials=credentials)

    @tool
    async def list_gateways(self, page_size: int = 100) -> List[Dict[str, Any]]:
        """
        List all GCP API Gateways asynchronously.

        Args:
            page_size: Number of results per page.

        Returns:
            List of Gateway property dictionaries.
        """
        gateways = []
        try:
            logger.debug("Starting to list Gateways")

            for location in self.locations:
                parent_path = f"projects/{self.project_id}/locations/{location}"
                request = await sync_to_async(
                    apigateway_v1.ListGatewaysRequest,
                    parent=parent_path,
                    page_size=page_size
                )

                try:
                    async for gateway in await self.client.list_gateways(request=request):
                        logger.debug(f"Gateway found: {gateway.name}")
                        gateways.append(await self._gateway_to_dict(gateway=gateway, location=location))
                except exceptions.NotFound:
                    logger.warning(f"No gateways found in location: {location}")
                    continue
                except exceptions.PermissionDenied as e:
                    logger.error(f"Permission denied in location {location}: {e}")
                    continue
                except exceptions.GoogleAPICallError as e:
                    logger.error(f"Failed to list gateways in location {location}: {e}")
                    continue

            logger.info(f"Total gateways found: {len(gateways)}")

        except Exception as e:
            logger.error(f"Unexpected error while listing gateways: {e}")

        return gateways

    async def _gateway_to_dict(self, gateway: apigateway_v1.Gateway, location: str) -> Dict[str, Any]:
        state = _get_gateway_state(gateway.state) if gateway.state else apigateway_v1.Gateway.State.ACTIVE
        return {
            'name': gateway.name,
            'display_name': gateway.display_name or '',
            'api_config': gateway.api_config or '',
            'state': state.name if state else None,
            'state_value': int(state) if state else None,
            'default_hostname': gateway.default_hostname or '',
            'labels': dict(gateway.labels) if gateway.labels else {},
            'create_time': gateway.create_time.isoformat() if gateway.create_time else None,
            'update_time': gateway.update_time.isoformat() if gateway.update_time else None,
            'resource_id': gateway.name.split('/')[-1] if gateway.name else None,
            'project_id': self.project_id,
            'location': location,
            'full_resource_name': gateway.name or ''
        }
