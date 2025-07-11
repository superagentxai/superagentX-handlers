from superagentx_handlers.gcp.api_gateway import GCPAPIGatewayHandler
import asyncio
import logging

logger = logging.getLogger(__name__)


async def main():
    """
    Test function to list API Gateways.
    """
    try:

        handler = GCPAPIGatewayHandler()
        gateways = await handler.list_gateways(page_size=50)

        if gateways:
            for gateway in gateways:
                print(f"Gateway: {gateway['name']}")
                print(f"  Location: {gateway['location']}")
                print(f"  State: {gateway['state']}")
                print(f"  Default Hostname: {gateway['default_hostname']}")
                print("---")
        else:
            print("No gateways found.")

    except Exception as e:
        logger.error(f"Error in main: {e}")
        print(f"Failed to list gateways: {e}")


if __name__ == "__main__":
    asyncio.run(main())
