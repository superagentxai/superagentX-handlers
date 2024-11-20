from abc import ABC
import aiohttp
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

BASE_URL = "https://api.bestbuy.com/v1/products"

SHOW_OPTIONS = (
    "show=customerReviewAverage,"
    "customerReviewCount,"
    "dollarSavings,"
    "image,"
    "includedItemList.includedItem,"
    "modelNumber,"
    "name,"
    "onlineAvailability,"
    "onSale,"
    "percentSavings,"
    "regularPrice,"
    "salePrice,"
    "sku,"
    "thumbnailImage"
)

DEFAULT_PAGINATION = "&pageSize=100"
RESPONSE_FORMAT = "&format=json"



class BestbuyHandler(BaseHandler):
    """
    A handler for interacting with the Best Buy API. This class provides methods
    to retrieve information about products from Best Buy's inventory.

    Attributes:
        api_key (str): The API key for authenticating requests to the Best Buy API.

    Methods:
        get_best_buy_info(keyword: str, pagination: str = None) -> dict:
            Retrieves product information from the Best Buy API based on the specified keyword.
    """

    def __init__(self,
                 *,
                 api_key: str
                 ):
        super().__init__()
        self.api_key = api_key

    @tool
    async def get_best_buy_info(self, search_text: str, pagination: str = None):
        """
        Retrieves product information from the Best Buy API.

        Args:
            search_text (str): The search keyword to look for products.
            pagination (str, optional): Pagination token or parameters for fetching
                additional results. Defaults to None.

        """

        search_keyword = f"(({search_text}))" if search_text else ""
        pagination = pagination if pagination else DEFAULT_PAGINATION

        url = f"{BASE_URL}{search_keyword}?{SHOW_OPTIONS}{RESPONSE_FORMAT}{pagination}&apiKey={self.api_key}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url=url) as resp:
                return await resp.json()
