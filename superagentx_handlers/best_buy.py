from abc import ABC
import aiohttp
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

base_url = "https://api.bestbuy.com/v1/products"
show_options = ("show=customerReviewAverage"
                ",customerReviewCount"
                ",dollarSavings"
                ",image"
                ",includedItemList.includedItem"
                ",modelNumber"
                ",name"
                ",onlineAvailability"
                ",onSale"
                ",percentSavings"
                ",regularPrice"
                ",salePrice"
                ",sku"
                ",thumbnailImage")
default_pagination = "&pageSize=100"
response_format = "&format=json"


class BestbuyHandler(BaseHandler, ABC):
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
    async def get_best_buy_info(self, keyword: str, pagination: str = None):
        """
            Retrieves product information from the Best Buy API.

            Args:
                keyword (str): The search keyword to look for products.
                pagination (str, optional): Pagination token or parameters for fetching
                    additional results. Defaults to None.

        """

        search_keyword = f"(({keyword}))" if keyword else ""
        pagination = pagination if pagination else default_pagination

        url = f"{base_url}{search_keyword}?{show_options}{response_format}{pagination}&apiKey={self.api_key}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url=url) as resp:
                return await resp.json()
