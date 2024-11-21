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

DEFAULT_PAGINATION = "pageSize=100"
RESPONSE_FORMAT = "format=json"


class BestBuyError(Exception):
    pass


class BestbuyHandler(BaseHandler):
    """
    A handler for interacting with the Best Buy API.

    This class provides methods to retrieve information about products from
    Best Buy's inventory using the API, with options for customization such
    as search filters, pagination, and response formatting.

    Attributes:
        api_key (str): The API key used for authenticating requests to the
            Best Buy API.

    Methods:
        get_best_buy_info(search_text: str, show_options: str = SHOW_OPTIONS,
                          pagination: str = DEFAULT_PAGINATION,
                          response_format: str = RESPONSE_FORMAT) -> dict:
            Asynchronously retrieves product information from the Best Buy API
            based on the provided search text and optional parameters for
            customization.
    """

    def __init__(
            self,
            *,
            api_key: str
    ):
        super().__init__()
        self.api_key = api_key

    @tool
    async def get_best_buy_info(
            self,
            search_text: str,
            show_options: str = SHOW_OPTIONS,
            pagination: str = DEFAULT_PAGINATION,
            response_format: str = RESPONSE_FORMAT
    ):
        """
        Fetches product information from the Best Buy API based on the search text.

        Args:
            search_text (str): The keyword or query string to search for products.
            show_options (str, optional): The fields to be included in the API response.
                Defaults to `SHOW_OPTIONS`, which includes fields like customer review
                average, model number, sale price, etc.
            pagination (str, optional): Pagination parameters to limit the number of
                results or specify the page size. Defaults to `DEFAULT_PAGINATION`.
            response_format (str, optional): The format of the API response.
                Defaults to `RESPONSE_FORMAT` (e.g., JSON).

        """

        search_keyword = f"(({search_text}))" if search_text else ""

        url = (
            f"{BASE_URL}"
            f"{search_keyword}?"
            f"{show_options}"
            f"&{response_format}"
            f"&{pagination}"
            f"&apiKey={self.api_key}"
        )
        async with aiohttp.ClientSession() as session:
            async with session.get(url=url) as resp:
                if resp.status == 200:
                    return await resp.json()
                raise BestBuyError(await resp.text())
