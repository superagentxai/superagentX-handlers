import aiohttp
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import iter_to_aiter

BASE_URL = "https://api.bestbuy.com/v1/products"

SHOW_OPTIONS = (
    "show=customerReviewAverage,"
    "customerReviewCount,"
    "dollarSavings,"
    "url,"
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
            search_text: str
    ):
        """
        Fetches product information from the Best Buy API based on the search text.

        Args:
            search_text (str): The keyword or query string to search for products.
        """

        search_keyword = f"((search={search_text}))" if search_text else ""

        url = (
            f"{BASE_URL}"
            f"{search_keyword}?"
            f"{SHOW_OPTIONS}"
            f"&{RESPONSE_FORMAT}"
            f"&{DEFAULT_PAGINATION}"
            f"&apiKey={self.api_key}"
        )
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url=url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        products = data['products']
                        if products:
                            return [
                                {
                                    'title': item.get('name'),
                                    'link': item.get('url'),
                                    'saleprice': item.get('salePrice'),
                                    'oldprice': item.get('regularPrice'),
                                    'reviews': item.get('customerReviewCount')
                                }
                                async for item in iter_to_aiter(products)
                            ]
                    raise BestBuyError(await resp.text())
        except Exception as ex:
            raise BestBuyError(ex)
