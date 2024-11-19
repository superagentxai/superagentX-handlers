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
pagination = "&pageSize=100"
response_format = "&format=json"

class BestbuyHandler(BaseHandler, ABC):

    def __init__(self,
                 *,
                 api_key: str
                 ):
        super().__init__()
        self.api_key = api_key

    @tool
    async def get_best_buy_info(self, keyword:str):

        search_keyword = f"(({keyword}))" if keyword else ""
        url = f"{base_url}{search_keyword}?{show_options}{response_format}{pagination}&apiKey={self.api_key}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url=url) as resp:
                return await resp.json()

