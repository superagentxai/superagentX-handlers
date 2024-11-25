from urllib.request import BaseHandler

import aiohttp
import requests
from requests_html import HTMLSession
from bs4 import BeautifulSoup
session = HTMLSession()

BASE_URL = 'https://pricetracker.wtf/api/product/search?q='
# product_url = 'https://www.bestbuy.com/site/apple-10-2-inch-ipad-with-wi-fi-64gb-space-gray/4901809.p?skuId=4901809'

# def getdata(url):
#     r = session.get(url)
#     r.html.render(sleep=1)
#     soup = BeautifulSoup(r.html.html, 'html.parser')
#     return soup

class PriceTrackHandler(BaseHandler):
    def __init__(
            self,
            product_url:str
    ):
        self.product_url=product_url

    async def get_track_detail_by_product_url(self):
        url = BASE_URL + self.product_url
        async with aiohttp.ClientSession() as session:
            async with session.get(url=url) as resp:
                data = await resp.json()
                if data.get('items')  and data.get('items')[0]:
                    return data.get('items')[0].get("detailsUrl")


