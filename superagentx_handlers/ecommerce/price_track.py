from urllib.request import BaseHandler

import aiohttp
import requests
from requests_html import HTMLSession
from bs4 import BeautifulSoup
session = HTMLSession()

BASE_URL = 'https://pricetracker.wtf/api/product/search?q='

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


