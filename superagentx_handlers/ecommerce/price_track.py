from urllib.request import BaseHandler

import aiohttp
import requests
from requests_html import HTMLSession
from bs4 import BeautifulSoup

session = HTMLSession()

BASE_URL = 'https://pricetracker.wtf/api/product/search?q='
CLASS_NAME = "table-auto"


async def get_header(table):
    # Extract table headers
    headers = [header.text for header in table.find_all("th")]
    return headers


class PriceTrackingException(Exception):
    pass


async def get_table_json(table):
    # Extract table rows
    table_rows = table.find_all("tr")
    # Extract table data
    table_json = []
    headers = await get_header(table)
    for tbl_row in table_rows[1:]:  # Skip the header row
        cells = tbl_row.find_all("td")
        item = {}
        for idx, cell in enumerate(cells):
            if idx == 0 and cell.find("a"):
                item[headers[idx] if headers[idx] else 'link'] = cell.find("a").get('href')
            if idx == 1:
                item[headers[idx] if headers[idx] else 'site_name'] = cell.text.strip()
            if headers[idx] and headers[idx].strip():
                item[headers[idx]] = cell.text.strip()
        table_json.append(item)
    return table_json


async def get_table_by_url(url, class_name: str = CLASS_NAME):
    # Example HTML content
    response = requests.get(url)
    html_content = ""
    if response.status_code == 200:
        html_content = response.text
    else:
        PriceTrackingException(f"Failed to fetch HTML content. Status code: {response.status_code}")

    # Parse the HTML
    soup = BeautifulSoup(html_content, "html.parser")
    # Find the table
    table = soup.find("table", {"class": class_name})
    return table


class PriceTrackHandler(BaseHandler):
    def __init__(
            self,
            product_url: str
    ):
        self.product_url = product_url

    async def get_track_detail_by_product_url(self):
        url = BASE_URL + self.product_url
        async with aiohttp.ClientSession() as session:
            async with session.get(url=url) as resp:
                data = await resp.json()
                if data.get('items') and data.get('items')[0]:
                    return data.get('items')[0].get("detailsUrl")
