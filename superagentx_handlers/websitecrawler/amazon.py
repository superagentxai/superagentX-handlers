import asyncio
import logging

from bs4 import BeautifulSoup
from requests_html import AsyncHTMLSession
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async, iter_to_aiter

logger = logging.getLogger(__name__)


class AmazonWebHandler(BaseHandler):

    def __init__(
            self,
    ):
        super().__init__()
        self.deals_list = []

    @staticmethod
    async def _get_data(url: str):
        headers = {
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)'
                          ' Chrome/98.0.4758.80 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,'
                      'image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'rtt': '200'
        }
        r = await AsyncHTMLSession().get(
            url,
            headers=headers
        )
        return BeautifulSoup(
            r.html.html,
            'html.parser'
        )

    async def _get_deals(
            self,
            soup
    ):
        products = await sync_to_async(
            soup.find_all,
            'div',
            {
                'data-component-type': 's-search-result'
            }
        )
        if products:
            async for item in iter_to_aiter(products):
                sale_price = ''
                title_find = await sync_to_async(
                    item.find,
                    'a',
                    {
                        'class': 'a-link-normal '
                                 's-underline-text '
                                 's-underline-link-text '
                                 's-link-style a-text-normal'
                    }
                )
                if title_find:
                    title = title_find.text.strip()
                    link_find = await sync_to_async(
                        item.find,
                        'a',
                        {
                            'class': 'a-link-normal s-underline-text s-underline-link-text s-link-style a-text-normal'
                        }
                    )
                    link = link_find.get('href')
                    try:
                        sale_prices = await sync_to_async(
                            item.find_all, 'span', {'class': 'a-offscreen'}
                        )
                        if sale_prices:
                            sale_price = sale_prices[0].text.replace('$', '').replace(',', '').strip()

                        old_prices = await sync_to_async(
                            item.find_all,
                            'span', {'class': 'a-offscreen'}
                        )
                        if  len(old_prices) > 1:
                            old_price = old_prices[1].text.replace('$', '').replace(',', '').strip()
                        else:
                            old_price = ''
                    except ValueError:
                        old_prices = await sync_to_async(
                            item.find,
                            'span',
                            {
                                'class': 'a-offscreen'
                            }
                        )
                        old_price = float(
                            old_prices.text.replace('$', '').replace(',', '').strip()
                        )
                    try:
                        reviews_find = await sync_to_async(
                            item.find,
                            'span',
                            {
                                'class': 'a-size-base'
                            }
                        )
                        reviews = float(reviews_find.text.strip())
                    except ValueError:
                        reviews = 0
                        logger.error("float error!...")

                    sale_item = {
                        'title': title,
                        'link': 'https://www.amazon.com' + link,
                        'sale_price': sale_price,
                        'old_price': old_price,
                        'reviews': reviews
                    }
                    self.deals_list.append(sale_item)

    @staticmethod
    async def _get_next_page(
            soup
    ):
        pages = await sync_to_async(
            soup.find,
            'span',
            {
                'class': 's-pagination-strip'
            }
        )
        if pages:
            all_pages = await sync_to_async(
                pages.find,
                'ul',
                {
                    'class': 'a-unordered-list a-horizontal s-unordered-list-accessibility'
                }
            )
            await asyncio.sleep(1)
            list_page = []
            if not all_pages:
                _list = await sync_to_async(
                    pages.find_all,
                    "a",
                    {
                        "class": "s-pagination-item s-pagination-button"
                    }
                )
                async for page in iter_to_aiter(_list):
                    list_page.append(
                        'https://www.amazon.com/s?k=' + page.get("href")
                    )
                return list_page
            else:
                li_urls = await sync_to_async(
                    all_pages.find_all,
                    'li',
                    {
                        'class': 's-list-item-margin-right-adjustment'
                    }
                )
                async for _url in iter_to_aiter(li_urls):
                    a_url = await sync_to_async(
                        _url.find,
                        'a',
                        {
                            'class': 's-pagination-item s-pagination-button s-pagination-button-accessibility'
                        }
                    )
                    if a_url:
                        list_page.append(
                            'https://www.amazon.com/s?k=' + a_url.get("href")
                        )
                return list_page

    @tool
    async def search(
            self,
            query: str
    ):

        """
        Searches for products on Amazon based on the given url.

        This method helps you find products on Amazon by using a search term like "laptop" or
        "headphones." It will return a list of items that match what you're looking for, along
        with important details like the product name, price, ratings, comments, and other feedback from customers.

        Args:
            query (str): The word or phrase you want to search for on Amazon.

        Returns:
            A list of products that match your search term, with information about each item.
        """

        url = f'https://www.amazon.com/s?k={query}'
        soup = await self._get_data(
            url
        )
        await self._get_deals(soup=soup)
        await asyncio.sleep(1)
        return self.deals_list
