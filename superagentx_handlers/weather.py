import aiohttp

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

class WeatherHandler(BaseHandler):

    @tool
    async def get_weather(
            self,
            latitude: str,
            longitude: str
    ) -> dict:
        """
        Get the weather data based on given latitude & longitude.

        Args:
            @param latitude: latitude of the location
            @param longitude: longitude of the location

            @return result (Str): Returns real time weather for the given latitude & longitude
        """

        url = f"https://api.open-meteo.com/v1/forecast?latitude={latitude}&longitude={longitude}&current_weather=true"
        async with aiohttp.ClientSession() as session:
            async with session.get(url=url) as resp:
                return await resp.json()

    @tool
    async def get_lat_long(
            self,
            place: str
    ) -> dict:

        """
        Get the coordinates of a city based on a location.

        Args:
            @param place: The place name

            @return result (Str): Return the real latitude & longitude for the given place.

        """

        header_dict = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                          " (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
            "referer": 'https://www.guichevirtual.com.br'
        }
        url = "http://nominatim.openstreetmap.org/search"

        params = {
            'q': place,
            'format': 'json',
            'limit': 1
        }
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url=url,
                params=params,
                headers=header_dict
            ) as resp:
                resp_data = await resp.json()
                if resp_data:
                    lat = resp_data[0]["lat"]
                    lon = resp_data[0]["lon"]
                    return {
                        "latitude": lat,
                        "longitude": lon
                    }
        return {}
