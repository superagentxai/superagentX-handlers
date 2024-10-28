import logging

import pytest

from superagentx_handlers import WeatherHandler

logger = logging.getLogger(__name__)


@pytest.fixture
async def weather_handler_init() -> WeatherHandler:
    return WeatherHandler()


class TestWeather:

    async def test_get_lat_lang(self, weather_handler_init: WeatherHandler):
        res = await weather_handler_init.get_lat_long(place="New York, USA")
        logger.info(f'Lat Lang => {res}')
        assert res and res['latitude'] == '40.7127281' and res['longitude'] == '-74.0060152'

    async def test_get_weather(self, weather_handler_init: WeatherHandler):
        res = await weather_handler_init.get_weather(
            latitude='40.7127281',
            longitude='-74.0060152'
        )
        logger.info(f'weather => {res}')
        assert res
