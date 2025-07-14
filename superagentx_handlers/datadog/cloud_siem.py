import os

from superagentx.handler.base import BaseHandler


class DDCloudSIEMHandler(BaseHandler):
    def __init__(
            self,
            api_key: str | None = None,
            app_key: str | None = None
    ):
        super().__init__()
        self.api_key = api_key or os.getenv('DD_API_KEY')
        self.app_key = app_key or os.getenv('DD_APP_KEY')
