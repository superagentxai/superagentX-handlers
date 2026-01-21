import asyncio
import json
import logging
import gspread

from typing import Optional, List
from google.oauth2.credentials import Credentials
from pathlib import Path

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)

# SCOPES = [
#     "https://www.googleapis.com/auth/spreadsheets",
#     "https://www.googleapis.com/auth/drive",
# ]


class GoogleSheetsHandler(BaseHandler):
    """
    GoogleSheetsHandler provides async utility methods for interacting with
    Google Sheets using the Google Sheets API via gspread.

    This handler supports common Google Sheets operations such as:
    - Creating spreadsheets and worksheets
    - Writing tabular data
    - Appending rows
    - Reading worksheet data
    - Clearing worksheets
    - Deleting spreadsheets
    - Formatting worksheets for readability

    Authentication is handled via OAuth 2.0 access tokens, which must be
    valid and have the required Google Sheets and Drive scopes.

    All methods are asynchronous and designed to be used in async workflows
    or AI agent tools (LangChain `@tool`).

    Supported Operations:
        - create_spreadsheet
        - create_worksheet
        - write_table
        - append_row
        - read_all
        - clear_worksheet
        - delete_spreadsheet
        - format_worksheet

    Notes:
        - Requires Google API scopes such as:
          `https://www.googleapis.com/auth/spreadsheets`
          `https://www.googleapis.com/auth/drive`
        - This handler uses ACCESS TOKEN ONLY authentication.
        - No refresh tokens or client secrets are stored.
        - Tokens must be refreshed externally when expired.

    Raises:
        RuntimeError: If Google Sheets API calls fail.
        PermissionError: If OAuth scopes are insufficient.
        ValueError: If required parameters are missing or invalid.
    """

    def __init__(self, access_token: str):
        """
        Initializes the GoogleSheetsHandler with an OAuth2 access token.

        Args:
            access_token (str): A valid OAuth2 access token with Google Sheets
                                and Drive permissions.

            Raises:
                ValueError: If access_token is missing or empty.
        """
        super().__init__()

        if not access_token:
            raise ValueError("access_token is required")

        self.credentials = Credentials(
            token=access_token,
            # scopes=SCOPES,
        )

        self.client = gspread.authorize(self.credentials)

    @staticmethod
    async def sync_to_async(func):
        """
        Runs a blocking function in a background thread and returns the result.

        This utility allows synchronous gspread calls to be safely used inside
        async workflows.

        Args:
        func (Callable): A synchronous function to execute.

        Returns:
        Any: The return value of the executed function.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, func)

    def _open_spreadsheet(self, *, spreadsheet_name: str):
        """
        Opens a Google Spreadsheet by name.

        Args:
            spreadsheet_name (str): The name of the spreadsheet to open.

        Returns:
            gspread.Spreadsheet: The opened spreadsheet instance.

        Raises:
            ValueError: If spreadsheet_name is missing.
            RuntimeError: If the spreadsheet cannot be opened.
        """
        if not spreadsheet_name:
            raise ValueError("spreadsheet_name is required")

        try:
            return self.client.open(spreadsheet_name)
        except Exception as e:
            raise RuntimeError(f"Failed to open spreadsheet → {e}")

    def _open_worksheet(
        self,
        *,
        spreadsheet_name: str,
        worksheet_name: str,
    ):
        """
        Opens a worksheet within a spreadsheet.

            Args:
                spreadsheet_name (str): Name of the spreadsheet.
                worksheet_name (str): Name of the worksheet.

            Returns:
                gspread.Worksheet: The opened worksheet.

            Raises:
                ValueError: If worksheet_name is missing or not found.
        """
        if not worksheet_name:
            raise ValueError("worksheet_name is required")

        sheet = self._open_spreadsheet(spreadsheet_name=spreadsheet_name)

        try:
            return sheet.worksheet(worksheet_name)
        except Exception:
            raise ValueError(f"Worksheet '{worksheet_name}' not found")

    @tool
    async def create_spreadsheet(
            self,
            title: str
    ):
        """
        Creates a new Google Spreadsheet.

            Args:
                title (str): The title of the spreadsheet.

            Returns:
                dict: Status information including spreadsheet name and URL.
                    Example:
                        {
                            "status": "success",
                            "spreadsheet_name": "...",
                            "spreadsheet_url": "..."
                        }
        """
        try:
            def _create():
                sheet = self.client.create(title)
                return {
                    "status": "success",
                    "spreadsheet_name": sheet.title,
                    "spreadsheet_url": sheet.url,
                }

            return await self.sync_to_async(_create)

        except Exception as e:
            logger.error(f"Create spreadsheet failed → {e}")
            return {"status": "failed", "error": str(e)}

    @tool
    async def create_worksheet(
        self,
        *,
        spreadsheet_name: str,
        worksheet_name: str,
        rows: int,
        cols: int,
    ):
        """
        Creates a worksheet inside an existing spreadsheet.

            If the worksheet already exists, the operation succeeds without
            creating a duplicate.

            Args:
                spreadsheet_name (str): Name of the spreadsheet.
                worksheet_name (str): Name of the worksheet to create.
                rows (int): Number of rows.
                cols (int): Number of columns.

            Returns:
                dict: Status information about the worksheet creation.
        """
        try:
            def _create():
                sheet = self.client.open(spreadsheet_name)

                if worksheet_name in [ws.title for ws in sheet.worksheets()]:
                    return {
                        "status": "success",
                        "worksheet": worksheet_name,
                        "message": "Worksheet already exists",
                    }

                ws = sheet.add_worksheet(
                    title=worksheet_name,
                    rows=rows,
                    cols=cols,
                )

                return {
                    "status": "success",
                    "worksheet": ws.title,
                    "rows": rows,
                    "cols": cols,
                }

            return await self.sync_to_async(_create)

        except Exception as e:
            logger.error(f"Create worksheet failed → {e}")
            return {"status": "failed", "error": str(e)}

    @tool
    async def read_all(
        self,
        *,
        spreadsheet_name: str,
        worksheet_name: str,
    ):
        """
        Writes a 2D table of values to a worksheet starting at cell A1.

            Args:
                spreadsheet_name (str): Name of the spreadsheet.
                worksheet_name (str): Name of the worksheet.
                values (List[List]): 2D list representing rows and columns.

            Returns:
                dict: Status information including number of rows and columns written.
        """
        try:
            return await self.sync_to_async(
                lambda: self._open_worksheet(
                    spreadsheet_name=spreadsheet_name,
                    worksheet_name=worksheet_name,
                ).get_all_records()
            )

        except Exception as e:
            logger.error(f"Read failed → {e}")
            return {"status": "failed", "error": str(e)}

    @tool
    async def append_row(
        self,
        *,
        spreadsheet_name: str,
        worksheet_name: str,
        row_values: List,
    ):
        """
        Appends a single row to the end of a worksheet.

            Args:
                spreadsheet_name (str): Name of the spreadsheet.
                worksheet_name (str): Name of the worksheet.
                row_values (List): Values to append as a row.

            Returns:
                dict: Status information and appended values.
        """
        try:
            def _append():
                ws = self._open_worksheet(
                    spreadsheet_name=spreadsheet_name,
                    worksheet_name=worksheet_name,
                )
                ws.append_row(row_values)
                return {
                    "status": "success",
                    "values": row_values,
                }

            return await self.sync_to_async(_append)

        except Exception as e:
            logger.error(f"Append row failed → {e}")
            return {"status": "failed", "error": str(e)}

    @tool
    async def write_table(
        self,
        *,
        spreadsheet_name: str,
        worksheet_name: str,
        values: List[List],
    ):
        """
        Reads all records from a worksheet.

            Args:
                spreadsheet_name (str): Name of the spreadsheet.
                worksheet_name (str): Name of the worksheet.

            Returns:
                list: A list of dictionaries representing worksheet rows.
        """
        try:
            def _write():
                ws = self._open_worksheet(
                    spreadsheet_name=spreadsheet_name,
                    worksheet_name=worksheet_name,
                )
                ws.update(values=values, range_name="A1")
                return {
                    "status": "success",
                    "rows": len(values),
                    "cols": len(values[0]),
                }

            return await self.sync_to_async(_write)

        except Exception as e:
            logger.error(f"Write table failed → {e}")
            return {"status": "failed", "error": str(e)}

    @tool
    async def clear_worksheet(
        self,
        *,
        spreadsheet_name: str,
        worksheet_name: str,
    ):
        """
        Clears all data from a worksheet.

            Args:
                spreadsheet_name (str): Name of the spreadsheet.
                worksheet_name (str): Name of the worksheet.

            Returns:
                dict: Status of the clear operation.
        """
        try:
            def _clear():
                ws = self._open_worksheet(
                    spreadsheet_name=spreadsheet_name,
                    worksheet_name=worksheet_name,
                )
                ws.clear()
                return {"status": "success"}

            return await self.sync_to_async(_clear)

        except Exception as e:
            logger.error(f"Clear worksheet failed → {e}")
            return {"status": "failed", "error": str(e)}

    @tool
    async def delete_spreadsheet(self, spreadsheet_name: str):
        """
        Deletes an entire spreadsheet.

            Args:
                spreadsheet_name (str): Name of the spreadsheet to delete.

            Returns:
                dict: Status of the delete operation.
        """
        try:
            def _delete():
                sheet = self.client.open(spreadsheet_name)
                self.client.del_spreadsheet(sheet.id)
                return {"status": "success"}

            return await self.sync_to_async(_delete)

        except Exception as e:
            logger.error(f"Delete spreadsheet failed → {e}")
            return {"status": "failed", "error": str(e)}


def normalize_cell(value):
    """
    Normalizes values for Google Sheets cells.

    - Primitive values are returned as-is.
    - Lists and dictionaries are converted to pretty JSON strings.

    Args:
        value (Any): Input value from JSON.

    Returns:
        Any: A Sheets-compatible value.
    """
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    # list or dict → stringify
    return json.dumps(value, ensure_ascii=False)


def normalize_cell(value):
    """
    Converts a list-of-dictionaries JSON file into a 2D table suitable
    for writing to Google Sheets.

    Column order and row order are preserved exactly as in the JSON file.

    Args:
        json_path (str): Path to the JSON file.

    Returns:
        List[List]: A 2D table with headers as the first row.
    """
    if value is None:
        return ""

    if isinstance(value, (str, int, float, bool)):
        return value

    # Pretty-print JSON for readability in Sheets
    return json.dumps(
        value,
        ensure_ascii=False,
        indent=2
    )


def json_to_table(json_path: str) -> List[List]:
    data = json.loads(Path(json_path).read_text(encoding="utf-8"))

    if not isinstance(data, list) or not data:
        raise ValueError("JSON must be a non-empty list")



    headers = list(data[0].keys())

    rows = []
    for item in data:
        row = [normalize_cell(item.get(h)) for h in headers]
        rows.append(row)

    return [headers] + rows
