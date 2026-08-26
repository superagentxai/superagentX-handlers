import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional
from uuid import uuid4

import pandas as pd
from confluent_kafka import Producer
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


BOOTSTRAP_SERVERS = os.environ.get(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9092"
)

TOPIC_NAME = os.environ.get(
    "KAFKA_TOPIC_NAME",
    "policy-input"
)

BATCH_SIZE = int(
    os.environ.get("KAFKA_BATCH_SIZE", "5")
)

ROW_NUMBER_FIELD = "__source_row_number"


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

logger = logging.getLogger(__name__)


class KafkaProducerHandler(BaseHandler):
    """
    SuperAgentX handler for publishing Excel transaction data to Apache Kafka.

    The handler reads transaction records from an Excel workbook, converts
    each row into a dictionary, assigns the original Excel row number, splits
    the records into configurable batches, and publishes those batches to a
    Kafka topic.

    Each Excel upload is assigned a unique ``upload_id``. The same upload ID
    is included in every Kafka batch so downstream consumers can group all
    batches that belong to the same uploaded file.

    Every published batch contains metadata required by the Kafka consumer,
    including:

    - upload_id
    - batch_id
    - batch_size
    - total_batches
    - total_data_count
    - source_file_path
    - records

    The producer waits for Kafka delivery confirmation before returning,
    ensuring that all generated batch messages have been successfully sent.

    Attributes:
        topic_name (str):
            Kafka topic where transaction batches are published.

        batch_size (int):
            Maximum number of Excel records included in each Kafka message.

        producer (Producer):
            Configured Confluent Kafka producer instance.
    """

    def __init__(
            self,
            bootstrap_servers: Optional[str] = None,
            topic_name: Optional[str] = None,
            batch_size: Optional[int] = None,
            **kwargs
    ):
        """
        Initialize the Kafka producer handler.

        Kafka configuration can be provided directly through constructor
        arguments. If a value is not supplied, the handler falls back to the
        application-level configuration loaded from environment variables.

        Args:
            bootstrap_servers (Optional[str]):
                Kafka bootstrap server address.

                Environment variable:
                    ``KAFKA_BOOTSTRAP_SERVERS``

                Default:
                    ``localhost:9092``

            topic_name (Optional[str]):
                Kafka topic to which Excel transaction batches will be
                published.

                Environment variable:
                    ``KAFKA_TOPIC_NAME``

                Default:
                    ``policy-input``

            batch_size (Optional[int]):
                Maximum number of transaction records to include in each
                Kafka batch.

                Environment variable:
                    ``KAFKA_BATCH_SIZE``

                Default:
                    ``5``

            **kwargs:
                Additional keyword arguments forwarded to the SuperAgentX
                ``BaseHandler``.

        Raises:
            ValueError:
                May be raised by the underlying Kafka Producer configuration
                if the supplied Kafka configuration is invalid.
        """

        super().__init__(**kwargs)

        self.topic_name = (
            topic_name
            or TOPIC_NAME
        )

        self.batch_size = (
            batch_size
            or BATCH_SIZE
        )

        self.producer = Producer(
            {
                "bootstrap.servers": (
                    bootstrap_servers
                    or BOOTSTRAP_SERVERS
                )
            }
        )

    # ---------------------------------------------------
    # Excel
    # ---------------------------------------------------

    @staticmethod
    def read_excel(
        file_path: str
    ) -> list[dict]:
        """
        Read transaction records from an Excel workbook.

        The method loads the first worksheet using pandas and converts each
        data row into a dictionary.

        Missing values are converted from pandas NaN values to ``None`` so
        they can be safely serialized into Kafka JSON messages.

        An internal field named ``__source_row_number`` is added to every
        transaction record. This value represents the original row number in
        the source Excel file and allows the downstream Kafka consumer to
        write policy evaluation results back to the correct row.

        Excel row 1 is assumed to contain column headers, therefore data row
        numbering starts from Excel row 2.

        Args:
            file_path (str):
                Absolute or relative path to the Excel workbook.

        Returns:
            list[dict]:
                List of transaction dictionaries extracted from the workbook.

                Example::

                    [
                        {
                            "Transaction ID": "TXN001",
                            "Amount": 10000,
                            "__source_row_number": 2
                        },
                        {
                            "Transaction ID": "TXN002",
                            "Amount": 25000,
                            "__source_row_number": 3
                        }
                    ]

        Raises:
            FileNotFoundError:
                If the specified Excel file does not exist.

            ValueError:
                If the provided file is not an ``.xlsx`` workbook.

            Exception:
                If pandas or openpyxl cannot read the workbook.
        """

        path = Path(
            file_path
        )

        if not path.exists():

            raise FileNotFoundError(
                f"Excel file not found: {file_path}"
            )

        if path.suffix.lower() != ".xlsx":

            raise ValueError(
                "Only .xlsx files are supported."
            )

        logger.info(
            "Reading workbook: %s",
            file_path
        )

        df = pd.read_excel(
            file_path,
            engine="openpyxl"
        )

        # Convert NaN / pandas missing values to None
        df = df.where(
            pd.notnull(df),
            None
        )

        records = df.to_dict(
            orient="records"
        )

        # Excel row 1 contains headers.
        # Transaction data starts from Excel row 2.
        for row_number, record in enumerate(
            records,
            start=2
        ):
            record[
                ROW_NUMBER_FIELD
            ] = row_number

        logger.info(
            "Loaded %s records",
            len(records)
        )

        return records

    # ---------------------------------------------------
    # Batch
    # ---------------------------------------------------

    @staticmethod
    def batch_records(
        records: list[dict],
        batch_size: int,
    ):
        """
        Split transaction records into smaller Kafka batches.

        Records are yielded sequentially in groups containing at most
        ``batch_size`` items.

        The final batch may contain fewer records when the total number of
        transactions is not evenly divisible by the configured batch size.

        Args:
            records (list[dict]):
                Complete list of transaction records extracted from Excel.

            batch_size (int):
                Maximum number of transaction records per batch.

        Yields:
            list[dict]:
                One batch of transaction records.

        Example:
            If 12 transaction records are supplied with ``batch_size=5``,
            the method yields three batches containing:

            - Batch 1: 5 records
            - Batch 2: 5 records
            - Batch 3: 2 records
        """

        for index in range(
            0,
            len(records),
            batch_size
        ):

            yield records[
                index:index + batch_size
            ]

    # ---------------------------------------------------
    # Kafka delivery callback
    # ---------------------------------------------------

    @staticmethod
    def delivery_report(
        err,
        msg
    ):
        """
        Handle Kafka message delivery confirmation.

        This callback is invoked asynchronously by the Confluent Kafka
        producer after Kafka either successfully acknowledges a message or
        reports a delivery failure.

        Successful deliveries are logged with their topic, partition, and
        offset.

        Args:
            err:
                Kafka delivery error. ``None`` when delivery succeeds.

            msg:
                Confluent Kafka message object containing delivery metadata.

        Returns:
            None

        Notes:
            This callback does not raise delivery errors directly because it
            is executed by the Kafka producer event loop. The final
            ``producer.flush()`` call is used to verify that all queued
            messages were delivered.
        """

        if err is not None:

            logger.error(
                "Kafka delivery failed: %s",
                err
            )

            return

        logger.info(
            "Delivered topic=%s partition=%s offset=%s",
            msg.topic(),
            msg.partition(),
            msg.offset(),
        )

    # ---------------------------------------------------
    # Publish
    # ---------------------------------------------------

    @tool
    async def publish_excel(
        self,
        file_path: str
    ) -> str:
        """
        Read an Excel file and publish its transaction records to Kafka.

        This SuperAgentX tool converts an uploaded Excel workbook into Kafka
        batches that can be consumed by the banking policy evaluation
        consumer.

        The processing flow is:

        1. Validate the Excel file path.
        2. Read all transaction records from the workbook.
        3. Add the original Excel row number to every transaction.
        4. Generate a unique upload ID.
        5. Calculate the total number of records.
        6. Calculate the total number of Kafka batches.
        7. Split records according to the configured batch size.
        8. Create one JSON Kafka message for each batch.
        9. Include upload and batch metadata in every message.
        10. Publish each batch to the configured Kafka topic.
        11. Wait until all queued Kafka messages are delivered.
        12. Return the generated upload ID.

        Each Kafka message has the following structure::

            {
                "upload_id": "generated-uuid",
                "batch_id": 1,
                "batch_size": 5,
                "total_batches": 5,
                "total_data_count": 24,
                "source_file_path": "/absolute/path/input.xlsx",
                "records": [...]
            }

        Args:
            file_path (str):
                Path to the ``.xlsx`` file containing transaction data.

        Returns:
            str:
                Unique upload identifier generated for this Excel upload.

                The same ``upload_id`` is included in every Kafka batch
                created from the workbook.

        Raises:
            FileNotFoundError:
                If the Excel file does not exist.

            ValueError:
                If the input file is not an ``.xlsx`` file.

            RuntimeError:
                If one or more Kafka messages remain undelivered after the
                producer flush operation.

            Exception:
                If Excel parsing, JSON serialization, or Kafka publishing
                fails.

        Notes:
            ``producer.flush()`` blocks until queued messages are delivered
            or Kafka reports a delivery problem.

            The returned upload ID can be used by downstream consumers to
            identify all batches belonging to the same Excel upload.
        """

        # ---------------------------------------------------
        # Read Excel
        # ---------------------------------------------------

        records = self.read_excel(
            file_path
        )

        # ---------------------------------------------------
        # Create upload ID
        # ---------------------------------------------------

        upload_id = str(
            uuid4()
        )

        total_records = len(
            records
        )

        # Calculate required number of batches
        total_batches = (
            total_records
            + self.batch_size
            - 1
        ) // self.batch_size

        logger.info(
            "Upload ID: %s",
            upload_id
        )

        logger.info(
            "Records=%s Batches=%s BatchSize=%s",
            total_records,
            total_batches,
            self.batch_size,
        )

        # ---------------------------------------------------
        # Create and publish batches
        # ---------------------------------------------------

        for batch_id, batch in enumerate(
            self.batch_records(
                records,
                self.batch_size
            ),
            start=1,
        ):

            message = {

                "upload_id":
                    upload_id,

                "batch_id":
                    batch_id,

                "batch_size":
                    len(batch),

                "total_batches":
                    total_batches,

                "total_data_count":
                    total_records,

                "source_file_path":
                    str(
                        Path(
                            file_path
                        ).resolve()
                    ),

                "records":
                    batch,
            }

            self.producer.produce(
                topic=self.topic_name,

                # Same upload ID is used as Kafka key.
                # This helps Kafka keep messages belonging to the same
                # upload on the same partition when possible.
                key=upload_id,

                value=json.dumps(
                    message,
                    default=str
                ).encode(
                    "utf-8"
                ),

                callback=self.delivery_report,
            )

            # Trigger delivery callbacks without blocking.
            self.producer.poll(
                0
            )

            logger.info(
                "Queued batch %s/%s",
                batch_id,
                total_batches,
            )

        # ---------------------------------------------------
        # Wait until Kafka receives all messages
        # ---------------------------------------------------

        remaining = self.producer.flush()

        if remaining != 0:

            raise RuntimeError(
                f"{remaining} Kafka messages were not delivered."
            )

        logger.info(
            "Successfully published upload=%s",
            upload_id
        )

        return upload_id