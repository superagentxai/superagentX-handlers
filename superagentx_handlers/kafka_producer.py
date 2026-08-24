import json
import logging
import os
import sys
from pathlib import Path
from uuid import uuid4

import pandas as pd
from confluent_kafka import Producer


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


class KafkaProducerHandler:

    def __init__(
        self,
        bootstrap_servers: str = BOOTSTRAP_SERVERS,
        topic_name: str = TOPIC_NAME,
        batch_size: int = BATCH_SIZE,
    ):
        self.topic_name = topic_name
        self.batch_size = batch_size

        self.producer = Producer({
            "bootstrap.servers": bootstrap_servers
        })

    # ---------------------------------------------------
    # Excel
    # ---------------------------------------------------

    @staticmethod
    def read_excel(file_path: str) -> list[dict]:

        path = Path(file_path)

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

        df = df.where(
            pd.notnull(df),
            None
        )

        records = df.to_dict(
            orient="records"
        )

        # Excel row 1 = header
        # actual data starts row 2
        for row_number, record in enumerate(
            records,
            start=2
        ):
            record[ROW_NUMBER_FIELD] = row_number

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
    def delivery_report(err, msg):

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

    def publish_excel(
        self,
        file_path: str
    ):

        records = self.read_excel(file_path)

        upload_id = str(uuid4())

        total_records = len(records)

        total_batches = (
            total_records + self.batch_size - 1
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

        for batch_id, batch in enumerate(
            self.batch_records(
                records,
                self.batch_size
            ),
            start=1,
        ):

            message = {

                "upload_id": upload_id,

                "batch_id": batch_id,

                "batch_size": len(batch),

                "total_batches": total_batches,

                "total_data_count": total_records,

                "source_file_path": str(
                    Path(file_path).resolve()
                ),

                "records": batch,
            }

            self.producer.produce(
                topic=self.topic_name,
                key=upload_id,
                value=json.dumps(
                    message,
                    default=str
                ).encode("utf-8"),
                callback=self.delivery_report,
            )

            self.producer.poll(0)

            logger.info(
                "Queued batch %s/%s",
                batch_id,
                total_batches,
            )

        # wait until Kafka actually receives messages
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


# ======================================================
# MAIN
# ======================================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(
            "Usage: python producer.py <excel_file_path>"
        )

        raise SystemExit(1)

    excel_path = sys.argv[1]

    handler = KafkaProducerHandler()

    upload_id = handler.publish_excel(
        excel_path
    )

    print(
        f"\nUpload published successfully."
        f"\nUpload ID: {upload_id}"
    )