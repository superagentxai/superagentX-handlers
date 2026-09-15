import os

os.environ.setdefault("FLAGS_enable_pir_api", "0")
os.environ.setdefault("FLAGS_use_mkldnn", "0")
os.environ.setdefault("FLAGS_use_onednn", "0")

# Avoid model source connectivity checks.
os.environ.setdefault(
    "PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK",
    "True",
)

import asyncio
import json
import logging
import re
from datetime import datetime
from typing import Any

import paddle
from paddleocr import PaddleOCR

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

from asgiref.sync import sync_to_async

logger = logging.getLogger(__name__)

class PaddleOCRHandler(BaseHandler):
    """
    Lightweight PaddleOCR PDF handler.

    Designed for CPU systems with limited RAM.

    Pipeline:

        PDF
         ↓
        PP-OCRv5 mobile detector
         ↓
        Arabic PP-OCRv5 mobile recognizer
         ↓
        bounding boxes
         ↓
        line grouping
         ↓
        ONE combined content

    No PPStructureV3 is used.

    No separate:
        text
        tables
        markdown
        pages

    are returned.

    Final document data is returned in:

        content
    """

    def __init__(
        self,
        model_name: str = "arabic_PP-OCRv5_mobile_rec",
        lang: str = "ar",
    ):
        super().__init__()

        self.model_name = model_name
        self.lang = lang

        self.device = self._detect_device()

        # Lazy initialization.
        self.ocr = None

    # ========================================================
    # Device detection
    # ========================================================

    @staticmethod
    def _detect_device() -> str:
        """
        Automatically select GPU if available.

        Docker decides whether a GPU is exposed.

        Returns:

            gpu:0
            or
            cpu
        """

        try:
            if paddle.is_compiled_with_cuda():

                gpu_count = paddle.device.cuda.device_count()

                if gpu_count > 0:

                    logger.info(
                        "Paddle GPU detected: %s GPU(s)",
                        gpu_count,
                    )

                    return "gpu:0"

        except Exception as exc:

            logger.warning(
                "GPU detection failed: %s",
                exc,
            )

        logger.info(
            "Paddle GPU unavailable. "
            "Using CPU."
        )

        return "cpu"

    # ========================================================
    # OCR initialization
    # ========================================================

    def _get_ocr(self):
        """
        Initialize lightweight PaddleOCR.

        IMPORTANT:

        This intentionally uses PaddleOCR instead of
        PPStructureV3 to avoid loading heavy table/formula
        models and causing OOM on CPU.
        """

        if self.ocr is not None:
            return self.ocr

        logger.info(
            "Initializing lightweight PaddleOCR "
            "model=%s lang=%s device=%s",
            self.model_name,
            self.lang,
            self.device,
        )

        self.ocr = PaddleOCR(

            text_recognition_model_name=self.model_name,

            text_detection_model_name="PP-OCRv5_mobile_det",

            lang=self.lang,

            device=self.device,

            enable_mkldnn=False,

            use_doc_orientation_classify=False,
            use_doc_unwarping=False,
            use_textline_orientation=False,
        )

        logger.info(
            "Lightweight PaddleOCR initialized successfully"
        )

        return self.ocr

    # ========================================================
    # JSON normalization
    # ========================================================

    @staticmethod
    def _normalize_result_json(
        result: Any,
    ) -> dict:
        """
        Normalize PaddleOCR result into a dictionary.

        PaddleOCR versions may expose:

            result.json

        as either:

            dict
            string
        """

        try:
            data = result.json

        except Exception:
            return {}

        if isinstance(data, str):

            try:
                data = json.loads(data)

            except Exception:
                return {}

        if not isinstance(data, dict):
            return {}

        # Some versions wrap actual OCR data inside `res`.
        if isinstance(data.get("res"), dict):

            return data["res"]

        return data

    # ========================================================
    # Generic list normalization
    # ========================================================

    @staticmethod
    def _safe_list(
        value: Any,
    ) -> list:
        """
        Convert possible Paddle result values into a list.
        """

        if value is None:
            return []

        if isinstance(value, list):
            return value

        try:
            return list(value)

        except Exception:
            return []

    # ========================================================
    # Get OCR texts
    # ========================================================

    @staticmethod
    def _get_rec_texts(
        data: dict,
    ) -> list:
        """
        Extract recognized text values.
        """

        texts = data.get(
            "rec_texts",
            [],
        )

        return [
            str(text).strip()
            for text in PaddleOCRHandler._safe_list(texts)
            if text is not None
            and str(text).strip()
        ]

    # ========================================================
    # Get OCR scores
    # ========================================================

    @staticmethod
    def _get_rec_scores(
        data: dict,
    ) -> list:
        """
        Extract recognition confidence scores.
        """

        scores = data.get(
            "rec_scores",
            [],
        )

        return PaddleOCRHandler._safe_list(
            scores
        )

    # ========================================================
    # Get OCR polygons
    # ========================================================

    @staticmethod
    def _get_rec_polys(
        data: dict,
    ) -> list:
        """
        Extract recognition polygons.

        PaddleOCR commonly returns:

            rec_polys

        Each polygon contains four points.
        """

        polys = data.get(
            "rec_polys",
            [],
        )

        if not polys:

            # Some versions may use dt_polys.
            polys = data.get(
                "dt_polys",
                [],
            )

        return PaddleOCRHandler._safe_list(
            polys
        )

    # ========================================================
    # Polygon center
    # ========================================================

    @staticmethod
    def _polygon_center(
        polygon: Any,
    ) -> tuple[float, float]:
        """
        Calculate center X/Y from OCR polygon.
        """

        try:

            points = []

            for point in polygon:

                if (
                    isinstance(point, (list, tuple))
                    and len(point) >= 2
                ):
                    points.append(
                        (
                            float(point[0]),
                            float(point[1]),
                        )
                    )

            if not points:
                return 0.0, 0.0

            x = sum(
                point[0]
                for point in points
            ) / len(points)

            y = sum(
                point[1]
                for point in points
            ) / len(points)

            return x, y

        except Exception:
            return 0.0, 0.0

    # ========================================================
    # Polygon height
    # ========================================================

    @staticmethod
    def _polygon_height(
        polygon: Any,
    ) -> float:
        """
        Calculate approximate OCR box height.
        """

        try:

            ys = [
                float(point[1])
                for point in polygon
                if isinstance(point, (list, tuple))
                and len(point) >= 2
            ]

            if not ys:
                return 0.0

            return max(ys) - min(ys)

        except Exception:
            return 0.0

    # ========================================================
    # Group OCR boxes into lines
    # ========================================================

    @staticmethod
    def _group_into_lines(
        items: list[dict],
    ) -> list[list[dict]]:
        """
        Group OCR boxes based on their Y position.

        This is what allows table rows to remain together
        without using the heavy PPStructureV3 table models.
        """

        if not items:
            return []

        # ----------------------------------------------------
        # Sort from top to bottom.
        # ----------------------------------------------------

        items = sorted(
            items,
            key=lambda item: item["cy"],
        )

        lines: list[list[dict]] = []

        for item in items:

            current_line = None

            item_height = item.get(
                "height",
                0.0,
            )

            # Dynamic tolerance based on OCR box height.
            tolerance = max(
                8.0,
                item_height * 0.60,
            )

            for line in lines:

                average_y = sum(
                    x["cy"]
                    for x in line
                ) / len(line)

                if abs(
                    item["cy"] - average_y
                ) <= tolerance:

                    current_line = line
                    break

            if current_line is None:

                lines.append(
                    [item]
                )

            else:

                current_line.append(
                    item
                )

        # ----------------------------------------------------
        # Sort each line horizontally.
        #
        # Arabic documents are generally RTL, so we keep
        # right-to-left OCR order.
        # ----------------------------------------------------

        for line in lines:

            line.sort(
                key=lambda item: item["cx"],
                reverse=True,
            )

        return lines

    # ========================================================
    # Clean OCR text
    # ========================================================

    @staticmethod
    def _clean_text(
        text: str,
    ) -> str:
        """
        Basic OCR output cleanup.

        Does NOT attempt to correct Arabic words.
        """

        if not text:
            return ""

        text = text.replace(
            "\u200f",
            "",
        )

        text = text.replace(
            "\u200e",
            "",
        )

        text = re.sub(
            r"[ \t]+",
            " ",
            text,
        )

        return text.strip()

    # ========================================================
    # Build one line
    # ========================================================

    @staticmethod
    def _build_line(
        line: list[dict],
    ) -> str:
        """
        Convert one OCR line into one content line.

        Table cells are separated using ` | `.

        Example:

            1 | 3787 | مدني/ خلود الشحي
        """

        parts = []

        for item in line:

            text = PaddleOCRHandler._clean_text(
                item.get("text", "")
            )

            if not text:
                continue

            parts.append(text)

        return " | ".join(parts)

    # ========================================================
    # Build combined content from one result
    # ========================================================

    @classmethod
    def _build_content_from_result(
        cls,
        result: Any,
    ) -> str:
        """
        Build one combined content string from a single
        PaddleOCR result/page.
        """

        data = cls._normalize_result_json(
            result
        )

        if not data:
            return ""

        texts = cls._safe_list(
            data.get(
                "rec_texts",
                [],
            )
        )

        scores = cls._safe_list(
            data.get(
                "rec_scores",
                [],
            )
        )

        polys = cls._get_rec_polys(
            data
        )

        if not texts:
            return ""

        items = []

        # ----------------------------------------------------
        # Build OCR items.
        # ----------------------------------------------------

        for index, text in enumerate(texts):

            text = cls._clean_text(
                str(text)
            )

            if not text:
                continue

            # -----------------------------------------------
            # Confidence
            # -----------------------------------------------

            score = None

            if index < len(scores):

                try:
                    score = float(
                        scores[index]
                    )

                except Exception:
                    score = None

            # -----------------------------------------------
            # Polygon
            # -----------------------------------------------

            polygon = None

            if index < len(polys):
                polygon = polys[index]

            # -----------------------------------------------
            # Position
            # -----------------------------------------------

            if polygon:

                cx, cy = cls._polygon_center(
                    polygon
                )

                height = cls._polygon_height(
                    polygon
                )

            else:

                # If no polygon is available,
                # preserve OCR sequence.
                cx = float(index)
                cy = float(index)

                height = 15.0

            items.append(
                {
                    "text": text,
                    "score": score,
                    "polygon": polygon,
                    "cx": cx,
                    "cy": cy,
                    "height": height,
                    "index": index,
                }
            )

        if not items:
            return ""

        if not polys:

            return "\n".join(
                item["text"]
                for item in items
            )

        lines = cls._group_into_lines(
            items
        )

        content_lines = []

        for line in lines:

            line_text = cls._build_line(
                line
            )

            if line_text:
                content_lines.append(
                    line_text
                )

        return "\n".join(
            content_lines
        ).strip()

    def _process_pdf(
        self,
        pdf_path: str,
    ) -> dict:
        """
        Run lightweight PaddleOCR on the PDF.

        IMPORTANT:

        `ocr.predict()` is called exactly once.

        All pages are combined into ONE content field.
        """

        start_time = datetime.now()

        logger.info(
            "Starting lightweight PaddleOCR PDF extraction: %s",
            pdf_path,
        )

        ocr = self._get_ocr()

        results = ocr.predict(
            pdf_path
        )

        content_parts = []

        page_count = 0

        for result in results:

            page_count += 1

            content = self._build_content_from_result(
                result
            )

            if content:

                content_parts.append(
                    content
                )

        final_content = "\n\n".join(
            part.strip()
            for part in content_parts
            if part
            and part.strip()
        ).strip()

        end_time = datetime.now()

        processing_time = (
            end_time - start_time
        ).total_seconds()

        logger.info(
            "PaddleOCR PDF extraction completed: "
            "pages=%s time=%.2fs",
            page_count,
            processing_time,
        )


        return {
            "status": "success",
            "file": pdf_path,
            "model": self.model_name,
            "language": self.lang,
            "device": self.device,
            "content": final_content,
            "processing_time_seconds": processing_time,
        }

    @tool
    async def extract_pdf(
        self,
        pdf_path: str,
        model_name: str = "arabic_PP-OCRv5_mobile_rec",
    ) -> dict:
        """
        Extract PDF using lightweight PaddleOCR.

        Text and table-like OCR content are returned as
        one combined `content` field.
        """

        try:

            if (
                model_name
                and model_name != self.model_name
            ):

                logger.info(
                    "Changing OCR recognition model "
                    "from %s to %s",
                    self.model_name,
                    model_name,
                )

                self.model_name = model_name

                self.ocr = None

            result = await sync_to_async(
                self._process_pdf,
                thread_sensitive=True,
            )(pdf_path)

            return result

        except Exception as exc:

            logger.exception(
                "PaddleOCR PDF extraction failed: %s",
                exc,
            )

            return {
                "status": "error",
                "file": pdf_path,
                "model": self.model_name,
                "language": self.lang,
                "device": self.device,
                "error": str(exc),
            }