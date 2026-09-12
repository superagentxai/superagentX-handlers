from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import paddle
from asgiref.sync import sync_to_async
from paddleocr import PaddleOCR

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


logger = logging.getLogger(__name__)


class PaddleOCRHandler(BaseHandler):
    """
    PaddleOCRHandler — Arabic OCR document ingestion handler.

    This handler provides asynchronous OCR extraction for Arabic
    Executive Order PDF documents used in the DCD Executive Order
    Agentic Workflow.

    The handler is responsible only for document reading and OCR
    evidence extraction. It does NOT perform document interpretation,
    translation, normalization, classification, planning, policy
    evaluation, execution, or human approval.

    Processing flow:

        PDF
          ↓
        PaddleOCR
          ↓
        Page-level OCR evidence
          ↓
        Deterministic row reconstruction
          ↓
        Structured OCR JSON
          ↓
        Normalization Agent

    PaddleOCR models:

        - PP-OCRv5_mobile_det
            Text detection model.

        - arabic_PP-OCRv5_mobile_rec
            Arabic text recognition model.

    Authoritative OCR output:

        pages[].ocr_items[]

    Each OCR item preserves:

        - OCR identifier
        - raw OCR text
        - normalized text
        - recognition confidence
        - bounding box
        - bounding-box center
        - source page

    Derived deterministic structures:

        pages[].rows
        pages[].page_text

    The derived structures are generated only from OCR geometry and
    recognized text. They do not attempt to infer semantic meaning.

    Important responsibility boundary:

        OCR Handler
            → "What text was physically found on the page?"

        Normalization Agent
            → "What does the extracted document content mean and how
               should it be represented structurally?"

        Classification Agent
            → "What type or types of orders are present?"

        Planning / Decision Agent
            → "What actions should be performed?"

    The handler processes the complete PDF in one PaddleOCR prediction
    call while preserving page-level OCR evidence in the returned JSON.
    """

    DEFAULT_DETECTION_MODEL = "PP-OCRv5_mobile_det"
    DEFAULT_RECOGNITION_MODEL = "arabic_PP-OCRv5_mobile_rec"
    DEFAULT_LANGUAGE = "ar"

    def __init__(
        self,
        model_name: str = DEFAULT_RECOGNITION_MODEL,
        lang: str = DEFAULT_LANGUAGE,
    ) -> None:
        """
        Initialize the PaddleOCR handler.

        Args:
            model_name:
                PaddleOCR text recognition model used for Arabic
                text recognition.

                Defaults to:
                    arabic_PP-OCRv5_mobile_rec

            lang:
                PaddleOCR language configuration.

                Defaults to:
                    ar

        Behavior:
            - Detects whether Paddle is CUDA-enabled.
            - Uses GPU when a CUDA-capable GPU is available.
            - Falls back to CPU otherwise.
            - Does not initialize PaddleOCR immediately.
            - PaddleOCR is initialized lazily when OCR extraction
              is first requested.

        Returns:
            None
        """

        super().__init__()

        self.model_name = model_name
        self.lang = lang
        self.device = self._detect_device()

        # Lazy PaddleOCR initialization.
        self.ocr: Optional[PaddleOCR] = None

    # ------------------------------------------------------------------
    # Device
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_device() -> str:
        """
        Detect the best available Paddle execution device.

        The handler prefers GPU execution when Paddle is compiled
        with CUDA support and at least one CUDA device is available.

        Returns:
            str:
                "gpu:0" when a CUDA GPU is available.
                "cpu" otherwise.

        Behavior:
            GPU detection failures do not stop OCR initialization.
            The handler falls back to CPU execution.
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
            "Paddle GPU unavailable. Using CPU.",
        )

        return "cpu"

    # ------------------------------------------------------------------
    # OCR initialization
    # ------------------------------------------------------------------

    def _get_ocr(self) -> PaddleOCR:
        """
        Lazily initialize and return the PaddleOCR instance.

        PaddleOCR initialization is intentionally delayed until the
        handler actually needs to process a document. This avoids
        loading OCR models during application startup when the handler
        is instantiated but never used.

        OCR configuration:

            Text detection:
                PP-OCRv5_mobile_det

            Text recognition:
                Configured Arabic recognition model.

            Language:
                Configured language, default "ar".

            Device:
                Automatically detected GPU or CPU.

        Disabled capabilities:

            - document orientation classification
            - document unwarping
            - text-line orientation

        These capabilities are intentionally disabled because this
        handler belongs to the Read/Ingestion OCR layer and should
        remain focused on text detection and recognition.

        Returns:
            PaddleOCR:
                Initialized PaddleOCR instance.
        """

        if self.ocr is not None:
            return self.ocr

        logger.info(
            "Initializing PaddleOCR: "
            "detection=%s recognition=%s language=%s device=%s",
            self.DEFAULT_DETECTION_MODEL,
            self.model_name,
            self.lang,
            self.device,
        )

        self.ocr = PaddleOCR(
            text_detection_model_name=self.DEFAULT_DETECTION_MODEL,
            text_recognition_model_name=self.model_name,
            lang=self.lang,
            device=self.device,

            # CPU-friendly configuration.
            enable_mkldnn=False,

            # Read/OCR layer only.
            use_doc_orientation_classify=False,
            use_doc_unwarping=False,
            use_textline_orientation=False,
        )

        logger.info(
            "PaddleOCR initialized successfully.",
        )

        return self.ocr

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_list(
        value: Any,
    ) -> List[Any]:
        """
        Safely convert a PaddleOCR result value into a Python list.

        PaddleOCR result fields may differ slightly between versions
        or result representations. This helper normalizes common
        list-like values without allowing malformed values to stop
        document processing.

        Args:
            value:
                Value returned from PaddleOCR.

        Returns:
            list:
                A Python list when conversion is possible.
                An empty list when the value is None or cannot be
                converted.
        """

        if value is None:
            return []

        if isinstance(value, list):
            return value

        if isinstance(value, tuple):
            return list(value)

        try:
            return list(value)
        except Exception:
            return []

    @staticmethod
    def _normalize_result_json(
        result: Any,
    ) -> Dict[str, Any]:
        """
        Normalize PaddleOCR result representations into a dictionary.

        PaddleOCR versions may expose result JSON through different
        representations. This helper attempts to access the result's
        JSON representation and normalize common wrapper structures.

        Args:
            result:
                Raw PaddleOCR result object.

        Returns:
            dict:
                Normalized PaddleOCR result dictionary.

                Returns an empty dictionary when the result cannot
                be interpreted safely.
        """

        try:
            data = getattr(
                result,
                "json",
                None,
            )

            if callable(data):
                data = data()

        except Exception as exc:
            logger.warning(
                "Unable to read PaddleOCR result JSON: %s",
                exc,
            )

            return {}

        if isinstance(data, str):
            try:
                data = json.loads(data)

            except json.JSONDecodeError:
                logger.warning(
                    "PaddleOCR result JSON could not be parsed.",
                )

                return {}

        if not isinstance(data, dict):
            return {}

        # Some PaddleOCR versions wrap the result in "res".
        if isinstance(data.get("res"), dict):
            return data["res"]

        return data

    # ------------------------------------------------------------------
    # Text
    # ------------------------------------------------------------------

    @staticmethod
    def _clean_text(
        text: Any,
    ) -> str:
        """
        Perform deterministic cleanup of OCR text.

        Cleanup is intentionally limited to formatting-level
        normalization.

        Performed operations:

            - Convert the value to string.
            - Remove Unicode directional control characters.
            - Collapse repeated whitespace.
            - Strip leading and trailing whitespace.

        Not performed:

            - Translation
            - Summarization
            - Entity extraction
            - Semantic correction
            - Classification
            - Name correction
            - Department inference
            - Date interpretation

        The purpose is to preserve the OCR evidence while making it
        easier for the downstream Normalization Agent to consume.

        Args:
            text:
                Raw OCR text.

        Returns:
            str:
                Deterministically cleaned text.
        """

        text = str(text or "")

        directional_marks = (
            "\u200e",
            "\u200f",
            "\u202a",
            "\u202b",
            "\u202c",
            "\u202d",
            "\u202e",
            "\u2066",
            "\u2067",
            "\u2068",
            "\u2069",
        )

        for mark in directional_marks:
            text = text.replace(
                mark,
                "",
            )

        text = re.sub(
            r"\s+",
            " ",
            text,
        )

        return text.strip()

    # ------------------------------------------------------------------
    # Geometry
    # ------------------------------------------------------------------

    @staticmethod
    def _bbox_from_polygon(
        polygon: Any,
    ) -> List[int]:
        """
        Convert a PaddleOCR polygon into a bounding box.

        The resulting bounding box uses the format:

            [x_min, y_min, x_max, y_max]

        Args:
            polygon:
                PaddleOCR polygon containing coordinate pairs.

        Returns:
            list[int]:
                Bounding box in [x_min, y_min, x_max, y_max] format.

                Returns [0, 0, 0, 0] when no valid points are available.
        """

        points: List[Tuple[float, float]] = []

        for point in polygon or []:
            if (
                isinstance(
                    point,
                    (list, tuple),
                )
                and len(point) >= 2
            ):
                try:
                    points.append(
                        (
                            float(point[0]),
                            float(point[1]),
                        )
                    )

                except (
                    TypeError,
                    ValueError,
                ):
                    continue

        if not points:
            return [0, 0, 0, 0]

        xs = [
            point[0]
            for point in points
        ]

        ys = [
            point[1]
            for point in points
        ]

        return [
            int(round(min(xs))),
            int(round(min(ys))),
            int(round(max(xs))),
            int(round(max(ys))),
        ]

    @staticmethod
    def _center(
        bbox: List[int],
    ) -> Tuple[float, float]:
        """
        Calculate the center point of a bounding box.

        Args:
            bbox:
                Bounding box in [x_min, y_min, x_max, y_max] format.

        Returns:
            tuple[float, float]:
                Center coordinates as (center_x, center_y).
        """

        return (
            (bbox[0] + bbox[2]) / 2.0,
            (bbox[1] + bbox[3]) / 2.0,
        )

    @staticmethod
    def _height(
        bbox: List[int],
    ) -> float:
        """
        Calculate the height of a bounding box.

        Args:
            bbox:
                Bounding box in [x_min, y_min, x_max, y_max] format.

        Returns:
            float:
                Bounding-box height.

                A minimum value of 1.0 is returned to prevent
                zero-height values from affecting row clustering.
        """

        return max(
            1.0,
            float(
                bbox[3] - bbox[1]
            ),
        )

    # ------------------------------------------------------------------
    # PaddleOCR arrays
    # ------------------------------------------------------------------

    @classmethod
    def _get_texts(
        cls,
        data: Dict[str, Any],
    ) -> List[Any]:
        """
        Extract recognized text values from PaddleOCR output.

        Args:
            data:
                Normalized PaddleOCR result dictionary.

        Returns:
            list:
                Recognized OCR text values.
        """

        return cls._safe_list(
            data.get(
                "rec_texts",
                [],
            )
        )

    @classmethod
    def _get_scores(
        cls,
        data: Dict[str, Any],
    ) -> List[Any]:
        """
        Extract recognition confidence scores from PaddleOCR output.

        Args:
            data:
                Normalized PaddleOCR result dictionary.

        Returns:
            list:
                OCR recognition confidence values.
        """

        return cls._safe_list(
            data.get(
                "rec_scores",
                [],
            )
        )

    @classmethod
    def _get_polygons(
        cls,
        data: Dict[str, Any],
    ) -> List[Any]:
        """
        Extract OCR text polygons from PaddleOCR output.

        PaddleOCR normally exposes recognized text polygons through
        the `rec_polys` field.

        The `dt_polys` field is retained as a compatibility fallback
        for PaddleOCR result representations that expose detection
        polygons under that name.

        Args:
            data:
                Normalized PaddleOCR result dictionary.

        Returns:
            list:
                OCR polygons.
        """

        polygons = data.get(
            "rec_polys",
            [],
        )

        if not polygons:
            polygons = data.get(
                "dt_polys",
                [],
            )

        return cls._safe_list(
            polygons
        )

    # ------------------------------------------------------------------
    # Page normalization
    # ------------------------------------------------------------------

    def _normalize_page(
        self,
        result: Any,
        page_index: int,
    ) -> Dict[str, Any]:
        """
        Convert a raw PaddleOCR page result into stable OCR evidence.

        Each recognized text element is represented as an OCR item
        containing both raw and deterministically normalized text,
        recognition confidence, and spatial information.

        OCR item format:

            {
                "id": "p1_ocr_1",
                "text": "...",
                "normalized_text": "...",
                "confidence": 0.98,
                "bbox": [x1, y1, x2, y2],
                "center": [x, y],
                "page": 1
            }

        Args:
            result:
                Raw PaddleOCR result for one page.

            page_index:
                Zero-based page index.

        Returns:
            dict:
                Normalized page OCR structure containing:

                    - page
                    - width
                    - height
                    - ocr_items
        """

        data = self._normalize_result_json(
            result
        )

        texts = self._get_texts(
            data
        )

        scores = self._get_scores(
            data
        )

        polygons = self._get_polygons(
            data
        )

        items: List[
            Dict[str, Any]
        ] = []

        for index, raw_text in enumerate(
            texts
        ):
            raw_text = str(
                raw_text or ""
            )

            normalized_text = (
                self._clean_text(
                    raw_text
                )
            )

            if not normalized_text:
                continue

            polygon = (
                polygons[index]
                if index < len(polygons)
                else []
            )

            bbox = (
                self._bbox_from_polygon(
                    polygon
                )
            )

            confidence: Optional[
                float
            ] = None

            if index < len(scores):
                try:
                    confidence = float(
                        scores[index]
                    )

                except (
                    TypeError,
                    ValueError,
                ):
                    confidence = None

            center_x, center_y = (
                self._center(
                    bbox
                )
            )

            ocr_id = (
                f"p{page_index + 1}"
                f"_ocr_{len(items) + 1}"
            )

            items.append(
                {
                    "id": ocr_id,
                    "text": raw_text,
                    "normalized_text": (
                        normalized_text
                    ),
                    "confidence": confidence,
                    "bbox": bbox,
                    "center": [
                        round(
                            center_x,
                            2,
                        ),
                        round(
                            center_y,
                            2,
                        ),
                    ],
                    "page": (
                        page_index + 1
                    ),
                }
            )

        page_width = data.get(
            "width"
        )

        page_height = data.get(
            "height"
        )

        if not page_width:
            page_width = max(
                (
                    item["bbox"][2]
                    for item in items
                ),
                default=0,
            )

        if not page_height:
            page_height = max(
                (
                    item["bbox"][3]
                    for item in items
                ),
                default=0,
            )

        try:
            page_width = int(
                page_width or 0
            )

        except (
            TypeError,
            ValueError,
        ):
            page_width = 0

        try:
            page_height = int(
                page_height or 0
            )

        except (
            TypeError,
            ValueError,
        ):
            page_height = 0

        return {
            "page": page_index + 1,
            "width": page_width,
            "height": page_height,
            "ocr_items": items,
        }

    # ------------------------------------------------------------------
    # Row reconstruction
    # ------------------------------------------------------------------

    @classmethod
    def _cluster_rows(
        cls,
        items: List[Dict[str, Any]],
        tolerance: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """
        Group OCR items into visual rows using bounding-box geometry.

        Row clustering is purely geometric.

        It does NOT:

            - identify tables
            - identify people
            - identify departments
            - infer relationships
            - classify orders
            - determine document structure
            - translate text

        For Arabic documents, items inside each row are ordered
        from right to left.

        Rows themselves are ordered from top to bottom.

        Args:
            items:
                Normalized OCR items.

            tolerance:
                Optional vertical distance tolerance used when grouping
                OCR items into rows.

                When omitted, the tolerance is calculated dynamically
                from the median OCR text height.

        Returns:
            list[dict]:
                Deterministically clustered visual rows.
        """

        if not items:
            return []

        heights = sorted(
            cls._height(
                item["bbox"]
            )
            for item in items
        )

        median_height = (
            heights[
                len(heights) // 2
            ]
            if heights
            else 15.0
        )

        tolerance_value = (
            tolerance
            if tolerance is not None
            else max(
                12.0,
                median_height * 0.65,
            )
        )

        ordered = sorted(
            items,
            key=lambda item: cls._center(
                item["bbox"]
            )[1],
        )

        rows: List[
            Dict[str, Any]
        ] = []

        for item in ordered:
            _, center_y = cls._center(
                item["bbox"]
            )

            best_row: Optional[
                Dict[str, Any]
            ] = None

            best_distance = float(
                "inf"
            )

            for row in rows:
                distance = abs(
                    center_y
                    - row["center_y"]
                )

                if (
                    distance
                    <= tolerance_value
                    and distance
                    < best_distance
                ):
                    best_row = row
                    best_distance = (
                        distance
                    )

            if best_row is None:
                rows.append(
                    {
                        "center_y": center_y,
                        "items": [item],
                    }
                )

                continue

            best_row[
                "items"
            ].append(item)

            best_row[
                "center_y"
            ] = (
                sum(
                    cls._center(
                        current["bbox"]
                    )[1]
                    for current
                    in best_row["items"]
                )
                / len(
                    best_row["items"]
                )
            )

        rows.sort(
            key=lambda row: row[
                "center_y"
            ]
        )

        for row_index, row in enumerate(
            rows,
            start=1,
        ):
            row["row_id"] = (
                row_index
            )

            # Arabic document reading order:
            # right -> left.
            row["items"] = sorted(
                row["items"],
                key=lambda item: cls._center(
                    item["bbox"]
                )[0],
                reverse=True,
            )

        return rows

    # ------------------------------------------------------------------
    # Derived row JSON
    # ------------------------------------------------------------------

    @classmethod
    def _build_rows(
        cls,
        items: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Build a deterministic row representation from OCR items.

        This structure is derived from OCR geometry and is intended
        to help downstream agents understand the visual reading order.

        Args:
            items:
                Normalized OCR items.

        Returns:
            list[dict]:
                Row-level representation containing row identifiers,
                vertical position, and OCR item references.
        """

        rows = cls._cluster_rows(
            items
        )

        return [
            {
                "row_id": row[
                    "row_id"
                ],
                "center_y": round(
                    row[
                        "center_y"
                    ],
                    2,
                ),
                "items": [
                    {
                        "ocr_id": item[
                            "id"
                        ],
                        "text": item[
                            "text"
                        ],
                        "normalized_text": (
                            item[
                                "normalized_text"
                            ]
                        ),
                        "confidence": item[
                            "confidence"
                        ],
                        "bbox": item[
                            "bbox"
                        ],
                    }
                    for item in row[
                        "items"
                    ]
                ],
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Derived page text
    # ------------------------------------------------------------------

    @classmethod
    def _build_page_text(
        cls,
        items: List[Dict[str, Any]],
    ) -> str:
        """
        Build human-readable page text from OCR items.

        Reading order:

            1. Top to bottom.
            2. Right to left within each visual row.

        This is a derived convenience representation only.

        The authoritative evidence remains:

            pages[].ocr_items[]

        Args:
            items:
                Normalized OCR items.

        Returns:
            str:
                Page text reconstructed from the OCR rows.
        """

        rows = cls._cluster_rows(
            items
        )

        lines: List[str] = []

        for row in rows:
            row_text = " ".join(
                item[
                    "normalized_text"
                ]
                for item in row[
                    "items"
                ]
                if item[
                    "normalized_text"
                ]
            )

            if row_text:
                lines.append(
                    row_text
                )

        return "\n".join(
            lines
        )

    # ------------------------------------------------------------------
    # Document processing
    # ------------------------------------------------------------------

    def _process_document(
        self,
        file_path: str,
    ) -> Dict[str, Any]:
        """
        Process a complete PDF document using PaddleOCR.

        The PDF is submitted to PaddleOCR as a complete document in
        one prediction call. PaddleOCR internally processes the
        document page by page, while this handler preserves the
        resulting evidence as page-level structures.

        Processing flow:

            PDF
              ↓
            PaddleOCR prediction
              ↓
            Page normalization
              ↓
            Row reconstruction
              ↓
            Page text reconstruction
              ↓
            Structured OCR JSON

        Args:
            file_path:
                Local or on-prem path to the PDF document.

        Returns:
            dict:
                Success response:

                {
                    "status": "success",
                    "document": {...},
                    "pages": [...],
                    "statistics": {...}
                }

                Error response:

                {
                    "status": "error",
                    "file": "...",
                    "error": "...",
                    ...
                }

        Important:
            This method performs OCR ingestion only. It does not
            interpret the meaning of the document.
        """

        started = time.time()

        if not file_path:
            return {
                "status": "error",
                "error": (
                    "file_path is required."
                ),
            }

        if not os.path.isfile(
            file_path
        ):
            return {
                "status": "error",
                "file": file_path,
                "error": (
                    f"File does not exist: "
                    f"{file_path}"
                ),
            }

        logger.info(
            "Starting PaddleOCR extraction: %s",
            file_path,
        )

        try:
            ocr = self._get_ocr()

            # Submit the complete document.
            # PaddleOCR internally processes individual pages.
            raw_results = ocr.predict(
                file_path
            )

            pages: List[
                Dict[str, Any]
            ] = []

            for page_index, raw_result in enumerate(
                raw_results
            ):
                page = self._normalize_page(
                    raw_result,
                    page_index,
                )

                page["rows"] = (
                    self._build_rows(
                        page[
                            "ocr_items"
                        ]
                    )
                )

                page["page_text"] = (
                    self._build_page_text(
                        page[
                            "ocr_items"
                        ]
                    )
                )

                pages.append(
                    page
                )

            total_items = sum(
                len(
                    page[
                        "ocr_items"
                    ]
                )
                for page in pages
            )

            processing_time = (
                time.time()
                - started
            )

            result = {
                "status": "success",

                "document": {
                    "source_file": (
                        os.path.basename(
                            file_path
                        )
                    ),
                    "source_path": file_path,
                    "page_count": len(
                        pages
                    ),

                    "ocr_models": {
                        "text_detection": (
                            self.DEFAULT_DETECTION_MODEL
                        ),
                        "text_recognition": (
                            self.model_name
                        ),
                    },

                    "language": self.lang,
                    "device": self.device,

                    "processing_time_seconds": (
                        round(
                            processing_time,
                            3,
                        )
                    ),
                },

                "pages": pages,

                "statistics": {
                    "ocr_item_count": (
                        total_items
                    ),

                    "pages_with_text": sum(
                        1
                        for page in pages
                        if page[
                            "ocr_items"
                        ]
                    ),
                },
            }

            logger.info(
                "PaddleOCR extraction completed: "
                "pages=%s items=%s time=%.2fs",
                len(pages),
                total_items,
                processing_time,
            )

            return result

        except Exception as exc:
            logger.exception(
                "PaddleOCR document extraction failed.",
            )

            return {
                "status": "error",
                "file": file_path,
                "model": self.model_name,
                "language": self.lang,
                "device": self.device,
                "error": str(exc),
                "processing_time_seconds": (
                    round(
                        time.time()
                        - started,
                        3,
                    )
                ),
            }

    # ------------------------------------------------------------------
    # SuperAgentX tool
    # ------------------------------------------------------------------

    @tool
    async def extract_pdf(
        self,
        pdf_path: str,
        model_name: str = DEFAULT_RECOGNITION_MODEL,
    ) -> dict:
        """
        Extract OCR evidence from an Arabic Executive Order PDF.

        This is the public SuperAgentX tool exposed to the agent
        runtime.

        The tool executes synchronous PaddleOCR processing in a worker
        thread so that the asynchronous SuperAgentX event loop is not
        blocked during OCR inference.

        Args:
            pdf_path:
                Local/on-prem path to the Executive Order PDF.

            model_name:
                Arabic PaddleOCR recognition model.

                Defaults to:
                    arabic_PP-OCRv5_mobile_rec

        Returns:
            dict:
                Structured OCR JSON containing:

                    - document metadata
                    - page-level OCR evidence
                    - OCR confidence scores
                    - bounding boxes
                    - visual rows
                    - reconstructed page text
                    - processing statistics

        Output purpose:

            The returned structure is intended to be passed to the
            downstream Normalization Agent.

        Responsibility boundary:

            This method does NOT:

                - translate Arabic to English
                - normalize business entities
                - identify order types
                - classify transfers
                - classify committee formation
                - infer organizational relationships
                - create execution plans
                - apply governance policies
                - request HITL approval
                - execute business actions
        """

        try:
            # Allow runtime recognition model override.
            if (
                model_name
                and model_name
                != self.model_name
            ):
                logger.info(
                    "Changing OCR recognition model: "
                    "%s -> %s",
                    self.model_name,
                    model_name,
                )

                self.model_name = (
                    model_name
                )

                # Reinitialize OCR with the new model
                # on the next request.
                self.ocr = None

            # PaddleOCR is synchronous.
            # Run it outside the async event loop.
            result = await sync_to_async(
                self._process_document,
                thread_sensitive=True,
            )(
                pdf_path
            )

            return result

        except Exception as exc:
            logger.exception(
                "PaddleOCR PDF extraction failed.",
            )

            return {
                "status": "error",
                "file": pdf_path,
                "model": self.model_name,
                "language": self.lang,
                "device": self.device,
                "error": str(exc),
            }


