import os
import re
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# File parsing libraries
try:
    import pypdf
except ImportError:
    pypdf = None

try:
    import docx
except ImportError:
    docx = None


class DataSanitizationEngine:
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self._add_custom_recognizers()

    def _add_custom_recognizers(self):
        # 1. PAN Card Recognizer (India)
        pan_pattern = Pattern(name="pan_pattern", regex=r"[A-Z]{5}[0-9]{4}[A-Z]{1}", score=0.85)
        pan_recognizer = PatternRecognizer(supported_entity="PAN_NUMBER", patterns=[pan_pattern])
        self.analyzer.registry.add_recognizer(pan_recognizer)

        # 2. Aadhaar Card Recognizer (India)
        aadhaar_pattern = Pattern(name="aadhaar_pattern", regex=r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b", score=0.85)
        aadhaar_recognizer = PatternRecognizer(supported_entity="AADHAAR_NUMBER", patterns=[aadhaar_pattern])
        self.analyzer.registry.add_recognizer(aadhaar_recognizer)

        # 3. Medical Record Number / Patient ID (PHI)
        mrn_pattern = Pattern(name="mrn_pattern", regex=r"\b(MRN|PATIENT|MED)[-:\s]?[0-9]{6,10}\b", score=0.8)
        mrn_recognizer = PatternRecognizer(supported_entity="MEDICAL_RECORD_NUMBER", patterns=[mrn_pattern])
        self.analyzer.registry.add_recognizer(mrn_recognizer)

    def extract_text_from_file(self, file_path: str) -> str:
        """Extracts plain text from TXT, PDF, and DOCX files."""
        ext = os.path.splitext(file_path)[1].lower()

        if ext in [".txt", ".log", ".csv", ".json"]:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()

        elif ext == ".pdf":
            if not pypdf:
                raise ImportError("pypdf is required for PDF parsing. Run `pip install pypdf`.")
            reader = pypdf.PdfReader(file_path)
            return "\n".join([page.extract_text() or "" for page in reader.pages])

        elif ext in [".docx", ".doc"]:
            if not docx:
                raise ImportError("python-docx is required for DOCX parsing. Run `pip install python-docx`.")
            doc = docx.Document(file_path)
            return "\n".join([p.text for p in doc.paragraphs])

        else:
            raise ValueError(f"Unsupported file format: {ext}")

    def mask_text_stream(self, text: str) -> dict:
        if not text.strip():
            return {"masked_text": "", "findings_count": 0, "detected_types": []}

        # Analyze for standard PII, PHI, PCI + Custom entities
        results = self.analyzer.analyze(
            text=text,
            entities=[
                "PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD", "US_SSN", 
                "PASSPORT", "PAN_NUMBER", "AADHAAR_NUMBER", "MEDICAL_RECORD_NUMBER"
            ],
            language="en"
        )

        # Mask/Anonymize detected entities
        anonymized_result = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators={
                "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})
            }
        )

        detected_types = list(set([res.entity_type for res in results]))

        return {
            "masked_text": anonymized_result.text,
            "findings_count": len(results),
            "detected_types": detected_types
        }

    def sanitize_file(self, input_file_path: str, output_file_path: str) -> dict:
        """Reads document, masks content, and saves a copy without modifying original."""
        text = self.extract_text_from_file(input_file_path)
        analysis = self.mask_text_stream(text)

        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(analysis["masked_text"])

        return analysis