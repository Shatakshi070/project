from engine import DataSanitizationEngine
engine = DataSanitizationEngine()
sample_text = "+91 89876-94937 or PAN ABCDE1234F"
# sample_text = "My name is Shatakshi and my Aadhaar number is 2764 2738 9303"
result = engine.mask_text_stream(sample_text)

print(" RESULT OF THE INPUTS ARE :-- ")
print("Findings:",result["findings_count"])
print("Detected Types:",result["detected_types"])
print("Masked Output:",result["masked_text"])