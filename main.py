from parser.email_parser import parse_email
from ioc.extractor import extract_iocs
from detector import analyze_email
from reporter import generate_report
from ai_explainer import ai_explain

email_data = parse_email("sample.eml")

print("\n=== HEADERS ===\n")
for k, v in email_data["headers"].items():
    print(f"{k}: {v}")

print("\n=== BODY ===\n")
print(email_data["body"])

print("\n=== IOC EXTRACTION ===\n")
combined_text = str(email_data["headers"]) + email_data["body"]
iocs = extract_iocs(combined_text)

for key, value in iocs.items():
    print(f"{key.upper()}:")
    for item in value:
        print("  ", item)
    print()

# Prepare data for detection engine
extracted_data = {
    "headers": str(email_data["headers"]),
    "urls": iocs["urls"],
    "domains": iocs["domains"],
    "ips": iocs["ips"]
}

# Analyze and print verdict
result = analyze_email(extracted_data)

print("\n=== VERDICT ===")
print("Score:", result["score"])
print("Verdict:", result["verdict"])
print("Reasons:")
for r in result["reasons"]:
    print("-", r)

# Generate report file
report_file = generate_report(email_data, iocs, result)
print(f"\n[+] Report saved to: {report_file}\n")

# Generate AI explanation
ai_explain(extracted_data, result)