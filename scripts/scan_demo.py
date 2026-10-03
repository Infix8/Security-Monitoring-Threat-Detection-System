"""Scan localhost on a small port set, save it, print result + DB row."""
import sys
sys.path.insert(0, ".")

from app.scanner.portscan import scan_target, is_allowed, ScanNotAllowed
from app.scanner.store import save_scan

TARGET = "127.0.0.1"
PORTS = [22, 80, 443, 5432, 8000, 9999, 12345]

print(f"is_allowed({TARGET}) = {is_allowed(TARGET)}")

result = scan_target(TARGET, PORTS, banners=True)
print("scan result:")
for k, v in result.items():
    print(f"  {k:<15} {v}")

sid = save_scan(result)
print(f"saved scan id={sid}")

try:
    scan_target("8.8.8.8", [80])
    print("ERROR: should have raised for 8.8.8.8")
except ScanNotAllowed as e:
    print(f"allow-list enforced: {e}")
