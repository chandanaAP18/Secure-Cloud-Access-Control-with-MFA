import requests
import time

BASE_URL = "http://localhost:8000"

def test_security_headers():
    print("Testing Security Headers...")
    try:
        response = requests.get(f"{BASE_URL}/accounts/login/")
        headers = response.headers
        
        checks = {
            "X-Frame-Options": "DENY" or "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "same-origin",
        }
        
        for header, expected in checks.items():
            val = headers.get(header)
            if val:
                print(f"[PASS] {header}: {val}")
            else:
                print(f"[FAIL] {header} is missing")
    except Exception as e:
        print(f"Error connecting to server: {e}. Make sure the server is running.")

def test_response_time():
    print("\nTesting Response Time...")
    try:
        start_time = time.time()
        response = requests.get(f"{BASE_URL}/")
        end_time = time.time()
        
        duration = (end_time - start_time) * 1000
        print(f"Home page loaded in {duration:.2f}ms")
        
        if duration < 500:
            print("[PASS] Response time is under 500ms")
        else:
            print("[WARN] Response time is over 500ms")
    except Exception as e:
        print(f"Error connecting to server: {e}")

if __name__ == "__main__":
    test_security_headers()
    test_response_time()
