#!/usr/bin/env python3
"""Test h2 with httpx to verify response delivery."""
import httpx

def test():
    try:
        with httpx.Client(verify=False, http2=True, timeout=5.0) as client:
            print("Testing GET / ...")
            r = client.get("https://127.0.0.1:8444/")
            print(f"Status: {r.status_code}")
            print(f"Body: {r.text[:100]}")
            print(f"HTTP version: {r.http_version}")
    except Exception as e:
        print(f"Error: {e}")

test()
