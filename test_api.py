#!/usr/bin/env python3
"""
Continuous test script for Project TEDDY API endpoints
This script runs in a loop, testing 8 teddy codes simultaneously
"""

import requests
import json
import time
import random
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:5000"  # Change this if your Flask app runs on a different host/port
TEST_TEDDY_CODES = ["123456", "654321", "111111", "222222", "333333", "444444", "555555", "999999"]
LOOP_INTERVAL = 10  # seconds between test cycles

def load_api_key():
    """Load API key from config.json"""
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            return config.get('api_key')
    except FileNotFoundError:
        print("⚠️  Warning: config.json not found. API key will be None.")
        return None
    except Exception as e:
        print(f"⚠️  Warning: Could not load API key: {e}")
        return None

def get_headers():
    """Get headers with API key"""
    headers = {"Content-Type": "application/json"}
    api_key = load_api_key()
    if api_key:
        headers["X-API-Key"] = api_key
    return headers

def send_battery_data(teddy_code, battery_level):
    """Send battery data for a specific teddy"""
    try:
        data = {
            "teddycode": teddy_code,
            "battery": battery_level
        }
        
        response = requests.post(
            f"{BASE_URL}/api/receive-data",
            json=data,
            headers=get_headers(),
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                return True, f"✅ Battery {battery_level}%"
            else:
                return False, f"❌ API Error: {result.get('message')}"
        else:
            return False, f"❌ HTTP {response.status_code}"
            
    except Exception as e:
        return False, f"❌ Exception: {e}"

def get_target_user(teddy_code):
    """Get target user for a specific teddy"""
    try:
        response = requests.get(
            f"{BASE_URL}/api/broadcast-teddy",
            params={"teddycode": teddy_code},
            headers=get_headers(),
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                target_user = result.get('target_user', 'Unknown')
                return True, f"🎯 Target: {target_user}"
            else:
                return False, f"❌ API Error: {result.get('message')}"
        elif response.status_code == 404:
            return True, "⚠️  Not paired"
        else:
            return False, f"❌ HTTP {response.status_code}"
            
    except Exception as e:
        return False, f"❌ Exception: {e}"

def test_all_teddies():
    """Test all 8 teddy codes in one cycle"""
    print(f"\n{'='*80}")
    print(f"🐻 Testing Cycle - {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*80}")
    
    for i, teddy_code in enumerate(TEST_TEDDY_CODES, 1):
        # Generate random battery level between 10-100
        battery_level = random.randint(10, 100)
        
        print(f"\n{i}. Testing TEDDY {teddy_code}:")
        
        # Send battery data
        send_success, send_msg = send_battery_data(teddy_code, battery_level)
        print(f"   📊 Send Data: {send_msg}")
        
        # Small delay between send and receive
        time.sleep(0.5)
        
        # Get target user
        get_success, get_msg = get_target_user(teddy_code)
        print(f"   🎯 Get Target: {get_msg}")
        
        # Overall status
        if send_success and get_success:
            print(f"   ✅ TEDDY {teddy_code} - ALL OK")
        else:
            print(f"   ❌ TEDDY {teddy_code} - ISSUES DETECTED")

def check_server_connection():
    """Check if the Flask server is running"""
    print("🔍 Checking server connection...")
    
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        if response.status_code == 200:
            print("   ✅ Server is running and accessible!")
            return True
        else:
            print(f"   ⚠️  Server responded with status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Cannot connect to server: {e}")
        print(f"   💡 Make sure your Flask app is running on {BASE_URL}")
        return False

def main():
    """Main loop function"""
    print("🐻 Project TEDDY Continuous API Testing")
    print("=" * 80)
    print(f"� Testing {len(TEST_TEDDY_CODES)} TEDDY codes every {LOOP_INTERVAL} seconds")
    print(f"🎯 Codes: {', '.join(TEST_TEDDY_CODES)}")
    print(f"🌐 Server: {BASE_URL}")
    print("=" * 80)
    print("Press Ctrl+C to stop")
    
    # Check server connection first
    if not check_server_connection():
        print("❌ Cannot proceed with tests - server is not accessible")
        return
    
    api_key = load_api_key()
    if api_key:
        print(f"🔑 API Key loaded: {api_key[:10]}...")
    else:
        print("⚠️  No API key found - tests may fail")
    
    cycle_count = 0
    
    try:
        while True:
            cycle_count += 1
            print(f"\n🔄 Cycle #{cycle_count}")
            
            # Run test cycle
            test_all_teddies()
            
            # Wait before next cycle
            print(f"\n⏱️  Waiting {LOOP_INTERVAL} seconds before next cycle...")
            time.sleep(LOOP_INTERVAL)
            
    except KeyboardInterrupt:
        print(f"\n\n🛑 Testing stopped by user after {cycle_count} cycles")
        print("👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()
