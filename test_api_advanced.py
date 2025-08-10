#!/usr/bin/env python3
"""
Advanced test script for Project TEDDY API endpoints
This script provides comprehensive testing with multiple scenarios
"""

import requests
import json
import time
import sys

class TeddyAPITester:
    def __init__(self, base_url="http://localhost:5000", api_key=None):
        self.base_url = base_url
        self.api_key = api_key or self.load_api_key()
        self.test_results = []
        
    def load_api_key(self):
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
    
    def get_headers(self):
        """Get headers with API key"""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers
        
    def log_test(self, test_name, success, message):
        """Log test results"""
        self.test_results.append({
            'test': test_name,
            'success': success,
            'message': message
        })
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"   {status}: {message}")
    
    def test_receive_data_valid(self):
        """Test /api/receive-data with valid data"""
        print("\n🧪 Test: Valid data submission")
        
        test_cases = [
            {"teddycode": "123456", "battery": 100},
            {"teddycode": "654321", "battery": 50},
            {"teddycode": "111111", "battery": 0},
            {"teddycode": "999999", "battery": 25}
        ]
        
        for i, data in enumerate(test_cases, 1):
            try:
                response = requests.post(
                    f"{self.base_url}/api/receive-data",
                    json=data,
                    headers=self.get_headers(),
                    timeout=10
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('success'):
                        self.log_test(f"Valid data {i}", True, f"Teddy {data['teddycode']} with {data['battery']}% battery")
                    else:
                        self.log_test(f"Valid data {i}", False, f"API returned success=false: {result.get('message')}")
                else:
                    self.log_test(f"Valid data {i}", False, f"HTTP {response.status_code}: {response.text}")
                    
            except Exception as e:
                self.log_test(f"Valid data {i}", False, f"Exception: {e}")
    
    def test_receive_data_invalid(self):
        """Test /api/receive-data with invalid data"""
        print("\n🧪 Test: Invalid data submission")
        
        test_cases = [
            ({"teddycode": "12345", "battery": 50}, "5-digit code"),
            ({"teddycode": "1234567", "battery": 50}, "7-digit code"), 
            ({"teddycode": "abcdef", "battery": 50}, "non-numeric code"),
            ({"teddycode": "123456", "battery": -1}, "negative battery"),
            ({"teddycode": "123456", "battery": 101}, "battery over 100"),
            ({"teddycode": "123456"}, "missing battery"),
            ({"battery": 50}, "missing teddy code"),
            ({}, "empty data")
        ]
        
        for data, description in test_cases:
            try:
                response = requests.post(
                    f"{self.base_url}/api/receive-data",
                    json=data,
                    headers=self.get_headers(),
                    timeout=10
                )
                
                if response.status_code == 400:
                    self.log_test(f"Invalid: {description}", True, "Correctly rejected")
                else:
                    self.log_test(f"Invalid: {description}", False, f"Should return 400, got {response.status_code}")
                    
            except Exception as e:
                self.log_test(f"Invalid: {description}", False, f"Exception: {e}")
    
    def test_broadcast_teddy_valid(self):
        """Test /api/broadcast-teddy with valid teddy codes"""
        print("\n🧪 Test: Valid broadcast requests")
        
        test_codes = ["123456", "654321", "111111", "999999"]
        
        for code in test_codes:
            try:
                response = requests.get(
                    f"{self.base_url}/api/broadcast-teddy",
                    params={"teddycode": code},
                    headers=self.get_headers(),
                    timeout=10
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('success'):
                        target_user = result.get('target_user', 'Unknown')
                        self.log_test(f"Broadcast {code}", True, f"Target user: {target_user}")
                    else:
                        self.log_test(f"Broadcast {code}", False, f"API returned success=false")
                elif response.status_code == 404:
                    self.log_test(f"Broadcast {code}", True, "Teddy not paired (expected for unpaired devices)")
                else:
                    self.log_test(f"Broadcast {code}", False, f"HTTP {response.status_code}: {response.text}")
                    
            except Exception as e:
                self.log_test(f"Broadcast {code}", False, f"Exception: {e}")
    
    def test_broadcast_teddy_invalid(self):
        """Test /api/broadcast-teddy with invalid teddy codes"""
        print("\n🧪 Test: Invalid broadcast requests")
        
        test_cases = [
            ("12345", "5-digit code"),
            ("1234567", "7-digit code"),
            ("abcdef", "non-numeric code"),
            ("", "empty code"),
            (None, "no teddycode parameter")
        ]
        
        for code, description in test_cases:
            try:
                params = {"teddycode": code} if code is not None else {}
                response = requests.get(
                    f"{self.base_url}/api/broadcast-teddy",
                    params=params,
                    headers=self.get_headers(),
                    timeout=10
                )
                
                if response.status_code == 400:
                    self.log_test(f"Invalid broadcast: {description}", True, "Correctly rejected")
                else:
                    self.log_test(f"Invalid broadcast: {description}", False, f"Should return 400, got {response.status_code}")
                    
            except Exception as e:
                self.log_test(f"Invalid broadcast: {description}", False, f"Exception: {e}")
    
    def test_api_key_authentication(self):
        """Test API key authentication"""
        print("\n🧪 Test: API Key Authentication")
        
        # Test without API key
        try:
            response = requests.post(
                f"{self.base_url}/api/receive-data",
                json={"teddycode": "123456", "battery": 50},
                headers={"Content-Type": "application/json"},  # No API key
                timeout=10
            )
            
            if response.status_code == 401:
                self.log_test("No API key", True, "Correctly rejected request without API key")
            else:
                self.log_test("No API key", False, f"Should return 401, got {response.status_code}")
                
        except Exception as e:
            self.log_test("No API key", False, f"Exception: {e}")
        
        # Test with invalid API key
        try:
            invalid_headers = {"Content-Type": "application/json", "X-API-Key": "invalid_key"}
            response = requests.post(
                f"{self.base_url}/api/receive-data",
                json={"teddycode": "123456", "battery": 50},
                headers=invalid_headers,
                timeout=10
            )
            
            if response.status_code == 401:
                self.log_test("Invalid API key", True, "Correctly rejected request with invalid API key")
            else:
                self.log_test("Invalid API key", False, f"Should return 401, got {response.status_code}")
                
        except Exception as e:
            self.log_test("Invalid API key", False, f"Exception: {e}")
        
        # Test with valid API key
        if self.api_key:
            try:
                response = requests.post(
                    f"{self.base_url}/api/receive-data",
                    json={"teddycode": "123456", "battery": 50},
                    headers=self.get_headers(),
                    timeout=10
                )
                
                if response.status_code == 200:
                    self.log_test("Valid API key", True, "Successfully authenticated with valid API key")
                else:
                    self.log_test("Valid API key", False, f"Authentication failed, got {response.status_code}")
                    
            except Exception as e:
                self.log_test("Valid API key", False, f"Exception: {e}")
        else:
            self.log_test("Valid API key", False, "No API key loaded from config")
    
    def test_server_availability(self):
        """Test if server is running and accessible"""
        print("\n🔍 Test: Server availability")
        
        try:
            response = requests.get(f"{self.base_url}/", timeout=5)
            if response.status_code == 200:
                self.log_test("Server connection", True, "Server is accessible")
                return True
            else:
                self.log_test("Server connection", False, f"Server returned {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Server connection", False, f"Cannot connect: {e}")
            return False
    
    def run_all_tests(self):
        """Run all tests"""
        print("🐻 Project TEDDY API Comprehensive Testing")
        print("=" * 60)
        
        # Check server first
        if not self.test_server_availability():
            print("\n❌ Cannot proceed - server is not accessible")
            print("💡 Make sure your Flask app is running")
            return False
        
        # Run all test suites
        self.test_api_key_authentication()
        self.test_receive_data_valid()
        self.test_receive_data_invalid()
        time.sleep(1)  # Brief pause between test suites
        self.test_broadcast_teddy_valid()
        self.test_broadcast_teddy_invalid()
        
        # Print summary
        self.print_summary()
        return True
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print("\n❌ Failed Tests:")
            for result in self.test_results:
                if not result['success']:
                    print(f"   - {result['test']}: {result['message']}")
        
        print("\n" + "=" * 60)

def main():
    """Main function"""
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://localhost:5000"
    
    print(f"Testing server at: {base_url}")
    
    tester = TeddyAPITester(base_url)
    tester.run_all_tests()

if __name__ == "__main__":
    main()
