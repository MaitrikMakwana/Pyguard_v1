#!/usr/bin/env python3
"""
Final test to verify the Unicode CSV export fix
"""

import sys
import os
sys.path.append('.')

# Import the helper function from desktop app
from desktop_app.desktop_app import clean_unicode_for_csv

def test_unicode_fix():
    """Test the Unicode fix with the actual helper function"""
    print("🧪 Final Unicode CSV Export Test")
    print("=" * 50)
    
    # Test cases with problematic Unicode characters
    test_cases = [
        ("DNS Query → google.com", "DNS Query -> google.com"),
        ("HTTP Response ← server", "HTTP Response <- server"),
        ("Bidirectional ↔ traffic", "Bidirectional <-> traffic"),
        ("Flow ⇒ destination", "Flow => destination"),
        ("Reverse ⇐ flow", "Reverse <= flow"),
        ("List • item 1", "List * item 1"),
        ("Range – 100", "Range - 100"),
        ("Long dash — separator", "Long dash -- separator"),
        ('"Quoted text"', '"Quoted text"'),
        ("'Single quotes'", "'Single quotes'"),
        ("Mixed → ← ↔ arrows", "Mixed -> <- <-> arrows"),
    ]
    
    print("🔍 Testing Unicode character replacement:")
    all_passed = True
    
    for original, expected in test_cases:
        result = clean_unicode_for_csv(original)
        if result == expected:
            print(f"   ✅ '{original}' → '{result}'")
        else:
            print(f"   ❌ '{original}' → Expected: '{expected}', Got: '{result}'")
            all_passed = False
    
    # Test with non-string inputs
    print("\n🔍 Testing non-string inputs:")
    non_string_tests = [
        (123, "123"),
        (None, ""),
        (45.67, "45.67"),
        (True, "True"),
    ]
    
    for original, expected in non_string_tests:
        result = clean_unicode_for_csv(original)
        if result == expected:
            print(f"   ✅ {original} ({type(original).__name__}) → '{result}'")
        else:
            print(f"   ❌ {original} ({type(original).__name__}) → Expected: '{expected}', Got: '{result}'")
            all_passed = False
    
    return all_passed

def simulate_csv_export():
    """Simulate the actual CSV export process"""
    print("\n🔍 Simulating actual CSV export process:")
    
    import csv
    from io import StringIO
    
    # Simulate packet data with Unicode characters
    test_packets = [
        {
            'frame_number': 1,
            'timestamp': '2025-01-04 12:00:00.123456',
            'src_ip': '192.168.1.100',
            'src_port': 12345,
            'dst_ip': '8.8.8.8',
            'dst_port': 53,
            'protocol': 'UDP',
            'size': 64,
            'summary': 'DNS Query → google.com'
        },
        {
            'frame_number': 2,
            'timestamp': '2025-01-04 12:00:00.234567',
            'src_ip': '8.8.8.8',
            'src_port': 53,
            'dst_ip': '192.168.1.100',
            'dst_port': 12345,
            'protocol': 'UDP',
            'size': 128,
            'summary': 'DNS Response ← google.com'
        }
    ]
    
    fields = ['frame_number', 'timestamp', 'src_ip', 'src_port', 
              'dst_ip', 'dst_port', 'protocol', 'size', 'summary']
    
    try:
        # Use StringIO to simulate file writing
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        
        for i, packet in enumerate(test_packets):
            # Apply the same logic as in the desktop app
            row = {}
            for field in fields:
                if field in packet:
                    if isinstance(packet[field], (dict, list)):
                        row[field] = clean_unicode_for_csv(str(packet[field]))
                    else:
                        row[field] = clean_unicode_for_csv(packet[field])
                elif field == 'frame_number' and 'frame_number' not in packet:
                    row[field] = i + 1
            
            writer.writerow(row)
        
        result = output.getvalue()
        print("   ✅ CSV export simulation successful!")
        print("   📝 Generated CSV content:")
        
        lines = result.strip().split('\n')
        for i, line in enumerate(lines):
            print(f"      {i+1}: {line}")
        
        # Check if Unicode characters were properly replaced
        if '→' in result or '←' in result:
            print("   ❌ Unicode characters still present in output!")
            return False
        elif '->' in result and '<-' in result:
            print("   ✅ Unicode characters successfully replaced!")
            return True
        
    except Exception as e:
        print(f"   ❌ CSV export simulation failed: {e}")
        return False

if __name__ == "__main__":
    print("🔧 PyGuard Unicode CSV Export - Final Verification")
    print("=" * 60)
    
    # Test the helper function
    helper_test_passed = test_unicode_fix()
    
    # Test the actual CSV export process
    csv_test_passed = simulate_csv_export()
    
    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS:")
    
    if helper_test_passed and csv_test_passed:
        print("✅ ALL TESTS PASSED!")
        print("🎉 The Unicode CSV export fix is working correctly!")
        print("\n💡 To apply the fix:")
        print("1. Restart the PyGuard desktop application")
        print("2. Capture some packets")
        print("3. Click '💾 Save' and select 'CSV files (*.csv)'")
        print("4. The CSV file should now save without Unicode errors")
    else:
        print("❌ SOME TESTS FAILED!")
        if not helper_test_passed:
            print("   - Helper function test failed")
        if not csv_test_passed:
            print("   - CSV export simulation failed")
        print("🔧 Please check the implementation and try again.")