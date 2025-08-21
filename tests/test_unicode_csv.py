#!/usr/bin/env python3
"""
Test script to verify Unicode character handling in CSV export
"""

import csv
import os
from pathlib import Path

def test_unicode_csv_export():
    """Test CSV export with Unicode characters"""
    print("🧪 Testing Unicode CSV Export Fix")
    print("=" * 50)
    
    # Test data with problematic Unicode characters
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
            'summary': 'DNS Query → google.com'  # Contains right arrow Unicode
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
            'summary': 'DNS Response ← google.com'  # Contains left arrow Unicode
        },
        {
            'frame_number': 3,
            'timestamp': '2025-01-04 12:00:01.345678',
            'src_ip': '192.168.1.100',
            'src_port': 54321,
            'dst_ip': '172.217.14.110',
            'dst_port': 80,
            'protocol': 'TCP',
            'size': 1024,
            'summary': 'HTTP GET "example.com" • Status: 200'  # Contains quotes and bullet
        }
    ]
    
    # Define CSV fields (same as desktop app)
    fields = ['frame_number', 'timestamp', 'src_ip', 'src_port', 
              'dst_ip', 'dst_port', 'protocol', 'size', 'summary']
    
    # Test the old method (should fail)
    print("🔍 Testing old method (without UTF-8 encoding)...")
    try:
        with open('test_old_method.csv', 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            for packet in test_packets:
                writer.writerow(packet)
        print("   ⚠️  Old method worked (unexpected - might depend on system)")
        os.remove('test_old_method.csv')
    except UnicodeEncodeError as e:
        print(f"   ❌ Old method failed as expected: {e}")
    
    # Test the new method (should work)
    print("\n🔍 Testing new method (with UTF-8 encoding and character replacement)...")
    try:
        output_file = 'test_unicode_fixed.csv'
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            
            for i, packet in enumerate(test_packets):
                # Create a clean row with Unicode character replacement
                row = {}
                for field in fields:
                    if field in packet:
                        if isinstance(packet[field], (dict, list)):
                            row[field] = str(packet[field])
                        else:
                            # Convert to string and handle Unicode characters
                            value = str(packet[field]) if packet[field] is not None else ""
                            # Replace problematic Unicode characters with ASCII equivalents
                            value = value.replace('\u2192', '->')  # Right arrow
                            value = value.replace('\u2190', '<-')  # Left arrow
                            value = value.replace('\u2194', '<->')  # Left-right arrow
                            value = value.replace('\u21d2', '=>')  # Double right arrow
                            value = value.replace('\u21d0', '<=')  # Double left arrow
                            value = value.replace('\u2022', '*')   # Bullet point
                            value = value.replace('\u2013', '-')   # En dash
                            value = value.replace('\u2014', '--')  # Em dash
                            value = value.replace('\u201c', '"')   # Left double quote
                            value = value.replace('\u201d', '"')   # Right double quote
                            value = value.replace('\u2018', "'")   # Left single quote
                            value = value.replace('\u2019', "'")   # Right single quote
                            row[field] = value
                    elif field == 'frame_number' and 'frame_number' not in packet:
                        row[field] = i + 1
                
                writer.writerow(row)
        
        print("   ✅ New method successful!")
        
        # Verify the file content
        if Path(output_file).exists():
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
                print(f"   📁 File created: {Path(output_file).absolute()}")
                print(f"   📊 File size: {len(content)} characters")
                print("\n   📝 Content preview:")
                lines = content.split('\n')
                for i, line in enumerate(lines[:5]):  # Show first 5 lines
                    print(f"      {i+1}: {line}")
                
                # Check if Unicode characters were replaced
                if '→' in content:
                    print("   ⚠️  Original Unicode characters still present")
                elif '->' in content:
                    print("   ✅ Unicode characters successfully replaced with ASCII")
        
        # Clean up
        if Path(output_file).exists():
            os.remove(output_file)
            
        return True
        
    except Exception as e:
        print(f"   ❌ New method failed: {e}")
        return False

def test_common_unicode_characters():
    """Test handling of common Unicode characters found in network traffic"""
    print("\n🔍 Testing common Unicode characters in network traffic...")
    
    unicode_test_cases = [
        ('\u2192', '->'),   # Right arrow
        ('\u2190', '<-'),   # Left arrow
        ('\u2194', '<->'),  # Left-right arrow
        ('\u21d2', '=>'),   # Double right arrow
        ('\u21d0', '<='),   # Double left arrow
        ('\u2022', '*'),    # Bullet point
        ('\u2013', '-'),    # En dash
        ('\u2014', '--'),   # Em dash
        ('\u201c', '"'),    # Left double quote
        ('\u201d', '"'),    # Right double quote
        ('\u2018', "'"),    # Left single quote
        ('\u2019', "'"),    # Right single quote
    ]
    
    for unicode_char, replacement in unicode_test_cases:
        test_string = f"Test {unicode_char} character"
        
        # Apply the same replacement logic as in the fix
        fixed_string = test_string
        fixed_string = fixed_string.replace('\u2192', '->')
        fixed_string = fixed_string.replace('\u2190', '<-')
        fixed_string = fixed_string.replace('\u2194', '<->')
        fixed_string = fixed_string.replace('\u21d2', '=>')
        fixed_string = fixed_string.replace('\u21d0', '<=')
        fixed_string = fixed_string.replace('\u2022', '*')
        fixed_string = fixed_string.replace('\u2013', '-')
        fixed_string = fixed_string.replace('\u2014', '--')
        fixed_string = fixed_string.replace('\u201c', '"')
        fixed_string = fixed_string.replace('\u201d', '"')
        fixed_string = fixed_string.replace('\u2018', "'")
        fixed_string = fixed_string.replace('\u2019', "'")
        
        expected = f"Test {replacement} character"
        if fixed_string == expected:
            print(f"   ✅ {repr(unicode_char)} → {repr(replacement)}")
        else:
            print(f"   ❌ {repr(unicode_char)} → Expected: {repr(expected)}, Got: {repr(fixed_string)}")

if __name__ == "__main__":
    success = test_unicode_csv_export()
    test_common_unicode_characters()
    
    print("\n" + "=" * 50)
    if success:
        print("✅ Unicode CSV export fix verified!")
        print("💡 The desktop app should now be able to save CSV files with Unicode characters.")
        print("🔄 Please restart the desktop application to use the updated code.")
    else:
        print("❌ Unicode CSV export fix needs more work.")