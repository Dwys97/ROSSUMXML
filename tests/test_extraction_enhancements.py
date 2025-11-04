#!/usr/bin/env python3
"""
Test script for invoice extraction enhancements
Tests the new model and customs field extraction
"""

import sys
import os

# Add ml-service directory to path
ml_service_path = os.path.join(os.path.dirname(__file__), '..', 'backend', 'ml-service')
sys.path.insert(0, ml_service_path)

from extractors.rule_based_extractor import RuleBasedExtractor

def test_rule_based_extraction():
    """Test rule-based extraction of customs fields"""
    print("Testing Rule-Based Extractor...")
    print("-" * 60)
    
    # Sample invoice text with customs data
    sample_text = """
    COMMERCIAL INVOICE
    
    Invoice Number: INV-2024-001234
    Date: 15-Jan-2024
    Currency: EUR
    
    Seller:
    ABC Electronics GmbH
    Hauptstrasse 123
    10115 Berlin, Germany
    VAT: DE123456789
    
    Buyer:
    XYZ Imports Ltd
    123 Business Park
    London, UK
    VAT: GB987654321
    
    Incoterms: FOB
    Country of Origin: CN
    HS Code: 8517.62.00
    
    Line Items:
    1. Mobile Phone Display - Qty: 1000 pcs - Unit Price: 25.50 EUR
       HS Code: 8517.62.00
       Net Weight: 150.5 kg
       Gross Weight: 175.8 kg
    
    Total Amount: 25,500.00 EUR
    Total Net Weight: 150.5 kg
    Total Gross Weight: 175.8 kg
    """
    
    extractor = RuleBasedExtractor()
    result = extractor.extract(sample_text)
    
    print("\nExtraction Results:")
    print("=" * 60)
    
    # Print invoice details
    print("\n📄 INVOICE DETAILS:")
    if result.get('invoice'):
        for key, value in result['invoice'].items():
            if not key.endswith('Confidence'):
                conf = result['invoice'].get(f"{key}Confidence", 0)
                print(f"  {key}: {value} (confidence: {conf:.1f}%)")
    
    # Print seller info
    print("\n🏢 SELLER:")
    if result.get('seller'):
        for key, value in result['seller'].items():
            if not key.endswith('Confidence'):
                conf = result['seller'].get(f"{key}Confidence", 0)
                print(f"  {key}: {value} (confidence: {conf:.1f}%)")
    
    # Print buyer info
    print("\n🏪 BUYER:")
    if result.get('buyer'):
        for key, value in result['buyer'].items():
            if not key.endswith('Confidence'):
                conf = result['buyer'].get(f"{key}Confidence", 0)
                print(f"  {key}: {value} (confidence: {conf:.1f}%)")
    
    # Print shipping/customs data
    print("\n📦 CUSTOMS DATA:")
    if result.get('shipping'):
        for key, value in result['shipping'].items():
            if not key.endswith('Confidence'):
                conf = result['shipping'].get(f"{key}Confidence", 0)
                print(f"  {key}: {value} (confidence: {conf:.1f}%)")
    
    # Print totals
    print("\n💰 TOTALS:")
    if result.get('totals'):
        for key, value in result['totals'].items():
            if not key.endswith('Confidence'):
                conf = result['totals'].get(f"{key}Confidence", 0)
                print(f"  {key}: {value} (confidence: {conf:.1f}%)")
    
    print("\n" + "=" * 60)
    print(f"Overall Confidence: {result.get('confidence', 0):.1f}%")
    print("-" * 60)
    
    # Validation
    print("\n✅ VALIDATION:")
    checks = {
        "Invoice Number Extracted": result.get('invoice', {}).get('number') is not None,
        "Currency Extracted": result.get('invoice', {}).get('currency') is not None,
        "Incoterms Extracted": result.get('shipping', {}).get('incoterms') is not None,
        "HS Code Extracted": result.get('shipping', {}).get('hs_code') is not None,
        "Net Weight Extracted": result.get('totals', {}).get('net_weight') is not None,
        "Gross Weight Extracted": result.get('totals', {}).get('gross_weight') is not None,
    }
    
    for check, passed in checks.items():
        symbol = "✓" if passed else "✗"
        print(f"  {symbol} {check}")
    
    passed_count = sum(checks.values())
    total_count = len(checks)
    print(f"\n{passed_count}/{total_count} checks passed")
    
    return passed_count == total_count

if __name__ == "__main__":
    print("=" * 60)
    print("Invoice Extraction Enhancement Test")
    print("=" * 60)
    print()
    
    try:
        success = test_rule_based_extraction()
        
        if success:
            print("\n" + "=" * 60)
            print("🎉 ALL TESTS PASSED!")
            print("=" * 60)
            sys.exit(0)
        else:
            print("\n" + "=" * 60)
            print("⚠️  SOME TESTS FAILED")
            print("=" * 60)
            sys.exit(1)
            
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
