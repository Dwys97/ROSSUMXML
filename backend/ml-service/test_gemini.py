#!/usr/bin/env python3
"""
Quick test script for Gemini RAG/Validation integration
"""

import os
import sys
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load env.json for API key
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'env.json')
if os.path.exists(env_path):
    with open(env_path, 'r') as f:
        env_config = json.load(f)
        os.environ['GEMINI_API_KEY'] = env_config['TransformFunction']['GEMINI_API_KEY']

from models.gemini_validator import GeminiValidator

def test_gemini_validator():
    """Test Gemini validator initialization and basic validation"""
    
    print("=" * 80)
    print("GEMINI RAG/VALIDATION TEST")
    print("=" * 80)
    
    # Initialize validator
    print("\n1. Initializing Gemini validator...")
    validator = GeminiValidator()
    
    if not validator.enabled:
        print("❌ FAILED: Gemini validator not enabled")
        print("   Check if GEMINI_API_KEY is set")
        return False
    
    print("✅ Gemini validator initialized")
    print(f"   Model: gemini-2.0-flash-exp")
    
    # Test data (sample extraction result)
    print("\n2. Preparing test data...")
    extracted_data = {
        "invoice": {
            "number": "INV-123456",
            "date": "2025-11-04",
            "currency": "USD"
        },
        "seller": {
            "name": "Test Supplier Inc"
        },
        "buyer": {
            "name": "Test Customer Ltd"
        },
        "totals": {
            "total_amount": 1250.50
        },
        "lineItems": [],
        "confidence": 65.5
    }
    
    ocr_text = """
    INVOICE
    Invoice Number: INV-123456
    Date: November 4, 2025
    
    From: Test Supplier Inc
    To: Test Customer Ltd
    
    Total Amount: $1,250.50 USD
    """
    
    print("✅ Test data prepared")
    
    # Test validation
    print("\n3. Testing Gemini validation...")
    try:
        result = validator.validate_extraction(
            extracted_data=extracted_data,
            ocr_text=ocr_text,
            pii_filtered=False
        )
        
        print("✅ Gemini validation completed")
        print(f"\n   Results:")
        print(f"   - Validated: {result.get('validated', False)}")
        print(f"   - Confidence Score: {result.get('confidence_score', 0)}%")
        print(f"   - Confidence Boost: +{result.get('confidence_boost', 0)}%")
        print(f"   - Corrections: {len(result.get('corrections', {}))} fields")
        print(f"   - Issues: {len(result.get('issues', []))} found")
        
        if result.get('issues'):
            print(f"\n   Issues Found:")
            for issue in result['issues']:
                print(f"   - {issue}")
        
        if result.get('corrections'):
            print(f"\n   Corrections Suggested:")
            for field, value in result['corrections'].items():
                print(f"   - {field}: {value}")
        
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "=" * 80)
    print("TEST COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    success = test_gemini_validator()
    sys.exit(0 if success else 1)
