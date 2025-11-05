#!/usr/bin/env python3
"""
Test Gemini RAG (Retrieval-Augmented Generation) for missing field extraction
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

def test_gemini_rag():
    """Test Gemini RAG for extracting missing fields"""
    
    print("=" * 80)
    print("GEMINI RAG (Retrieval-Augmented Generation) TEST")
    print("=" * 80)
    
    # Initialize validator
    print("\n1. Initializing Gemini validator...")
    validator = GeminiValidator()
    
    if not validator.enabled:
        print("❌ FAILED: Gemini validator not enabled")
        return False
    
    print("✅ Gemini validator initialized")
    
    # Simulate incomplete extraction (missing critical fields)
    print("\n2. Simulating incomplete extraction...")
    incomplete_extraction = {
        "invoice": {
            # Missing: number, date
            "currency": "USD"
        },
        "seller": {
            # Missing: name
        },
        "buyer": {
            # Missing: name
        },
        "totals": {
            # Missing: total_amount
        },
        "shipping": {
            # Missing: incoterms, countryOfOrigin
        },
        "lineItems": [],
        "confidence": 45.0  # Low confidence due to missing fields
    }
    
    # OCR text that contains the missing information
    ocr_text = """
    COMMERCIAL INVOICE
    
    Invoice No: INV-2025-11-0452
    Date: November 4, 2025
    Currency: USD
    
    EXPORTER:
    Global Electronics Manufacturing Ltd.
    123 Industrial Park Road
    Shenzhen, China
    
    CONSIGNEE:
    TechDist Solutions Inc.
    456 Commerce Boulevard
    San Francisco, CA 94105
    USA
    
    SHIPPING TERMS: FOB Shenzhen
    COUNTRY OF ORIGIN: China
    
    ITEM DESCRIPTION                    QTY    UNIT PRICE    AMOUNT
    Wireless Mouse Model XR-200         500    $12.50        $6,250.00
    USB-C Cables 2m Premium Grade      1000    $3.75         $3,750.00
    
    SUBTOTAL:                                               $10,000.00
    SHIPPING:                                                  $450.00
    INSURANCE:                                                 $125.00
    
    TOTAL AMOUNT:                                          $10,575.00
    
    NET WEIGHT: 125.5 KG
    GROSS WEIGHT: 142.8 KG
    """
    
    print("✅ Incomplete extraction prepared")
    print(f"   Missing fields: invoice.number, invoice.date, seller.name, buyer.name, etc.")
    
    # Test RAG extraction
    print("\n3. Using Gemini RAG to extract missing fields...")
    print("   (This may take 3-5 seconds...)")
    
    try:
        # Identify missing fields
        missing_fields = validator._identify_missing_fields(incomplete_extraction, pii_filtered=False)
        print(f"\n   Identified {len(missing_fields)} missing critical fields:")
        for field in missing_fields:
            print(f"   - {field}")
        
        # Extract using RAG
        rag_result = validator.extract_missing_fields(
            extracted_data=incomplete_extraction,
            ocr_text=ocr_text,
            missing_fields=missing_fields
        )
        
        print(f"\n✅ Gemini RAG extraction completed")
        print(f"   Extracted {len(rag_result)} fields:\n")
        
        for field, value in rag_result.items():
            if not field.endswith("Confidence"):
                confidence = rag_result.get(f"{field}Confidence", "N/A")
                print(f"   ✓ {field}: {value} (confidence: {confidence}%)")
        
        # Test full validation + RAG pipeline
        print("\n4. Testing full validation + RAG enhancement pipeline...")
        enhanced_data = validator.validate_and_enhance(
            extracted_data=incomplete_extraction,
            ocr_text=ocr_text,
            pii_filtered=False,
            enable_rag=True
        )
        
        print(f"\n✅ Enhancement completed")
        print(f"\n   BEFORE Enhancement:")
        print(f"   - Confidence: {incomplete_extraction.get('confidence', 0)}%")
        print(f"   - Invoice fields: {len(incomplete_extraction.get('invoice', {}))}")
        print(f"   - Seller fields: {len(incomplete_extraction.get('seller', {}))}")
        print(f"   - Buyer fields: {len(incomplete_extraction.get('buyer', {}))}")
        
        print(f"\n   AFTER Enhancement:")
        print(f"   - Confidence: {enhanced_data.get('confidence', 0)}%")
        print(f"   - Invoice fields: {len(enhanced_data.get('invoice', {}))}")
        print(f"   - Seller fields: {len(enhanced_data.get('seller', {}))}")
        print(f"   - Buyer fields: {len(enhanced_data.get('buyer', {}))}")
        print(f"   - Gemini Validated: {enhanced_data.get('gemini_validated', False)}")
        print(f"   - RAG Extracted Fields: {enhanced_data.get('gemini_rag_fields', [])}")
        
        print("\n   Enhanced Invoice Data:")
        print(f"   {json.dumps(enhanced_data.get('invoice', {}), indent=6)}")
        
        return True
        
    except Exception as e:
        print(f"❌ FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "=" * 80)
    print("RAG TEST COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    success = test_gemini_rag()
    sys.exit(0 if success else 1)
