#!/usr/bin/env python3
"""
Integration test for CPU-first deterministic extraction pipeline
Tests the full flow: CIR → Validation → LLM disambiguation
"""

import json
import sys

# Mock test - demonstrates the expected flow
def test_deterministic_pipeline():
    """Test the CPU-first deterministic pipeline logic"""
    
    print("=" * 60)
    print("CPU-First Deterministic Pipeline Integration Test")
    print("=" * 60)
    
    # Step 1: Simulate CIR extraction
    print("\n[Step 1] CIR Deterministic Extraction")
    print("-" * 60)
    
    invoice_text = """
    Invoice Number: INV-12345
    Invoice Date: 2026-01-15
    Due Date: 2026-02-15
    Vendor: Acme Corp
    Total Amount: $1,234.56
    VAT Number: GB123456789
    Currency: USD
    """
    
    # Import CIR service
    sys.path.insert(0, 'services/cir-service')
    from app import extractor
    
    cir_fields = extractor.extract_fields(invoice_text)
    
    print(f"✓ Extracted {len(cir_fields)} fields deterministically:")
    for field in cir_fields:
        print(f"  {field.field_name}: {field.value} "
              f"(confidence: {field.confidence:.2f}, method: {field.method})")
    
    # Convert to dict format for validation
    fields_dict = {}
    for field in cir_fields:
        fields_dict[field.field_name] = {
            'value': field.value,
            'confidence': field.confidence,
            'method': field.method
        }
    
    # Step 2: Simulate validation
    print("\n[Step 2] Validation Engine")
    print("-" * 60)
    
    # Clear sys.path and add validation service
    sys.path = [p for p in sys.path if 'cir-service' not in p]
    sys.path.insert(0, 'services/validation-service')
    
    # Import fresh
    import importlib
    if 'app' in sys.modules:
        del sys.modules['app']
    from app import validator
    
    validation_result = validator.validate_fields(fields_dict)
    
    print(f"✓ Validation complete:")
    print(f"  Overall confidence: {validation_result['overall_confidence']:.3f}")
    print(f"  Validation issues: {len(validation_result['validation_issues'])}")
    print(f"  Fields needing LLM: {validation_result['needs_llm']}")
    
    if validation_result['validation_issues']:
        print(f"  Issues found:")
        for issue in validation_result['validation_issues'][:3]:
            print(f"    - {issue}")
    
    # Step 3: Simulate LLM disambiguation decision
    print("\n[Step 3] LLM Disambiguation Decision")
    print("-" * 60)
    
    ambiguous_fields = validation_result['needs_llm']
    
    if ambiguous_fields:
        print(f"⚠ {len(ambiguous_fields)} field(s) need LLM disambiguation:")
        for field in ambiguous_fields:
            print(f"  - {field}")
        print(f"\n→ Would call Qwen2.5 for these {len(ambiguous_fields)} fields only")
    else:
        print("✓ All fields extracted deterministically - NO LLM NEEDED!")
    
    # Step 4: Calculate metrics
    print("\n[Step 4] Extraction Metrics")
    print("-" * 60)
    
    total_fields = len(fields_dict)
    deterministic_fields = total_fields - len(ambiguous_fields)
    deterministic_rate = (deterministic_fields / total_fields * 100) if total_fields > 0 else 0
    
    print(f"Total fields: {total_fields}")
    print(f"Deterministic: {deterministic_fields}")
    print(f"LLM required: {len(ambiguous_fields)}")
    print(f"Deterministic rate: {deterministic_rate:.1f}%")
    
    # Step 5: Routing decision
    print("\n[Step 5] Confidence Routing")
    print("-" * 60)
    
    overall_confidence = validation_result['overall_confidence']
    confidence_threshold = 0.90
    
    if overall_confidence >= confidence_threshold:
        print(f"✓ High confidence ({overall_confidence:.3f}) - AUTO-APPROVE")
        status = "completed"
    else:
        print(f"⚠ Low confidence ({overall_confidence:.3f}) - ROUTE TO HITL")
        status = "needs_review"
    
    # Summary
    print("\n" + "=" * 60)
    print("Pipeline Summary")
    print("=" * 60)
    print(f"Status: {status}")
    print(f"Deterministic extraction rate: {deterministic_rate:.1f}%")
    print(f"Overall confidence: {overall_confidence:.3f}")
    print(f"LLM usage: {len(ambiguous_fields)}/{total_fields} fields ({len(ambiguous_fields)/total_fields*100:.1f}%)")
    
    # Success criteria
    print("\n" + "=" * 60)
    print("Success Criteria")
    print("=" * 60)
    
    success = True
    
    # Check 1: At least 50% deterministic extraction
    if deterministic_rate >= 50:
        print(f"✓ Deterministic rate ≥50%: {deterministic_rate:.1f}%")
    else:
        print(f"✗ Deterministic rate <50%: {deterministic_rate:.1f}%")
        success = False
    
    # Check 2: Overall confidence reasonable
    if overall_confidence >= 0.70:
        print(f"✓ Overall confidence ≥0.70: {overall_confidence:.3f}")
    else:
        print(f"✗ Overall confidence <0.70: {overall_confidence:.3f}")
        success = False
    
    # Check 3: Some fields extracted
    if total_fields > 0:
        print(f"✓ Fields extracted: {total_fields}")
    else:
        print(f"✗ No fields extracted")
        success = False
    
    print("\n" + "=" * 60)
    if success:
        print("✓✓✓ ALL TESTS PASSED ✓✓✓")
        print("=" * 60)
        return 0
    else:
        print("✗✗✗ SOME TESTS FAILED ✗✗✗")
        print("=" * 60)
        return 1


if __name__ == '__main__':
    try:
        exit_code = test_deterministic_pipeline()
        sys.exit(exit_code)
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
