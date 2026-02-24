# Qwen Prompt Update & Worker Integration Summary

## 1. System Prompt Update
- **File:** `services/qwen-service/app.py`
- **Change:** Replaced the generic system prompt with the "Professional Customs Data Entry Specialist" persona.
- **Details:** 
  - Added strict field definitions for HS Codes, Net Weight, Gross Weight, Country of Origin, etc.
  - Implemented specific rules for null values (`null`, not "N/A").
  - Defined strict JSON output format with `line_items` array.

## 2. Data Pipeline Update
- **File:** `backend/workers/extractionWorker.js`
- **Change:** Updated `convertMicroservicesResponse` and `extractLineItems`.
- **Details:**
  - Added support for the nested `line_items` JSON array returned by the new prompt.
  - Preserved backward compatibility for flattened fields (`item_description_1`).
  - Mapped new field names to database columns.

## 3. Services Status
- **Qwen Service:** Restarted and Healthy.
- **Extraction Worker:** Code updated and restarted.
- **Orchestrator:** Verified as pass-through (no changes needed).

## 4. Verification
- The pipeline is now configured to extract strict customs data including:
  - HS Codes (6+ digits)
  - Net/Gross Weights
  - Country of Origin (ISO2)
  - Line item details (Quantity, Unit Price, Total)
