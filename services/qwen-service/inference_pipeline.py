"""
Dynamic Field Manager (DFM) helpers for Qwen 2.5 extraction.
Builds scenario-aware prompts and injects structural anchors.
"""

from typing import Dict, Any, List, Optional
import re

DEFAULT_ALIAS_MAP = {
    "seller_name": ["shipper", "vendor", "exporter", "consignor"],
    "buyer_name": ["consignee", "importer", "deliver to", "fao", "payer"],
    "seller_vat_number": ["vat no", "vat number", "vat id", "tax id", "eori"],
    "buyer_vat_number": ["vat no", "vat number", "vat id", "tax id", "eori"],
    "total_amount": ["statistical value", "incoming value", "declared value", "repair value", "invoice total", "total value"],
    "subtotal": ["net value", "net amount", "subtotal"],
    "tax_amount": ["vat", "tax amount", "tax"],
    "total_packages": ["packages", "cartons", "pkgs"],
}

SELLER_KEYWORDS = ["seller", "vendor", "shipper", "exporter", "consignor"]
BUYER_KEYWORDS = ["buyer", "consignee", "importer", "deliver to", "fao", "payer"]
TOTALS_KEYWORDS = ["total", "subtotal", "tax", "amount", "gross", "net", "packages", "value"]
FINANCIAL_KEYWORDS = ["repair value", "declared value", "statistical value", "incoming value"]


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def detect_scenario(document_text: str) -> str:
    text = document_text or ""
    lower = text.lower()
    top = lower[:1200]

    has_table_headers = all(k in lower for k in ["description", "qty", "total"]) or all(k in lower for k in ["description", "quantity", "total"])
    has_grid_markers = "|" in text or any(re.search(r"\s{2,}\w+\s{2,}\w+", line) for line in text.splitlines()[:50])

    floating_hits = any(k in lower for k in ["awb", "cpc", "repair value", "declared value", "statistical value", "incoming value"])
    header_hits = sum(1 for k in ["exporter", "importer", "consignee", "payer", "deliver to", "fao", "vat", "eori"] if k in top)

    if has_table_headers and has_grid_markers:
        return "Traditional Grid"
    if floating_hits:
        return "Logistics Floating"
    if header_hits >= 2:
        return "Header-Heavy"
    return "Traditional Grid"


def inject_structural_anchors(document_text: str) -> str:
    lines = document_text.splitlines()
    tagged_lines: List[str] = []

    for line in lines:
        lower = _normalize(line)
        wrapped = line

        if any(k in lower for k in FINANCIAL_KEYWORDS):
            wrapped = f"[FINANCIAL_SUMMARY] {line} [/FINANCIAL_SUMMARY]"
        elif any(k in lower for k in SELLER_KEYWORDS):
            wrapped = f"[SELLER_ZONE] {line} [/SELLER_ZONE]"
        elif any(k in lower for k in BUYER_KEYWORDS):
            wrapped = f"[BUYER_ZONE] {line} [/BUYER_ZONE]"
        elif any(k in lower for k in TOTALS_KEYWORDS):
            wrapped = f"[TOTALS_ZONE] {line} [/TOTALS_ZONE]"

        tagged_lines.append(wrapped)

    return "\n".join(tagged_lines)


def build_terminology_cues(field_manager: Optional[Dict[str, Any]]) -> str:
    cues = []
    fields = (field_manager or {}).get("fields", [])
    if fields:
        for field in fields:
            key = field.get("field_key")
            aliases = field.get("aliases") or DEFAULT_ALIAS_MAP.get(key, [])
            if key and aliases:
                cues.append(f"'{' / '.join(aliases)}' are aliases for '{key}'.")
    else:
        for key, aliases in DEFAULT_ALIAS_MAP.items():
            cues.append(f"'{' / '.join(aliases)}' are aliases for '{key}'.")

    if not cues:
        return ""

    return "NOTE: " + " ".join(cues)


def _field_line(field: Dict[str, Any]) -> str:
    key = field.get("field_key") or ""
    label = field.get("field_label") or key
    desc = field.get("field_description") or ""
    fmt = field.get("format_hint")
    required = field.get("is_required")
    extras = []
    if fmt:
        extras.append(f"format: {fmt}")
    if required:
        extras.append("required")
    extra_str = f" ({', '.join(extras)})" if extras else ""
    return f"- {key}: {label}. {desc}{extra_str}".strip()


def build_dynamic_field_rules(field_manager: Optional[Dict[str, Any]], mode: str) -> str:
    fields = (field_manager or {}).get("fields", [])
    
    # Special case: if mode is "headers" and we have no non-line_items fields,
    # provide default header fields to extract
    if mode == "headers":
        has_header_fields = any(
            f.get("field_key") and f.get("field_key") != "line_items" 
            for f in fields
        )
        if not has_header_fields:
            # Return default header fields when none are specified
            return """- invoice_number: Invoice or reference number
- invoice_date: Invoice date
- seller_name: Seller/vendor/exporter name
- seller_address: Seller/vendor address
- seller_vat_number: Seller VAT or tax ID
- buyer_name: Buyer/consignee/importer name
- buyer_address: Buyer address
- buyer_vat_number: Buyer VAT or tax ID
- total_amount: Total invoice amount
- subtotal: Subtotal before tax
- tax_amount: Tax or VAT amount
- currency: Currency code
- Use null for any field not found in the document."""
    
    if not fields:
        return "- Use provided field keys and return null when not found."

    lines: List[str] = []
    field_count = 0
    
    for field in fields:
        key = field.get("field_key")
        if not key:
            continue
        if mode == "headers" and key == "line_items":
            continue
        if mode == "line_items" and key != "line_items":
            continue
        if key == "line_items":
            nested = field.get("nested_schema") or {}
            lines.append("- line_items: Array of item objects with fields:")
            for nested_key, nested_def in nested.items():
                label = nested_def.get("label", nested_key)
                desc = nested_def.get("description", "")
                line = f"  - {nested_key}: {label}. {desc}".strip()
                lines.append(line)
            lines.append("  - For each line item, include ALL listed keys and use null when missing.")
            field_count += 1
            continue
        lines.append(_field_line(field))
        field_count += 1
    
    if not lines:
        return "- Use provided field keys and return null when not found."
    
    # Add explicit instruction to include ALL fields
    result = "\n".join(lines)
    result += f"\n\nIMPORTANT: Your output MUST include ALL {field_count} fields listed above. Set any field to null if not found in the document. Do not omit any fields from the output."
    
    return result


def build_dynamic_prompt(document_text: str, field_manager: Optional[Dict[str, Any]] = None, mode: str = "full") -> str:
    scenario = detect_scenario(document_text)
    tagged_text = inject_structural_anchors(document_text)
    terminology = build_terminology_cues(field_manager)
    field_rules = build_dynamic_field_rules(field_manager, mode)

    scenario_clues = """- For Tabled: Follow the grid; treat the first row after headers as the start of a LineItem object.
- For Floating: Associate numerical values with the nearest text label (e.g., 'Repair Value').
- For Header-Heavy: Extract VAT/EORI and party names from contact blocks; map 'FAO' and 'Deliver To' to buyer_name.
- If the table has columns like 'Net Wt', 'Gross Wt', 'Net Weight', 'Gross Weight', map them to line_items.net_weight and line_items.gross_weight.
"""

    formatting_rules = """FORMATTING:
- Monetary fields must be numeric with exactly 2 decimal places.
- Weight fields (net/gross/total weight) must be numeric with exactly 3 decimal places.

TOTALS RULES:
- Use explicit totals near the summary/amount due section (e.g., 'TOTAL', 'GRAND TOTAL', 'INVOICE TOTAL', 'AMOUNT DUE', 'TOTAL PAYABLE').
- If a totals label exists, prefer that value over any sum of line items.
- Only infer totals from line items when no explicit totals are present.
"""

    prompt = f"""<|im_start|>system
You are a Customs Field Manager. You are extracting data for a {scenario} scenario.

FIELD RULES:
{field_rules}

{terminology}

SCENARIO CLUES:
{scenario_clues}

{formatting_rules}

Output only valid JSON following the schema. Use null for missing fields.
<|im_end|>
<|im_start|>user
{tagged_text}
<|im_end|>
<|im_start|>assistant
"""

    return prompt
