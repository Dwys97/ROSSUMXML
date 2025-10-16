# 📄 How to Extract and View Transformed XML

**Updated:** October 16, 2025  
**Status:** ✅ Backend updated to store transformed XML

---

## 🎯 Quick Start

### Method 1: View Latest Transformed XML (Easiest)

```bash
bash view-latest-xml.sh
```

This will show you the most recent successfully transformed XML, formatted and pretty-printed.

### Method 2: List All Webhooks and Choose One

```bash
# List all webhooks
bash list-webhooks.sh

# Extract specific webhook by ID
bash extract-webhook-xml.sh 66bcecee-0f01-4c46-b8ba-c8bcd7cf8fd0
```

### Method 3: Save to File

```bash
# Save latest XML to file
bash view-latest-xml.sh > output.xml

# Or save specific webhook
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c \
  "SELECT response_payload FROM webhook_events WHERE id = 'WEBHOOK_ID_HERE';" \
  > transformed_output.xml
```

---

## 📊 Understanding the Output

### What You'll See

When you run `view-latest-xml.sh`, you'll see output like:

```xml
<?xml version="1.0"?>
<RossumInvoice>
  <Metadata>
    <AnnotationId>23133597</AnnotationId>
    <Status>exporting</Status>
    <ModifiedAt>2025-10-15T19:44:45.068620Z</ModifiedAt>
  </Metadata>
  <basic_info_section>
    <document_id>000957537</document_id>
    <date_issue>1/3/2019</date_issue>
    <document_type>tax_invoice</document_type>
    <language>eng</language>
  </basic_info_section>
  <amounts_section>
    <amount_total_base>1 682.00</amount_total_base>
    <amount_total_tax>336.40</amount_total_tax>
    <amount_total>2 018.40</amount_total>
    <amount_due>2 018.40</amount_due>
    <currency>gbp</currency>
    <tax_details>
      <Item>
        <tax_detail_rate>20</tax_detail_rate>
        <tax_detail_base>1 682.00</tax_detail_base>
        <tax_detail_tax>336.40</tax_detail_tax>
        <tax_detail_total>2 018.40</tax_detail_total>
      </Item>
    </tax_details>
  </amounts_section>
  <vendor_section>
    <sender_name>Good Lock &amp; Safe Services</sender_name>
    <sender_address>762 Lovewell Street
Newcastle Upon Tyne
NE1 0SG</sender_address>
    <sender_vat_id>857 5746 84</sender_vat_id>
    <sender_ic>71 952 744 286</sender_ic>
    <recipient_name>Hilltop Hamlet</recipient_name>
    <recipient_address>PO Box 17320
HARDEN
BD16 1BU</recipient_address>
  </vendor_section>
  <payment_info_section>
    <account_num>505736372</account_num>
    <bank_num>80-37-95</bank_num>
    <terms>14 Days from Date of Invoice</terms>
    <var_sym>00013227</var_sym>
    <spec_sym>80-37-95</spec_sym>
  </payment_info_section>
  <line_items_section>
    <line_items>
      <Item>
        <item_quantity>100</item_quantity>
        <item_code>Skeleton key</item_code>
        <item_description>GMK keys stamping 132 issue 42-40</item_description>
        <item_amount_base>16.82</item_amount_base>
        <item_total_base>1 682.00</item_total_base>
        <item_amount_total>1 682.00</item_amount_total>
        <item_amount>16.82</item_amount>
      </Item>
    </line_items>
  </line_items_section>
</RossumInvoice>
```

This is the **SOURCE XML** (converted from Rossum JSON).

After transformation with your mapping, you get the **TRANSFORMED XML** (destination format).

---

## 🔄 Update Note

**Important:** I've just updated the backend to store transformed XML in the database.

**This means:**
- ❌ **Old webhooks** (processed before now) don't have XML stored
- ✅ **New webhooks** (processed after now) will have XML stored

**To see transformed XML:**
1. Go to Rossum: https://xmlmapper.rossum.app
2. Export an invoice (this triggers a new webhook)
3. Run: `bash view-latest-xml.sh`

---

## 🧪 Test Right Now

### Step 1: Export in Rossum

1. Open https://xmlmapper.rossum.app
2. Log in: jijesiv423@bdnets.com / Cancunmexico2025
3. Go to your queue
4. Select any annotation
5. Click "Export"

### Step 2: View the XML

```bash
# Wait 2 seconds for processing
sleep 2

# View the transformed XML
bash view-latest-xml.sh
```

---

## 📋 All Available Scripts

### 1. `view-latest-xml.sh`
**Purpose:** Quick view of the most recent transformed XML  
**Usage:**
```bash
bash view-latest-xml.sh
```

**Output:**
- ✅ Formatted, pretty-printed XML
- 📊 File size information
- 💾 Instructions to save to file

### 2. `list-webhooks.sh`
**Purpose:** See all webhook events with their status  
**Usage:**
```bash
bash list-webhooks.sh
```

**Output:**
- Webhook IDs (first 8 characters)
- Timestamp
- Rossum annotation ID
- Source/transformed XML sizes
- Processing time
- Status
- Whether XML is stored

### 3. `extract-webhook-xml.sh`
**Purpose:** Extract XML from a specific webhook  
**Usage:**
```bash
# View latest
bash extract-webhook-xml.sh

# View specific webhook
bash extract-webhook-xml.sh 66bcecee-0f01-4c46-b8ba-c8bcd7cf8fd0
```

**Output:**
- Webhook details (time, status, sizes)
- Source data structure (Rossum JSON summary)
- Transformed XML (if available)
- Export instructions

### 4. `monitor-webhooks.sh`
**Purpose:** Real-time monitoring of incoming webhooks  
**Usage:**
```bash
bash monitor-webhooks.sh
```

**Output:**
- Live updates when webhooks arrive
- Success/failure status
- Processing statistics

---

## 💾 Save XML to File

### Save Latest XML
```bash
bash view-latest-xml.sh > my_transformed_invoice.xml
```

### Save Specific Webhook
```bash
# Get webhook ID first
bash list-webhooks.sh

# Extract that webhook
bash extract-webhook-xml.sh WEBHOOK_ID_HERE > specific_invoice.xml
```

### Save with Timestamp
```bash
bash view-latest-xml.sh > invoice_$(date +%Y%m%d_%H%M%S).xml
```

---

## 🔍 Advanced: Direct Database Queries

### Get Transformed XML by Annotation ID
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT response_payload 
FROM webhook_events 
WHERE rossum_annotation_id = '23133597' 
  AND status = 'success'
  AND response_payload IS NOT NULL
ORDER BY created_at DESC 
LIMIT 1;
"
```

### Get All Successful Transformations
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
    TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') as time,
    rossum_annotation_id,
    source_xml_size,
    transformed_xml_size,
    processing_time_ms
FROM webhook_events 
WHERE status = 'success' 
  AND response_payload IS NOT NULL
ORDER BY created_at DESC;
"
```

### Export Multiple XMLs
```bash
#!/bin/bash
# Save all successful transformed XMLs to files

docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -A -c "
SELECT id || '|' || rossum_annotation_id 
FROM webhook_events 
WHERE status = 'success' AND response_payload IS NOT NULL;
" | while IFS='|' read -r webhook_id annotation_id; do
    echo "Exporting annotation $annotation_id..."
    docker exec rossumxml-db-1 psql -U postgres -d rossumxml -t -c "
    SELECT response_payload 
    FROM webhook_events 
    WHERE id = '$webhook_id';
    " > "transformed_${annotation_id}.xml"
    echo "  ✅ Saved to transformed_${annotation_id}.xml"
done

echo "Done! All XMLs exported."
```

---

## 🎯 What Gets Stored

### In Database (webhook_events table)

| Field | Description |
|-------|-------------|
| `request_payload` | Full Rossum JSON webhook payload (53KB+) |
| `response_payload` | **NEW!** Transformed XML output (3-4KB) |
| `source_xml_size` | Size of converted source XML in bytes |
| `transformed_xml_size` | Size of transformed XML in bytes |
| `processing_time_ms` | How long transformation took |
| `status` | 'success' or 'failed' |
| `rossum_annotation_id` | Rossum's annotation ID for reference |

---

## 🚀 Next Steps

### 1. Trigger a New Export

Export an invoice in Rossum to see the new storage in action:
```bash
# Then check
bash view-latest-xml.sh
```

### 2. Set Up Automatic Export

If you want to automatically save all transformed XMLs to files:

```bash
# Create a cron job or background script
watch -n 5 'bash view-latest-xml.sh > /path/to/exports/latest.xml'
```

### 3. Forward to Destination System

Configure `destination_webhook_url` in your API key settings to automatically forward transformed XML to another system.

---

## ✅ Summary

**You now have 3 ways to view transformed XML:**

1. **Quick View:** `bash view-latest-xml.sh`
2. **List & Choose:** `bash list-webhooks.sh` → `bash extract-webhook-xml.sh WEBHOOK_ID`
3. **Direct Query:** SQL queries to `webhook_events` table

**To test immediately:**
1. Export an invoice in Rossum
2. Run `bash view-latest-xml.sh`
3. See your transformed XML! 🎉

---

**Updated:** October 16, 2025  
**Backend:** ✅ Updated to store transformed XML  
**Scripts:** ✅ Ready to use
