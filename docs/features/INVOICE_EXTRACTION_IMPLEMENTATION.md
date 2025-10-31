# Invoice Extraction System - Implementation Guide

## 📋 Overview

This document describes the implementation of the AI-Powered Invoice Extraction & Annotation System, including architecture, components, and deployment instructions.

## 🏗️ Architecture

### Database Schema
The system uses 6 new PostgreSQL tables (Migration 013):

1. **invoices** - Main invoice storage
   - File metadata and paths
   - ML extraction status and confidence
   - Workflow status tracking
   - GDPR-compliant file deletion scheduling

2. **invoice_parties** - Buyer/Seller information
   - Party details (name, address, VAT, etc.)
   - Per-field confidence scores (JSON)
   - Bounding box coordinates (JSON)

3. **invoice_line_items** - Itemized goods
   - Line item details (description, HS code, origin, etc.)
   - Quantities, prices, weights
   - Per-field confidence scores

4. **invoice_corrections** - User corrections
   - Field-level correction tracking
   - ML confidence scores
   - Training dataset preparation
   - Query/rejection comments

5. **vendor_profiles** - Vendor recognition
   - Vendor identification (name, VAT, logo hash)
   - Custom extraction templates
   - Performance metrics

6. **invoice_audit_log** - Audit trail
   - All user actions logged
   - Status changes tracked
   - ISO 27001 compliant

### Backend Services

#### 1. invoiceExtraction.service.js
**Purpose:** ML-based data extraction from invoices

**Current Implementation:**
- PDF text extraction with `pdf-parse`
- Pattern-based field extraction (fallback)
- Confidence score calculation
- Database storage of extracted data

**Production Enhancements Needed:**
- Full LayoutLMv3 integration via HuggingFace API
- OCR for image-based invoices
- Bounding box detection and storage
- Multi-page document handling

**Key Functions:**
```javascript
extractInvoiceData(invoiceId)      // Main extraction function
extractWithLayoutLMv3(filePath)    // ML extraction (placeholder)
extractDataFromText(text)          // Pattern-based fallback
getVendorProfile(orgId, name)      // Vendor matching
```

#### 2. vendorRecognition.service.js
**Purpose:** Vendor identification and custom templates

**Features:**
- Vendor matching by VAT number or name
- Vendor profile creation/updating
- Custom extraction template application
- Accuracy metrics tracking

**Key Functions:**
```javascript
createOrUpdateVendorProfile(orgId, vendorData)
matchVendor(orgId, extractedData)
applyVendorTemplate(vendorProfile, data)
updateVendorMetrics(vendorId, confidence)
```

#### 3. invoiceExport.service.js
**Purpose:** Generate export files in multiple formats

**Features:**
- HMRC CDS Schema compliant XML
- CSV with all customs fields
- XLS export (Excel compatible)

**Formats:**
- **XML:** Full customs declaration structure
- **CSV:** Flat format with one row per line item
- **XLS:** CSV format (for true .xls, add 'xlsx' library)

**Key Functions:**
```javascript
exportAsXML(invoiceId)    // HMRC CDS compliant
exportAsCSV(invoiceId)    // CSV format
exportAsXLS(invoiceId)    // Excel compatible
```

#### 4. invoiceAudit.service.js
**Purpose:** Audit trail and compliance reporting

**Features:**
- Invoice-level audit trails
- Organization-wide statistics
- User activity tracking
- Compliance report generation

**Key Functions:**
```javascript
getInvoiceAuditTrail(invoiceId, options)
getInvoiceAuditSummary(invoiceId)
getOrganizationAuditStats(orgId, options)
generateComplianceReport(orgId, options)
```

#### 5. modelFineTuning.service.js
**Purpose:** ML model improvement via user corrections

**Features:**
- Correction collection and filtering
- Training dataset preparation
- HuggingFace API integration (placeholder)
- Accuracy metrics tracking

**Key Functions:**
```javascript
collectCorrections(options)
prepareTrainingDataset(corrections)
markCorrectionsAsUsed(correctionIds)
submitTrainingJob(dataset)          // Placeholder
getAccuracyMetrics(orgId, options)
```

### API Endpoints

#### Invoice Management

**1. Upload Invoice**
```http
POST /api/invoices/upload
Authorization: Bearer <token>
Permission: invoice:upload

Content-Type: multipart/form-data
Body:
  - file: <file> (PDF/PNG/JPG, max 10MB)
  - organizationId: <uuid>

Response: 201 Created
{
  "message": "Invoice uploaded successfully",
  "invoice": { ... }
}
```

**2. List Invoices**
```http
GET /api/invoices?organizationId=<uuid>&status=<status>&page=1&limit=20
Authorization: Bearer <token>
Permission: invoice:review

Response: 200 OK
{
  "invoices": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "pages": 5
  }
}
```

**3. Get Invoice Details**
```http
GET /api/invoices/:id
Authorization: Bearer <token>
Permission: invoice:review

Response: 200 OK
{
  "invoice": { ... },
  "parties": [...],
  "lineItems": [...],
  "corrections": [...]
}
```

**4. Update Status**
```http
PUT /api/invoices/:id/status
Authorization: Bearer <token>
Permission: invoice:review

Body:
{
  "status": "queried|rejected|exported",
  "comment": "Reason or question",
  "recipientEmail": "supplier@example.com"
}

Response: 200 OK
{
  "message": "Invoice status updated successfully",
  "oldStatus": "to_review",
  "newStatus": "queried"
}
```

**5. Trigger Extraction**
```http
POST /api/invoices/:id/extract
Authorization: Bearer <token>
Permission: invoice:upload

Response: 200 OK
{
  "message": "ML extraction triggered successfully",
  "status": "processing"
}
```

**6. Submit Correction**
```http
PUT /api/invoices/:id/correct
Authorization: Bearer <token>
Permission: invoice:review

Body:
{
  "fieldPath": "buyer.name",
  "originalValue": "ABC Corp",
  "correctedValue": "ABC Corporation",
  "mlConfidence": 85.5
}

Response: 200 OK
{
  "message": "Correction submitted successfully"
}
```

**7. Export Invoice**
```http
POST /api/invoices/:id/export
Authorization: Bearer <token>
Permission: invoice:export

Body:
{
  "format": "xml|csv|xls"
}

Response: 200 OK
Content-Type: application/xml|text/csv|application/vnd.ms-excel
Content-Disposition: attachment; filename="invoice-<id>.<ext>"

<file content>
```

### Frontend Components

#### Pages

**1. InvoiceWorkflowPage** (`/invoices`)
- Document queue with status filters
- Table and grid view toggle
- Pagination
- Upload button with drag-drop

**2. InvoiceAnnotationPage** (`/invoices/:id`)
- Split-panel layout (PDF left, fields right)
- Export buttons (XML/CSV/XLS)
- Field-level review interface
- Line items editor

#### Components

**1. InvoiceUploader**
- Drag-drop file upload
- File type validation
- Multi-file support
- Progress indication

**2. InvoiceQueue**
- Table view with sortable columns
- Grid view with cards
- Status badges
- Confidence indicators
- Pagination controls

**3. InvoiceCard**
- Compact card display
- Status badge
- Key invoice details
- Confidence indicator

**4. PDFViewer**
- PDF/image display (simplified)
- Zoom controls (+/-, fit-width)
- Page navigation
- Bounding box overlay (placeholder)

**5. FieldsPanel**
- Extracted fields display
- Confidence indicators
- Field-level actions (Accept/Query/Reject)
- Sections: Invoice Details, Buyer, Seller, Totals

**6. LineItemsTable**
- Editable table
- Add/remove rows
- Auto-calculation (quantity × unit price)
- Edit mode toggle

**7. ConfidenceIndicator**
- Color-coded badges
- Green (>90%): High confidence
- Yellow (70-90%): Medium confidence
- Red (<70%): Low confidence

**8. QueryRejectModal**
- Query/rejection form
- Comment input
- Recipient email field
- Validation

## 🚀 Deployment

### Prerequisites

1. **Database Migration**
```bash
cd /home/runner/work/ROSSUMXML/ROSSUMXML/backend
psql -U postgres -d rossumxml -f db/migrations/013_invoice_extraction_system.sql
```

2. **Backend Dependencies**
```bash
cd backend
npm install
```

3. **Frontend Dependencies**
```bash
cd frontend
npm install
```

### Environment Variables

Add to `backend/.env`:
```env
# HuggingFace API (for LayoutLMv3)
HUGGINGFACE_API_KEY=your_api_key_here

# Use local model instead of API
USE_LOCAL_MODEL=false

# File upload settings
MAX_FILE_SIZE=10485760  # 10MB
UPLOAD_DIR=/tmp/invoices
FILE_DELETION_DAYS=30   # GDPR compliance
```

### RBAC Configuration

The migration automatically adds these permissions:
- `invoice:upload`
- `invoice:review`
- `invoice:approve`
- `invoice:export`
- `invoice:query`
- `invoice:reject`
- `invoice:manage_vendors`

Permissions are granted to roles:
- **Admin:** All permissions
- **Developer:** upload, review, export, query
- **Viewer:** review only

### File Storage

**Development:**
- Files stored in `/tmp/invoices/`
- Auto-cleanup via GDPR schedule

**Production:**
- Use cloud storage (S3, Azure Blob, GCS)
- Implement encryption at rest
- Configure CDN for file serving
- Set up lifecycle policies for auto-deletion

## 🔒 Security & Compliance

### GDPR Compliance

1. **File Deletion**
   - Files auto-scheduled for deletion 30 days after upload
   - Stored only in temporary directory
   - Structured data retained for customs compliance

2. **Data Access**
   - Complete audit trail
   - User consent required
   - Right to erasure supported

### ISO 27001 Compliance

1. **Access Control**
   - RBAC-based permissions
   - Resource ownership validation
   - Audit logging for all actions

2. **Data Protection**
   - Encryption at rest (database level)
   - Encryption in transit (HTTPS/TLS)
   - Secure file upload validation

3. **Audit Trail**
   - All actions logged with:
     - User ID and name
     - Timestamp
     - Action type
     - Status changes
     - IP address
     - User agent

### Rate Limiting

Implement per-organization limits:
```javascript
// Trial tier
maxInvoicesPerMonth: 10

// Basic tier
maxInvoicesPerMonth: 50

// Pro tier
maxInvoicesPerMonth: 500

// Enterprise tier
maxInvoicesPerMonth: null  // Unlimited
```

## 📝 Known Limitations & Future Enhancements

### Current Limitations

1. **PDF.js Integration**
   - Simplified placeholder implementation
   - No actual PDF rendering with bounding boxes
   - Zoom controls are functional but document display is placeholder

2. **LayoutLMv3 Integration**
   - Pattern-based extraction as fallback
   - HuggingFace API integration is placeholder
   - No actual ML model inference

3. **Line Items Editing**
   - Frontend editing works
   - Backend persistence not implemented
   - Save operation logs to console only

4. **Model Fine-Tuning**
   - Training dataset preparation works
   - HuggingFace API submission is placeholder
   - No actual model deployment

5. **XLS Export**
   - Returns CSV format
   - Excel can open it, but it's not true .xls
   - For production, integrate 'xlsx' library

### Production Enhancements

#### 1. Full PDF.js Integration
```bash
npm install --save pdfjs-dist
```

Configure worker:
```javascript
import * as pdfjsLib from 'pdfjs-dist/build/pdf';
pdfjsLib.GlobalWorkerOptions.workerSrc = 
  `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.js`;
```

Implement rendering:
- Canvas-based page rendering
- SVG overlay for bounding boxes
- Zoom and pan functionality
- Page thumbnails sidebar

#### 2. LayoutLMv3 Integration
```javascript
const { HfInference } = require('@huggingface/inference');
const hf = new HfInference(process.env.HUGGINGFACE_API_KEY);

// Use document question answering
const result = await hf.documentQuestionAnswering({
  model: 'microsoft/layoutlmv3-base',
  inputs: {
    question: 'What is the invoice number?',
    image: imageBuffer
  }
});
```

#### 3. True XLS Export
```bash
npm install --save xlsx
```

```javascript
const XLSX = require('xlsx');

function exportAsXLS(invoiceData) {
  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.json_to_sheet(invoiceData);
  XLSX.utils.book_append_sheet(wb, ws, 'Invoice');
  return XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
}
```

#### 4. OCR for Images
```bash
npm install --save tesseract.js
```

```javascript
const Tesseract = require('tesseract.js');

async function extractTextFromImage(imagePath) {
  const { data: { text } } = await Tesseract.recognize(
    imagePath,
    'eng',
    { logger: m => console.log(m) }
  );
  return text;
}
```

#### 5. Cloud Storage
```javascript
// AWS S3 example
const AWS = require('aws-sdk');
const s3 = new AWS.S3();

async function uploadToS3(file, key) {
  return s3.upload({
    Bucket: process.env.S3_BUCKET,
    Key: key,
    Body: file,
    ServerSideEncryption: 'AES256'
  }).promise();
}
```

## 🧪 Testing

### Unit Tests
```bash
# Backend services
cd backend
npm test -- services/invoiceExtraction.service.test.js
npm test -- services/invoiceExport.service.test.js

# Frontend components
cd frontend
npm test -- src/components/invoice/
```

### Integration Tests
```bash
# API endpoints
cd backend
npm test -- routes/invoice.routes.test.js
```

### E2E Tests
```bash
# Full workflow
cd frontend
npm run test:e2e -- invoice-workflow.spec.js
```

## 📚 Additional Resources

- [Feature Specification](./INVOICE_EXTRACTION_FEATURE_SPEC.md)
- [HMRC CDS Schema Documentation](https://www.gov.uk/government/publications/customs-declaration-service-xml-schema)
- [LayoutLMv3 Paper](https://arxiv.org/abs/2204.08387)
- [HuggingFace API Documentation](https://huggingface.co/docs/api-inference/index)

## 🤝 Support

For questions or issues:
1. Check existing documentation
2. Review audit logs for debugging
3. Contact system administrator
4. Submit support ticket with:
   - Invoice ID
   - Error message
   - Steps to reproduce
   - Expected vs actual behavior
