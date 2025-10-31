# 📄 Invoice Extraction & Annotation Feature - Complete Specification

**Project:** ROSSUMXML/SCHEMABRIDGE  
**Feature:** AI-Powered Invoice Data Extraction with LayoutLMv3  
**Date:** October 31, 2025  
**Status:** 🚧 Planning Phase

---

## 🎯 Executive Summary

Add a comprehensive invoice extraction and annotation system to ROSSUMXML, enabling users to upload commercial invoices (PDF/images), automatically extract customs data using LayoutLMv3, review and correct extractions with a visual annotation interface, and export validated data as XML/CSV/XLS for customs declarations (HMRC CDS Schema compliance).

---

## 📋 Requirements Overview

### 1. **Workflow & Queue Management**
- ✅ Upload commercial invoices (PDF, PNG, JPG)
- ✅ Document queue with statuses:
  - `To Review` - Newly uploaded, awaiting review
  - `Reviewing` - Currently being reviewed by user
  - `Queried` - Flagged with questions (with comments + recipient email)
  - `Postponed` - Temporarily set aside
  - `Rejected` - Rejected with reason (with comments + recipient email)
  - `Exported` - Approved and exported as XML/CSV/XLS
- ✅ Organization-based document segregation (multi-tenant)
- ✅ RBAC-based access control

### 2. **LayoutLMv3 Integration**
- **Model Selection:**
  - **Primary:** Use **Microsoft's LayoutLMv3** via HuggingFace Inference API (Free tier: 30,000 requests/month)
  - **Fallback:** Local inference with LayoutLMv3-base model (GDPR compliant)
  - **Fine-tuning:** Store corrections for continuous learning (self-improving model)

- **GDPR & ISO 27001 Compliance:**
  - Process documents in temporary storage (auto-delete after 30 days)
  - Store only extracted structured data in PostgreSQL
  - Encrypt data at rest and in transit
  - Audit trail for all data access/modifications
  - User consent for data processing

### 3. **Data Extraction Requirements**

**Customs Data Fields:**
- ✅ **Parties:**
  - Buyer (Importer) - Full Name, Address, Country, VAT/Tax ID
  - Seller (Exporter) - Full Name, Address, Country, VAT/Tax ID
  
- ✅ **Invoice Details:**
  - Invoice Number
  - Invoice Date
  - Currency
  - Incoterms (FOB, CIF, DAP, etc.)
  
- ✅ **Line Items (Goods):**
  - Description of Goods
  - HS Code (Harmonized System Code)
  - Country of Origin
  - Quantity
  - Unit Price
  - Total Value
  - Net Weight (per item)
  - Gross Weight (per item)
  
- ✅ **Totals:**
  - Subtotal
  - Tax/VAT Amount
  - Total Invoice Amount
  - Total Gross Weight
  - Total Net Weight

### 4. **Annotation Interface Features**

**Visual Components:**
- ✅ **PDF Viewer (Left Panel):**
  - Embedded PDF.js renderer
  - Floating zoom controls (+/- buttons)
  - Auto-zoom on field selection (highlight bounding box)
  - Multi-page navigation for large invoices
  - Page thumbnails sidebar
  
- ✅ **Fields Panel (Right Panel):**
  - Extracted fields with confidence scores
  - Color-coded confidence indicators:
    - 🟢 Green (>90%) - High confidence
    - 🟡 Yellow (70-90%) - Medium confidence
    - 🔴 Red (<70%) - Low confidence (requires review)
  - Action buttons per field: ✓ Accept | ⚠ Query | ✗ Reject
  
- ✅ **Bounding Boxes:**
  - Adjustable/draggable bounding boxes on PDF
  - Click field → highlights corresponding box on PDF
  - Adjust box → submit correction for fine-tuning (background job)
  
- ✅ **Line Items Table:**
  - Editable table for itemized goods
  - Add/remove rows
  - Automatic HS Code suggestions
  - Weight/value calculations

### 5. **Learning & Fine-Tuning**

- ✅ **Self-Learning System:**
  - Store user corrections in `invoice_corrections` table
  - Track vendor-specific patterns (vendor fingerprinting)
  - When same vendor invoice uploaded → use historical corrections
  - Background job: Aggregate corrections → submit for model fine-tuning
  
- ✅ **Vendor Recognition:**
  - Extract vendor logo/name → create vendor profile
  - Link invoices to vendor
  - Apply vendor-specific extraction templates
  - Accuracy improves with each vendor invoice

### 6. **Export & Transformation**

- ✅ **Export Formats:**
  - **XML** - HMRC CDS Schema compliant
  - **CSV** - Customs declaration format
  - **XLS** - Excel format with proper formatting
  
- ✅ **Transformation Pipeline:**
  1. User clicks "Export as XML"
  2. Validate extracted data against HMRC CDS Schema
  3. Use existing transformation engine (backend default source)
  4. Generate XML/CSV/XLS files
  5. Store in database + make available for FTP upload
  
- ✅ **Ad-hoc Transformation:**
  - Users can still use frontend Transformer page for other XML schemas
  - Invoice extraction is a separate workflow

### 7. **Audit Trail & Comments**

- ✅ **Audit Logging:**
  - Track all actions: Upload, Review, Accept, Query, Reject, Export
  - Log user ID, timestamp, action, document ID
  - Store in `invoice_audit_log` table
  
- ✅ **Query/Reject Modal:**
  - When user clicks Query/Reject:
    - Show modal with:
      - Text box for comments (required)
      - Email field for recipient (optional)
      - Urgency level (Low/Medium/High)
    - Store comment in database
    - Send email notification to recipient
    - Update invoice status

### 8. **Storage Strategy**

- ✅ **Temporary File Storage:**
  - Upload commercial invoices to `/tmp/invoices/` directory
  - Filename: `{organization_id}/{invoice_id}_{timestamp}.pdf`
  - Auto-delete after 30 days (GDPR compliance)
  - Periodic cleanup cron job
  
- ✅ **PostgreSQL Storage:**
  - Store extracted structured data only
  - Tables:
    - `invoices` - Invoice metadata
    - `invoice_parties` - Buyer/Seller info
    - `invoice_line_items` - Goods details
    - `invoice_corrections` - User corrections for learning
    - `invoice_audit_log` - Audit trail
    - `vendor_profiles` - Vendor patterns

### 9. **Performance & Scaling**

- ✅ **Current Capacity:** 100 invoices/day
- ✅ **Future Scaling:**
  - Implement job queue (Redis + Bull)
  - Separate ML inference microservice (Python FastAPI)
  - Load balancing for ML endpoint
  - Horizontal scaling with Kubernetes
  
- ✅ **Rate Limiting:**
  - Trial users: 10 invoices/month
  - Basic tier: 50 invoices/month
  - Professional tier: 500 invoices/month
  - Enterprise tier: Unlimited

### 10. **RBAC & Subscription Control**

- ✅ **New Permissions:**
  - `invoice:upload` - Upload invoices
  - `invoice:review` - Review and annotate
  - `invoice:approve` - Approve for export
  - `invoice:export` - Export as XML/CSV/XLS
  - `invoice:delete` - Delete invoices
  - `invoice:admin` - Manage invoice settings
  
- ✅ **Subscription Tiers:**
  - **Trial:** 10 invoices/month, basic features
  - **Basic:** 50 invoices/month, all features
  - **Professional:** 500 invoices/month, priority support
  - **Enterprise:** Unlimited, dedicated ML instance, SLA

---

## 🏗️ Technical Architecture

### **Backend Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend (React)                      │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐ │
│  │ Invoice Upload │  │ Review Queue   │  │ Annotation UI  │ │
│  └────────────────┘  └────────────────┘  └────────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  Backend (Node.js + Express)                 │
│  ┌──────────────────────────────────────────────────────────┤
│  │ Invoice Routes                                            │
│  │  - POST /api/invoices/upload                              │
│  │  - GET /api/invoices (list with filters)                 │
│  │  - GET /api/invoices/:id (details)                        │
│  │  - PUT /api/invoices/:id/status                           │
│  │  - POST /api/invoices/:id/extract (trigger ML)           │
│  │  - PUT /api/invoices/:id/correct (submit correction)     │
│  │  - POST /api/invoices/:id/export (XML/CSV/XLS)           │
│  └──────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────────────────────────────────────────────┤
│  │ ML Service Integration                                    │
│  │  - HuggingFace Inference API (Primary)                   │
│  │  - Local LayoutLMv3 Model (Fallback)                     │
│  │  - Fine-tuning Job Queue (Redis + Bull)                  │
│  └──────────────────────────────────────────────────────────┤
└──────────────────────┬────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    PostgreSQL Database                       │
│  - invoices                                                  │
│  - invoice_parties                                           │
│  - invoice_line_items                                        │
│  - invoice_corrections                                       │
│  - invoice_audit_log                                         │
│  - vendor_profiles                                           │
└─────────────────────────────────────────────────────────────┘
```

### **ML Pipeline**

```
1. User uploads PDF
   ↓
2. Store in /tmp/invoices/
   ↓
3. Convert PDF to images (pdf2image)
   ↓
4. Send to LayoutLMv3 API
   ↓
5. Parse JSON response → extract fields
   ↓
6. Store in PostgreSQL
   ↓
7. Render annotation UI
   ↓
8. User corrects → store correction
   ↓
9. Background job: Aggregate corrections → fine-tune model
```

---

## 📂 Database Schema

### **New Tables**

```sql
-- Invoices table
CREATE TABLE invoices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id),
    user_id UUID REFERENCES users(id),
    vendor_id UUID REFERENCES vendor_profiles(id),
    
    -- File info
    filename VARCHAR(255) NOT NULL,
    file_path TEXT,
    file_size INTEGER,
    page_count INTEGER,
    
    -- Status
    status VARCHAR(50) DEFAULT 'to_review', -- to_review, reviewing, queried, postponed, rejected, exported
    
    -- Metadata
    invoice_number VARCHAR(100),
    invoice_date DATE,
    currency VARCHAR(10),
    total_amount DECIMAL(15,2),
    
    -- ML
    extraction_confidence DECIMAL(5,2), -- Average confidence score
    model_version VARCHAR(50),
    
    -- Timestamps
    uploaded_at TIMESTAMP DEFAULT NOW(),
    reviewed_at TIMESTAMP,
    exported_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Invoice parties (buyer/seller)
CREATE TABLE invoice_parties (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID REFERENCES invoices(id) ON DELETE CASCADE,
    party_type VARCHAR(20), -- 'buyer' or 'seller'
    
    name TEXT,
    address TEXT,
    city VARCHAR(100),
    country VARCHAR(100),
    postal_code VARCHAR(20),
    vat_number VARCHAR(50),
    
    -- Bounding box for annotation
    bbox_page INTEGER,
    bbox_x DECIMAL(10,4),
    bbox_y DECIMAL(10,4),
    bbox_width DECIMAL(10,4),
    bbox_height DECIMAL(10,4),
    
    confidence DECIMAL(5,2),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Invoice line items (goods)
CREATE TABLE invoice_line_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID REFERENCES invoices(id) ON DELETE CASCADE,
    line_number INTEGER,
    
    description TEXT,
    hs_code VARCHAR(20),
    country_of_origin VARCHAR(100),
    quantity DECIMAL(15,3),
    unit_of_measure VARCHAR(20),
    unit_price DECIMAL(15,2),
    total_value DECIMAL(15,2),
    net_weight DECIMAL(15,3),
    gross_weight DECIMAL(15,3),
    
    -- Bounding box
    bbox_page INTEGER,
    bbox_x DECIMAL(10,4),
    bbox_y DECIMAL(10,4),
    bbox_width DECIMAL(10,4),
    bbox_height DECIMAL(10,4),
    
    confidence DECIMAL(5,2),
    created_at TIMESTAMP DEFAULT NOW()
);

-- User corrections for learning
CREATE TABLE invoice_corrections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID REFERENCES invoices(id),
    user_id UUID REFERENCES users(id),
    
    field_name VARCHAR(100), -- e.g., 'buyer_name', 'line_item_hs_code'
    field_path TEXT, -- JSON path if nested
    
    original_value TEXT,
    corrected_value TEXT,
    
    bbox_adjustment JSONB, -- Store bbox changes
    
    applied_to_training BOOLEAN DEFAULT FALSE,
    training_job_id VARCHAR(100),
    
    created_at TIMESTAMP DEFAULT NOW()
);

-- Vendor profiles for pattern recognition
CREATE TABLE vendor_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id),
    
    vendor_name VARCHAR(255),
    vendor_country VARCHAR(100),
    
    -- Pattern templates
    invoice_template JSONB, -- Store field positions/patterns
    logo_hash VARCHAR(64), -- For vendor recognition
    
    invoice_count INTEGER DEFAULT 0,
    accuracy_rate DECIMAL(5,2), -- How accurate extractions are
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Audit log for invoice actions
CREATE TABLE invoice_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    invoice_id UUID REFERENCES invoices(id),
    user_id UUID REFERENCES users(id),
    
    action VARCHAR(50), -- upload, review, query, reject, approve, export
    status_from VARCHAR(50),
    status_to VARCHAR(50),
    
    comment TEXT,
    recipient_email VARCHAR(255),
    
    ip_address INET,
    user_agent TEXT,
    
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_invoices_org ON invoices(organization_id);
CREATE INDEX idx_invoices_status ON invoices(status);
CREATE INDEX idx_invoices_vendor ON invoices(vendor_id);
CREATE INDEX idx_invoice_parties_invoice ON invoice_parties(invoice_id);
CREATE INDEX idx_invoice_line_items_invoice ON invoice_line_items(invoice_id);
CREATE INDEX idx_invoice_corrections_invoice ON invoice_corrections(invoice_id);
CREATE INDEX idx_invoice_audit_invoice ON invoice_audit_log(invoice_id);
```

---

## 🎨 Frontend Components

### **New Pages**

1. **`/invoice-workflow`** - Main invoice management page
   - Document list (left sidebar)
   - Queue table (center)
   - Filters and search
   
2. **`/invoice-workflow/:id`** - Annotation page
   - PDF viewer (left)
   - Fields panel (right)
   - Bounding box overlay
   
3. **`/invoice-settings`** - Invoice module settings (admin only)
   - ML model configuration
   - Subscription limits
   - Auto-export settings

### **New Components**

```
frontend/src/pages/
├── InvoiceWorkflowPage.jsx           # Main queue page
├── InvoiceAnnotationPage.jsx         # Annotation interface
└── InvoiceSettingsPage.jsx           # Admin settings

frontend/src/components/invoice/
├── InvoiceUploader.jsx                # Drag-drop uploader
├── InvoiceQueue.jsx                   # Queue table with filters
├── InvoiceCard.jsx                    # Invoice card in list
├── PDFViewer.jsx                      # PDF.js viewer wrapper
├── FieldsPanel.jsx                    # Right panel with extracted fields
├── BoundingBoxOverlay.jsx             # SVG overlay for bounding boxes
├── LineItemsTable.jsx                 # Editable line items table
├── QueryRejectModal.jsx               # Modal for comments
├── ConfidenceIndicator.jsx            # Color-coded confidence badge
└── ExportOptionsModal.jsx             # Choose XML/CSV/XLS
```

---

## 🚀 Implementation Phases

### **Phase 1: Foundation (Week 1-2)**
- [ ] Database schema migration
- [ ] Backend routes structure
- [ ] File upload endpoint
- [ ] Basic queue page UI
- [ ] RBAC permissions setup

### **Phase 2: ML Integration (Week 3-4)**
- [ ] HuggingFace API integration
- [ ] LayoutLMv3 response parser
- [ ] Field extraction logic
- [ ] Vendor recognition system
- [ ] Correction storage

### **Phase 3: Annotation UI (Week 5-6)**
- [ ] PDF viewer with PDF.js
- [ ] Fields panel with confidence scores
- [ ] Bounding box overlay
- [ ] Drag-to-adjust boxes
- [ ] Line items table editor

### **Phase 4: Workflow & Export (Week 7-8)**
- [ ] Status transitions
- [ ] Query/Reject modal
- [ ] Email notifications
- [ ] XML export (HMRC CDS schema)
- [ ] CSV/XLS export
- [ ] Transformation engine integration

### **Phase 5: Learning & Optimization (Week 9-10)**
- [ ] Fine-tuning job queue
- [ ] Vendor pattern matching
- [ ] Accuracy tracking
- [ ] Performance optimization
- [ ] Rate limiting

### **Phase 6: Testing & Deployment (Week 11-12)**
- [ ] Unit tests
- [ ] Integration tests
- [ ] E2E tests (Playwright)
- [ ] Security audit
- [ ] Documentation
- [ ] Deployment

---

## 📚 API Endpoints

### **Invoice Management**

```javascript
// Upload invoice
POST /api/invoices/upload
Headers: Authorization: Bearer {token}
Body: multipart/form-data { file: File, metadata: {...} }
Response: { invoice_id, status, extraction_job_id }

// List invoices
GET /api/invoices?status=to_review&page=1&limit=20
Response: { invoices: [...], pagination: {...} }

// Get invoice details
GET /api/invoices/:id
Response: { invoice: {...}, parties: [...], line_items: [...] }

// Update invoice status
PUT /api/invoices/:id/status
Body: { status: 'queried', comment: '...', recipient_email: '...' }
Response: { success: true }

// Submit correction
PUT /api/invoices/:id/correct
Body: { field_name: '...', corrected_value: '...', bbox: {...} }
Response: { success: true, training_queued: true }

// Export invoice
POST /api/invoices/:id/export
Body: { format: 'xml' | 'csv' | 'xls' }
Response: { download_url: '...', file_path: '...' }

// Trigger extraction
POST /api/invoices/:id/extract
Response: { job_id: '...', status: 'processing' }

// Get extraction result
GET /api/invoices/:id/extraction
Response: { fields: {...}, confidence: 0.95, status: 'completed' }
```

---

## 🔒 Security & Compliance

### **GDPR Compliance**
- ✅ Data minimization (only structured data stored permanently)
- ✅ Right to erasure (delete invoice + file)
- ✅ Data portability (export as CSV/JSON)
- ✅ Consent management (terms acceptance)
- ✅ Data encryption (at rest + in transit)
- ✅ Access logging (audit trail)

### **ISO 27001 Controls**
- ✅ **A.9.2** - User access management (RBAC)
- ✅ **A.9.4** - System access control (permissions)
- ✅ **A.12.3** - Backup (database backups)
- ✅ **A.12.4** - Logging and monitoring (audit logs)
- ✅ **A.13.1** - Network security (HTTPS, TLS)
- ✅ **A.14.1** - Security requirements (input validation)

---

## 📊 Success Metrics

- **Extraction Accuracy:** >90% average confidence
- **User Corrections:** <5% per invoice
- **Processing Time:** <30 seconds per invoice
- **Vendor Recognition:** >85% accuracy after 5 invoices
- **User Adoption:** 50+ invoices processed/week
- **Export Success Rate:** >99%

---

## 📝 Next Steps

1. **Review & Approve Specification**
2. **Create Database Migration**
3. **Set up Backend Routes**
4. **Implement ML Integration**
5. **Build Annotation UI**
6. **Test End-to-End**
7. **Deploy to Production**

---

**Estimated Timeline:** 10-12 weeks  
**Priority:** High  
**Dependencies:** HuggingFace API access, PDF.js library, HMRC CDS schema documentation

---

**Document Owner:** Development Team  
**Last Updated:** October 31, 2025
