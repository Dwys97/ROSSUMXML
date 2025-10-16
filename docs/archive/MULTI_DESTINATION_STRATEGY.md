# 🌐 Multi-Destination Software Strategy

**Date**: October 15, 2025  
**Current State**: System is functional but tightly coupled to CargoWise as destination  
**Strategic Goal**: Support multiple destination ERP/logistics systems (SAP, Oracle, Sage, etc.)

---

## 📊 Current Architecture Analysis

### ✅ What's Already Multi-Destination Ready

1. **Database Schema** ✅
   - `transformation_mappings.destination_schema_type` (VARCHAR 100) - supports any value
   - `transformation_mappings.destination_schema_xml` (TEXT) - stores any XML template
   - No hardcoded CargoWise references in schema

2. **Transformation Engine** ✅
   - `backend/index.js` transformation logic is **schema-agnostic**
   - Uses XPath and generic XML traversal (no CargoWise-specific code)
   - Collection mapping works for any repeating structure
   - Custom element mapping is universal

3. **Editor UI** ✅
   - Visual tree renderer works for any XML structure
   - Drag-and-drop mapping is schema-agnostic
   - File upload accepts any valid XML

### ❌ What's CargoWise-Coupled (Needs Refactoring)

1. **AI Mapping Service** ❌ **CRITICAL BLOCKER**
   - `backend/services/aiMapping.service.js` has **hardcoded CargoWise logic**:
     - Line 99-120: `extractElementNameFromPath()` - assumes `<Code>` wrapper elements (CargoWise pattern)
     - Line 283-310: Semantic synonym map includes CargoWise-specific terms (`CommercialInvoice`, `LineNo`, etc.)
     - Line 534-560: Prompt engineering mentions "CargoWise" and "LineItem" assumptions
     - **Impact**: AI suggestions will be inaccurate for SAP, Oracle, etc.

2. **Documentation & Examples** ❌
   - All examples reference CargoWise Universal Shipment format
   - Templates in `frontend-old/templates/` are CargoWise-only
   - API docs show only Rossum → CargoWise workflows

3. **UI Terminology** ⚠️ Minor
   - Some help text may reference CargoWise implicitly

---

## 🎯 Strategic Recommendation: Phased Approach

### **Phase 1: Schema Template Library (Foundation)** 
**Priority**: 🔴 HIGH  
**Effort**: 2-3 days  
**Impact**: Enables rapid multi-destination expansion

#### What to Build:
1. **Schema Repository** (`backend/templates/`)
   ```
   backend/templates/
   ├── sources/
   │   ├── rossum-invoice-export.xml
   │   ├── rossum-purchase-order.xml
   │   └── generic-invoice.xml
   └── destinations/
       ├── cargowise/
       │   ├── universal-shipment.xml
       │   ├── customs-declaration.xml
       │   └── metadata.json
       ├── sap/
       │   ├── idoc-invoice.xml
       │   └── metadata.json
       ├── oracle/
       │   ├── fusion-invoice.xml
       │   └── metadata.json
       └── sage/
           ├── x3-invoice.xml
           └── metadata.json
   ```

2. **Metadata Schema** (`metadata.json` example):
   ```json
   {
     "system_name": "CargoWise One",
     "system_code": "CW1",
     "schema_type": "UNIVERSAL_SHIPMENT",
     "version": "2011.11",
     "namespace": "http://www.cargowise.com/Schemas/Universal/2011/11",
     "description": "CargoWise Universal Shipment format for customs declarations",
     "common_use_cases": ["customs_import", "invoice_import"],
     "key_collections": [
       {
         "path": "Shipment > CommercialInfo > CommercialInvoiceLineCollection > CommercialInvoiceLine",
         "type": "line_item",
         "description": "Invoice line items"
       }
     ],
     "special_patterns": {
       "code_wrapper": true,
       "description": "Many elements wrapped in <Code> (e.g., <Currency><Code>GBP</Code></Currency>)"
     }
   }
   ```

3. **API Endpoint**: `GET /api/templates/destinations`
   ```json
   {
     "destinations": [
       {
         "id": "cw-universal-shipment",
         "name": "CargoWise Universal Shipment",
         "system": "CargoWise One",
         "category": "logistics",
         "template_path": "/templates/destinations/cargowise/universal-shipment.xml"
       },
       {
         "id": "sap-idoc-invoice",
         "name": "SAP IDoc Invoice",
         "system": "SAP ERP",
         "category": "erp",
         "template_path": "/templates/destinations/sap/idoc-invoice.xml"
       }
     ]
   }
   ```

4. **Frontend Template Picker** (Add to EditorPage):
   ```jsx
   <div className="template-selector">
     <h3>Or start from a template:</h3>
     <select onChange={handleTemplateSelect}>
       <option value="">-- Select Destination System --</option>
       <optgroup label="Logistics">
         <option value="cw-universal-shipment">CargoWise Universal Shipment</option>
         <option value="cw-customs">CargoWise Customs Declaration</option>
       </optgroup>
       <optgroup label="ERP Systems">
         <option value="sap-idoc">SAP IDoc Invoice</option>
         <option value="oracle-fusion">Oracle Fusion Financials</option>
         <option value="sage-x3">Sage X3 Invoice</option>
       </optgroup>
     </select>
   </div>
   ```

#### Benefits:
- ✅ Users can quickly start with industry-standard templates
- ✅ No more manual XML creation for common systems
- ✅ Template library becomes a **product differentiator**
- ✅ Foundation for intelligent AI suggestions (Phase 2)

---

### **Phase 2: AI Mapping Intelligence Overhaul** 
**Priority**: 🔴 HIGH  
**Effort**: 3-4 days  
**Impact**: AI works accurately for ANY destination system

#### Problem Statement:
Current AI service is **CargoWise-trained**. It will fail or produce low-quality suggestions for SAP, Oracle, etc.

#### Solution: Schema-Aware AI System

**Step 1: Extract Schema Metadata Service**
```javascript
// backend/services/schemaAnalyzer.service.js

/**
 * Analyze an XML schema to extract structural patterns
 * Works for ANY XML schema (CargoWise, SAP, Oracle, etc.)
 */
function analyzeSchema(xmlString) {
  const patterns = {
    namespaces: extractNamespaces(xmlString),
    wrapperPatterns: detectWrapperElements(xmlString), // e.g., <Code>, <Value>
    collectionPaths: findRepeatingElements(xmlString),
    commonFieldTypes: classifyFields(xmlString), // date, currency, quantity, etc.
    hierarchyDepth: calculateDepth(xmlString),
    namingConventions: detectNamingStyle(xmlString) // camelCase, PascalCase, snake_case
  };
  
  return {
    system_type: detectSystemType(patterns), // "CargoWise", "SAP IDoc", "Oracle", "Unknown"
    patterns: patterns,
    confidence: calculateConfidence(patterns)
  };
}

/**
 * Detect system type from XML patterns
 */
function detectSystemType(patterns) {
  // CargoWise signatures
  if (patterns.namespaces.includes('cargowise.com')) return 'CargoWise';
  if (patterns.wrapperPatterns.includes('Code') && 
      patterns.collectionPaths.some(p => p.includes('Collection'))) return 'CargoWise';
  
  // SAP IDoc signatures
  if (patterns.namespaces.includes('sap.com') || 
      /IDOC|E1[A-Z]{3}\d{2}/.test(xmlString)) return 'SAP IDoc';
  
  // Oracle signatures
  if (patterns.namespaces.includes('oracle.com') ||
      patterns.collectionPaths.some(p => p.includes('fusion'))) return 'Oracle Fusion';
  
  // Sage signatures
  if (patterns.wrapperPatterns.includes('PARAM') ||
      /SEED|CLOB/.test(xmlString)) return 'Sage X3';
  
  return 'Generic XML';
}
```

**Step 2: Dynamic AI Prompt Builder**
```javascript
// backend/services/aiMapping.service.js (REFACTORED)

async function generateMappingSuggestion(sourceNode, targetNodes, context = {}) {
  // 1. Analyze BOTH schemas dynamically
  const sourceAnalysis = analyzeSchema(context.sourceSchemaXml);
  const targetAnalysis = analyzeSchema(context.targetSchemaXml);
  
  // 2. Build system-specific semantic map
  const semanticMap = buildSemanticMap(sourceAnalysis.system_type, targetAnalysis.system_type);
  
  // 3. Extract wrapper patterns dynamically
  const targetWrappers = targetAnalysis.patterns.wrapperPatterns; // e.g., ['Code'] for CW, ['PARAM'] for Sage
  
  // 4. Build dynamic prompt
  const prompt = `
XML Schema Mapping Expert: Map source to best target candidate.

SOURCE SYSTEM: ${sourceAnalysis.system_type}
TARGET SYSTEM: ${targetAnalysis.system_type}

${targetAnalysis.system_type === 'CargoWise' ? 
  'NOTE: CargoWise wraps values in <Code> elements. Map to PARENT element, not Code.' : ''}

${targetAnalysis.system_type === 'SAP IDoc' ?
  'NOTE: SAP uses segment prefixes (E1, E2). Match segment names, not prefixes.' : ''}

${targetAnalysis.system_type === 'Oracle Fusion' ?
  'NOTE: Oracle uses verbose naming. Look for semantic meaning, not exact matches.' : ''}

SOURCE: "${sourceNode.name}"
Level: ${detectHierarchyLevel(sourceNode, sourceAnalysis)}

CANDIDATES (pre-scored):
${targetNodes.map(t => formatCandidate(t, targetAnalysis)).join('\n')}

SEMANTIC EQUIVALENTS (${sourceAnalysis.system_type} → ${targetAnalysis.system_type}):
${JSON.stringify(semanticMap, null, 2)}

RULES:
1. Match hierarchical level (header vs line item)
2. Consider system-specific naming conventions
3. ${targetWrappers.length > 0 ? `Ignore wrapper elements: ${targetWrappers.join(', ')}` : 'Match element names directly'}
4. Use semantic map for cross-system translations

Return JSON only: {"targetIndex": X, "confidence": Y, "reasoning": "..."}
`;

  // 5. Call Gemini with dynamic prompt
  return callGeminiAPI(prompt);
}

/**
 * Build semantic translation map between two systems
 */
function buildSemanticMap(sourceSystem, targetSystem) {
  const crossSystemMaps = {
    // Rossum → CargoWise
    'Rossum AI_CargoWise': {
      'invoice_id': ['InvoiceNumber', 'DocNumber', 'ReferenceNumber'],
      'vendor_name': ['SupplierName', 'VendorName', 'ConsignorName'],
      'line_item_description': ['Description', 'GoodsDescription', 'ItemDescription']
    },
    
    // Rossum → SAP
    'Rossum AI_SAP IDoc': {
      'invoice_id': ['BELNR', 'VBELN', 'DOCNUM'],
      'vendor_name': ['LIFNR', 'NAME1', 'VENDOR'],
      'line_item_description': ['ARKTX', 'MAKTX', 'DESCRIPTION']
    },
    
    // Rossum → Oracle
    'Rossum AI_Oracle Fusion': {
      'invoice_id': ['InvoiceNumber', 'SourceDocumentNumber', 'TransactionNumber'],
      'vendor_name': ['SupplierName', 'VendorName', 'SupplierSiteName'],
      'line_item_description': ['ItemDescription', 'LineDescription', 'ProductDescription']
    }
  };
  
  const mapKey = `${sourceSystem}_${targetSystem}`;
  return crossSystemMaps[mapKey] || {};
}
```

**Step 3: Training Data Collection**
```javascript
// Log actual mappings for machine learning
async function logMappingDecision(sourceNode, targetNode, accepted, userId) {
  await db.query(`
    INSERT INTO ai_training_data (
      user_id, source_system, target_system,
      source_path, target_path, 
      was_accepted, confidence_score
    ) VALUES ($1, $2, $3, $4, $5, $6, $7)
  `, [userId, sourceSystem, targetSystem, sourcePath, targetPath, accepted, confidence]);
}
```

#### Benefits:
- ✅ AI works accurately for **any** destination system
- ✅ No manual semantic maps to maintain
- ✅ Self-improving through user feedback
- ✅ Can detect and adapt to custom XML schemas

---

### **Phase 3: Multi-Destination UI Enhancements**
**Priority**: 🟡 MEDIUM  
**Effort**: 2 days  
**Impact**: Better UX for multi-system workflows

#### Features:
1. **System Badge** in Editor
   ```jsx
   <div className="schema-header">
     <h3>Target Schema</h3>
     <span className="system-badge cargowise">CargoWise One</span>
   </div>
   ```

2. **Smart Validation**
   ```javascript
   // Warn if mixing incompatible systems
   if (sourceSystem === 'Rossum AI' && targetSystem === 'SAP IDoc') {
     showWarning('SAP IDoc requires specific field formats. Review mapping carefully.');
   }
   ```

3. **System-Specific Mapping Tips**
   ```jsx
   {targetSystem === 'CargoWise' && (
     <InfoBox>
       💡 Tip: CargoWise uses <Code> wrappers. Map to Currency, not Currency > Code.
     </InfoBox>
   )}
   ```

---

### **Phase 4: Marketplace & Community Templates** (Optional)
**Priority**: 🟢 LOW (Future Revenue Stream)  
**Effort**: 1-2 weeks  
**Impact**: Product differentiation + revenue

#### Concept:
- Users can **publish** mapping templates to marketplace
- Pre-built "Rossum → SAP" mappings available for purchase ($49)
- Community voting on quality
- Verified templates by ROSSUMXML team

---

## 🚀 Implementation Roadmap

### **Week 1: Foundation (Phase 1)**
- [ ] Day 1-2: Create schema template library structure
- [ ] Day 2-3: Add 3 destination systems (CargoWise, SAP, Oracle)
- [ ] Day 3: Build template picker UI
- [ ] Day 4: Add template metadata API endpoint
- [ ] Day 5: Test with real SAP/Oracle schemas

### **Week 2: AI Intelligence (Phase 2)**
- [ ] Day 6-7: Build schema analyzer service
- [ ] Day 7-8: Refactor AI prompt generator (remove CargoWise hardcoding)
- [ ] Day 8-9: Test AI with SAP, Oracle, Sage schemas
- [ ] Day 9-10: Build cross-system semantic maps
- [ ] Day 10: A/B test AI accuracy (CargoWise vs SAP)

### **Week 3: Polish (Phase 3)**
- [ ] Day 11-12: Add system badges and validation
- [ ] Day 12-13: System-specific help tips
- [ ] Day 13: Update documentation
- [ ] Day 14: End-to-end testing (Rossum → 4 different systems)
- [ ] Day 15: User acceptance testing

---

## 📝 Database Schema Changes (Minimal)

### New Table: `schema_templates`
```sql
CREATE TABLE IF NOT EXISTS schema_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    system_name VARCHAR(255) NOT NULL, -- "CargoWise One", "SAP ERP"
    system_code VARCHAR(50) NOT NULL,  -- "CW1", "SAP"
    schema_type VARCHAR(100) NOT NULL, -- "UNIVERSAL_SHIPMENT", "IDOC_INVOICE"
    category VARCHAR(50) NOT NULL,     -- "logistics", "erp", "accounting"
    template_xml TEXT NOT NULL,
    metadata_json TEXT,                -- Store metadata.json
    is_public BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_system_schema UNIQUE(system_code, schema_type)
);

CREATE INDEX idx_templates_category ON schema_templates(category);
CREATE INDEX idx_templates_system ON schema_templates(system_code);
```

### Enhance Existing Table:
```sql
-- Add detected system type to mappings
ALTER TABLE transformation_mappings
ADD COLUMN IF NOT EXISTS detected_source_system VARCHAR(100),
ADD COLUMN IF NOT EXISTS detected_destination_system VARCHAR(100);
```

---

## 🎯 Success Metrics

After implementation, measure:
1. **AI Accuracy by System**:
   - CargoWise: 85%+ confidence average
   - SAP IDoc: 75%+ confidence average
   - Oracle Fusion: 70%+ confidence average
   
2. **Template Usage**:
   - 60%+ of users start with templates (vs manual upload)
   - Template library has 10+ systems within 6 months

3. **User Feedback**:
   - "Works with my SAP system!" testimonials
   - Reduced support tickets about "Why doesn't AI work?"

---

## 💡 Quick Win: Immediate Action (1 Day)

**Goal**: Make system work TODAY for non-CargoWise users

**Steps**:
1. Add configuration flag to disable CargoWise-specific AI logic
   ```javascript
   // env.json
   {
     "AI_GENERIC_MODE": "true" // Disables CargoWise assumptions
   }
   ```

2. Update AI prompt to be system-agnostic
   ```javascript
   if (process.env.AI_GENERIC_MODE === 'true') {
     // Skip Code wrapper extraction
     // Use generic semantic synonyms only
   }
   ```

3. Add UI warning:
   ```jsx
   <Alert type="info">
     AI suggestions are optimized for CargoWise. 
     For other systems, review suggestions carefully.
   </Alert>
   ```

This gives you **breathing room** while you implement the full multi-destination strategy.

---

## 🤔 Decision Point: What to Do Next?

**Option A: Quick Win (1 day)**
- Add "generic mode" toggle to AI
- Update docs to say "CargoWise optimized, others supported"
- Ship today, refactor later

**Option B: Foundation First (1 week)**
- Build template library (Phase 1)
- Ship with 3-4 destination systems
- AI stays CargoWise-focused for now

**Option C: AI Overhaul (2 weeks)**
- Refactor AI to be system-agnostic (Phase 2)
- Test with multiple systems
- Ship "Multi-System AI" as major feature

**My Recommendation**: **Option B (Foundation First)**
- Template library has immediate user value
- Easier to implement than AI refactor
- Sets foundation for everything else
- Can market as "Multi-Destination Support" right away

What do you think? Should we start with the template library, or do you want the AI fixed first?
