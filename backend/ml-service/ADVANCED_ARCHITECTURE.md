# Advanced ML Service Architecture

## 🚀 Next-Generation Invoice Extraction Pipeline

### Components:

1. **PaddleOCR 3.0 with PP-StructureV3**
   - Latest layout analysis engine
   - Table detection and extraction
   - Document structure understanding

2. **Surya OCR**
   - Layout-aware text extraction
   - Better handling of complex layouts
   - Lightweight and fast

3. **GLM-4-Flash (Hi-3 Mini)**
   - Zhipu AI's efficient model
   - Document understanding
   - Field extraction

4. **RAGFlow**
   - Document retrieval and indexing
   - Context-aware extraction
   - Historical data learning

5. **Gemini 2.0 Flash**
   - Validation layer
   - Missing field extraction (RAG)
   - Quality assurance

### Installation Requirements:

```bash
# PaddleOCR 3.0
pip install paddlepaddle==3.0.0
pip install paddleocr==3.0.0

# Surya OCR
pip install surya-ocr>=0.4.14

# GLM-4 (Zhipu AI SDK)
pip install zhipuai

# RAGFlow dependencies
pip install ragflow-sdk
pip install chromadb  # Vector database
pip install sentence-transformers  # Embeddings

# Already installed
pip install google-generativeai
```

### Architecture Flow:

```
Input PDF/Image
     ↓
[1] PaddleOCR 3.0 PP-StructureV3
    - Layout detection
    - Table extraction
    - Region classification
     ↓
[2] Surya OCR
    - Text extraction per region
    - Preserve layout structure
     ↓
[3] RAGFlow Document Indexing
    - Create embeddings
    - Store in vector DB
    - Retrieve similar historical invoices
     ↓
[4] GLM-4-Flash Extraction
    - Use RAG context
    - Extract structured fields
    - High-speed inference
     ↓
[5] Gemini Validation
    - Validate extracted fields
    - Fill missing data via RAG
    - Quality assurance
     ↓
Final Output (GDPR-filtered)
```

### API Endpoints:

- `POST /extract-advanced` - Full pipeline with all models
- `POST /extract-paddle` - PaddleOCR 3.0 only
- `POST /extract-surya` - Surya OCR only
- `POST /extract-glm` - GLM-4-Flash only
- `POST /validate-gemini` - Gemini validation only

### Configuration:

```json
{
  "paddle": {
    "version": "3.0",
    "use_structure_v3": true,
    "enable_table_detection": true
  },
  "surya": {
    "enabled": true,
    "model": "layout-aware"
  },
  "glm4": {
    "api_key": "YOUR_ZHIPU_KEY",
    "model": "glm-4-flash",
    "temperature": 0.1
  },
  "ragflow": {
    "enabled": true,
    "vector_db": "chromadb",
    "embedding_model": "all-MiniLM-L6-v2"
  },
  "gemini": {
    "api_key": "YOUR_GEMINI_KEY",
    "model": "gemini-2.0-flash-exp",
    "enable_rag": true
  }
}
```

### Performance Estimates:

| Component | Time (CPU) | Accuracy |
|-----------|------------|----------|
| PaddleOCR 3.0 | 2-4s | 95%+ |
| Surya OCR | 1-3s | 94%+ |
| RAGFlow Retrieval | 0.5-1s | N/A |
| GLM-4-Flash | 1-2s | 92%+ |
| Gemini Validation | 2-4s | 98%+ |
| **Total** | **6-14s** | **97%+** |

### Next Steps:

1. Install dependencies
2. Implement PaddleOCR 3.0 integration
3. Add Surya OCR
4. Integrate GLM-4-Flash
5. Set up RAGFlow
6. Connect all components
7. Test with sample invoices
8. Deploy

Would you like me to proceed with the implementation?
