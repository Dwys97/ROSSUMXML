# PDF Viewer Fix - Invalid PDF Structure Error

## Problem
PDF.js was throwing "Invalid PDF structure" errors with warnings about invalid hex strings. The issue was that `PDFViewer` was trying to load PDF files using local file paths instead of fetching them through an API endpoint.

## Root Cause
- `InvoiceAnnotationPage` was passing `invoice.file_path` (server-side file path) directly to `PDFViewer`
- PDF.js cannot load files from server file paths in a browser environment
- Files need to be served through HTTP as binary data (ArrayBuffer)

## Solution

### 1. Backend Changes (`backend/index.js`)
**Added new endpoint:** `GET /api/invoices/{id}/file`

```javascript
// Get invoice file (PDF/Image download)
if (path && path.match(/^\/api\/invoices\/[0-9a-fA-F-]+\/file$/) && 
    (event.httpMethod === 'GET' || event.requestContext?.http?.method === 'GET')) {
    // Verify JWT authentication
    // Fetch file_path, file_type, file_name from database
    // Read file from disk using fs.readFileSync()
    // Return file as base64-encoded binary with proper Content-Type headers
}
```

**Key features:**
- JWT authentication required
- Reads file from server filesystem
- Returns binary data with proper `Content-Type` header
- Supports both PDF and image files
- Sets `Content-Disposition: inline` for browser rendering

### 2. Frontend Changes

#### `PDFViewer.jsx`
**Changed props:**
- `filePath` → `invoiceId` (now accepts invoice UUID instead of file path)

**Updated PDF loading logic:**
```javascript
const loadPDF = async () => {
    const token = localStorage.getItem('authToken');
    const response = await fetch(`/api/invoices/${invoiceId}/file`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    
    const arrayBuffer = await response.arrayBuffer();
    const loadingTask = pdfjsLib.getDocument({ data: arrayBuffer });
    const pdf = await loadingTask.promise;
    // ... render PDF
};
```

**Image preview fix:**
- Non-PDF files (images) now also use the `/file` endpoint
- Dynamic URL generation: `/api/invoices/${invoiceId}/file`

#### `InvoiceAnnotationPage.jsx`
**Updated PDFViewer usage:**
```jsx
<PDFViewer
    invoiceId={id}              // Changed from filePath
    fileName={invoice.file_name}
    fileType={invoice.file_type}
    selectedField={selectedField}
/>
```

## Technical Details

### Why ArrayBuffer?
PDF.js requires binary data in one of these formats:
- **ArrayBuffer** (preferred for API fetches)
- URL (not possible for server-side files)
- Uint8Array
- Base64 string (less efficient)

### Security
- Endpoint requires JWT authentication
- File access is restricted to authenticated users
- UUID-based file identification prevents path traversal attacks

## Testing Checklist
✅ Backend builds successfully (`sam build`)  
✅ Frontend builds without errors (`npm run build`)  
✅ Backend serves files at `/api/invoices/{uuid}/file`  
✅ PDF.js loads PDF as ArrayBuffer  
✅ No "Invalid PDF structure" errors  
✅ No hex string warnings  

## Files Modified
1. `backend/index.js` - Added file download endpoint
2. `frontend/src/components/invoice/PDFViewer.jsx` - Changed to fetch via API
3. `frontend/src/pages/InvoiceAnnotationPage.jsx` - Updated props

## Result
✅ PDF files now load correctly in the browser  
✅ Multi-page navigation works  
✅ Zoom controls functional  
✅ No console errors or warnings  
✅ Production-ready implementation  
