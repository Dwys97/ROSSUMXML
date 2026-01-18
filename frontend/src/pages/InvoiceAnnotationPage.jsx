import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useSocket } from '../contexts/SocketContext';
import PDFViewer from '../components/invoice/PDFViewer';
import FieldsPanel from '../components/invoice/FieldsPanel';
import LineItemsTable from '../components/invoice/LineItemsTable';
import QueryRejectModal from '../components/invoice/QueryRejectModal';
import BoundingBoxOverlay from '../components/invoice/BoundingBoxOverlay';
import * as correctionsApi from '../services/correctionsApi';
import styles from './InvoiceAnnotationPage.module.css';

const InvoiceAnnotationPage = () => {
    const { id } = useParams();
    const { getToken } = useAuth();
    const { joinInvoice, leaveInvoice, onFieldUpdate, onExtractionComplete, onExtractionProgress, onOCRPreview, connected } = useSocket();
    const navigate = useNavigate();
    
    // Add force refresh mechanism
    const [refreshTrigger, setRefreshTrigger] = useState(0);

    const [invoice, setInvoice] = useState(null);
    const [parties, setParties] = useState([]);
    const [lineItems, setLineItems] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [selectedField, setSelectedField] = useState(null);
    const [showQueryModal, setShowQueryModal] = useState(false);
    const [modalAction, setModalAction] = useState(null); // 'query' or 'reject'
    const [extracting, setExtracting] = useState(false);
    const [extractionProgress, setExtractionProgress] = useState(0);
    const [extractionStage, setExtractionStage] = useState('Initializing...');
    const extractionProgressRef = useRef(0);
    const [ocrPreview, setOcrPreview] = useState(null); // OCR text preview while waiting for LLM
    const [extractedFields, setExtractedFields] = useState({}); // Progressive field updates
    const [boundingBoxes, setBoundingBoxes] = useState({}); // Field bounding boxes
    const [corrections, setCorrections] = useState([]); // Pending corrections to submit
    const [showFieldManager, setShowFieldManager] = useState(false); // Field manager modal
    
    // Fetch invoice details
    const fetchInvoiceDetails = React.useCallback(async (isBackground = false) => {
        if (!isBackground) {
            setLoading(true);
        }
        setError(null);
        
        try {
            console.log(`[Fetch] Loading invoice ${id} (isBackground=${isBackground})...`);
            // Add cache busting
            const response = await fetch(`/api/invoices/${id}?t=${Date.now()}`, {
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to fetch invoice details');
            }
            
            const data = await response.json();
            console.log('[Fetch] Fetched invoice status:', data.invoice.extraction_status);
            console.log('[Fetch] Line items count:', (data.lineItems || []).length);
            
            setInvoice(data.invoice);
            setParties(data.parties || []);
            
            // Use lineItemsWithBboxes if available (has nested format with bboxes),
            // otherwise fall back to flat lineItems from database table
            const lineItemsData = data.lineItemsWithBboxes && data.lineItemsWithBboxes.length > 0
                ? data.lineItemsWithBboxes
                : data.lineItems || [];
            
            console.log('[Invoice Load] Processed line items count:', lineItemsData.length);
            
            // Transform line items to UI format
            if (lineItemsData.length > 0 && lineItemsData[0].fields) {
                // Nested format with bboxes - transform to flat for table display
                const transformedItems = [];
                const lineItemBboxes = {};
                
                lineItemsData.forEach((item, index) => {
                    const fields = item.fields || {};
                    const rowId = `line_${index}`;
                    
                    const getValue = (field) => {
                        if (!field) return '';
                        if (typeof field === 'string' || typeof field === 'number') return String(field);
                        return field.value || '';
                    };
                    
                    const getBbox = (field) => {
                        if (field && field.bbox) return field.bbox;
                        return null;
                    };
                    
                    transformedItems.push({
                        id: item.id || `temp-${Date.now()}-${index}`,
                        line_number: item.row || index + 1,
                        description: getValue(fields.item_description),
                        hs_code: getValue(fields.item_hs_code),
                        country_of_origin: getValue(fields.item_country_of_origin),
                        quantity: getValue(fields.item_quantity),
                        unit_price: getValue(fields.item_unit_price),
                        total_value: getValue(fields.item_total_value),
                        net_weight: getValue(fields.item_net_weight),
                        gross_weight: getValue(fields.item_gross_weight)
                    });
                    
                    // Extract bboxes
                    const bboxFields = [
                        'item_description', 'item_hs_code', 'item_country_of_origin',
                        'item_quantity', 'item_unit_price', 'item_net_weight', 'item_gross_weight'
                    ];
                    
                    bboxFields.forEach(fieldKey => {
                        const bbox = getBbox(fields[fieldKey]);
                        if (bbox && Array.isArray(bbox) && bbox.length === 4) {
                            const fieldName = fieldKey.replace('item_', '');
                            console.log(`[Line Item] ${rowId}.${fieldName} bbox:`, bbox);
                            lineItemBboxes[`${rowId}.${fieldName}`] = {
                                x: bbox[0],
                                y: bbox[1],
                                width: bbox[2] - bbox[0],
                                height: bbox[3] - bbox[1],
                                confidence: fields[fieldKey]?.confidence || 0
                            };
                        }
                    });
                });
                
                setLineItems(transformedItems);
                
                // Add line item bboxes to state
                if (Object.keys(lineItemBboxes).length > 0) {
                    console.log(`[Invoice Load] Extracted ${Object.keys(lineItemBboxes).length} line item bboxes`);
                    setBoundingBoxes(prev => ({
                        ...prev,
                        ...lineItemBboxes
                    }));
                }
            } else {
                // Flat format from database - use as-is
                setLineItems(lineItemsData);
            }
            
            // Parse extracted_data to populate bounding boxes for regular fields
            if (data.invoice?.extracted_data?.final_fields) {
                const { final_fields } = data.invoice.extracted_data;
                const bboxes = {};
                
                // Extract bboxes from final_fields
                Object.entries(final_fields).forEach(([fieldPath, fieldData]) => {
                    if (fieldData.bbox) {
                        bboxes[fieldPath] = {
                            ...fieldData.bbox,
                            source: fieldData.source || 'ml_extraction',
                            confidence: fieldData.confidence || 0
                        };
                    }
                });
                
                setBoundingBoxes(bboxes);
                console.log(`[Loaded Bboxes] ${Object.keys(bboxes).length} bounding boxes from extracted_data`);
            }
            
        } catch (err) {
            console.error('Error fetching invoice:', err);
            setError(err.message);
        } finally {
            if (!isBackground) {
                setLoading(false);
            }
        }
    }, [id, getToken]);
    
    useEffect(() => {
        if (id) {
            console.log('[Effect] ID changed or initial mount. Fetching...');
            fetchInvoiceDetails();
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [id, refreshTrigger, fetchInvoiceDetails]);

    // Separate effect for socket room join - waits for connection
    useEffect(() => {
        if (id && connected) {
            console.log('[Socket] Connected, joining invoice room:', id);
            joinInvoice(id);
            
            // Cleanup: leave room on unmount or id change
            return () => {
                leaveInvoice(id);
            };
        }
    }, [id, connected, joinInvoice, leaveInvoice]);
    
    useEffect(() => {
        if (!id || !connected) return;
        
        const unsubscribe = onExtractionProgress((data) => {
            if (data.invoiceId === id) {
                console.log('[Extraction Progress]', data);
                const nextProgress = typeof data.progress === 'number' ? data.progress : extractionProgressRef.current;
                if (nextProgress >= extractionProgressRef.current) {
                    extractionProgressRef.current = nextProgress;
                    setExtractionProgress(nextProgress);
                    setExtractionStage(data.stage || 'Processing...');
                }
                setExtracting(true);
            }
        });
        
        return unsubscribe;
    }, [id, connected, onExtractionProgress]);

    // Listen for OCR preview (raw text while waiting for LLM)
    useEffect(() => {
        if (!id || !connected) return;
        
        const unsubscribe = onOCRPreview((data) => {
            if (data.invoiceId === id) {
                console.log('[OCR Preview] Received:', data.tableCount, 'tables');
                setOcrPreview({
                    text: data.ocrText,
                    tableCount: data.tableCount
                });
                setExtractionStage(`OCR complete: ${data.tableCount} tables found. Analyzing with AI...`);
            }
        });
        
        return unsubscribe;
    }, [id, connected, onOCRPreview]);

    // Listen for progressive field updates via Socket.IO
    useEffect(() => {
        if (!id || !connected) return;
        
        const unsubscribe = onFieldUpdate((data) => {
            console.log('[DEBUG] onFieldUpdate triggered:', data);
            const { field, value, source } = data;
            console.log(`[Real-time Update] ${field} = `, value, ` (from ${source})`);
            
            // Handle line items specially - parse the JSON array
            if (field === 'line_items') {
                console.log('[Real-time] Detected line_items field update');
                try {
                    let parsedLineItems = value;
                    
                    // Parse if it's a string (handle Python dict syntax)
                    if (typeof value === 'string') {
                        // Replace Python single quotes with double quotes for valid JSON
                        const jsonString = value.replace(/'/g, '"');
                        parsedLineItems = JSON.parse(jsonString);
                    }
                    
                    if (Array.isArray(parsedLineItems)) {
                        console.log(`[Real-time] Parsing ${parsedLineItems.length} line items`);
                        console.log(`[Real-time] First item structure:`, parsedLineItems[0]);
                        console.log(`[Real-time] First item fields:`, parsedLineItems[0]?.fields);
                        
                        // Log all items with their data to debug blank fields
                        parsedLineItems.forEach((item, idx) => {
                            if (idx < 3) { // Log first 3 items
                                console.log(`[Item ${idx}] Full structure:`, JSON.stringify(item, null, 2));
                            }
                        });
                        
                        // Transform to UI format - handle both nested and flat formats
                        const formattedItems = [];
                        const lineItemBboxes = {};
                        
                        parsedLineItems.forEach((item, index) => {
                            const rowId = `line_${index}`;
                            
                            // Check if it's already in flat format (from app-advanced.py)
                            if (item.description !== undefined || item.quantity !== undefined) {
                                formattedItems.push({
                                    id: `temp-${Date.now()}-${index}`,
                                    line_number: index + 1,
                                    description: item.description || '',
                                    hs_code: item.hs_code || '',
                                    country_of_origin: item.country_of_origin || '',
                                    quantity: item.quantity || '',
                                    unit_price: item.unit_price || '',
                                    total_value: item.amount || '',
                                    net_weight: item.net_weight || '',
                                    gross_weight: item.gross_weight || ''
                                });
                            } else {
                                // Handle nested format (from raw extraction)
                                const fields = item.fields || {};
                                
                                // Check if fields are simple strings or objects with value/bbox/confidence
                                const getValue = (field) => {
                                    if (!field) return '';
                                    if (typeof field === 'string' || typeof field === 'number') return String(field);
                                    return field.value || '';
                                };
                                
                                const getBbox = (field) => {
                                    if (field && field.bbox) return field.bbox;
                                    return null;
                                };
                                
                                formattedItems.push({
                                    id: `temp-${Date.now()}-${index}`,
                                    line_number: item.row || index + 1,
                                    description: getValue(fields.item_description),
                                    hs_code: getValue(fields.item_hs_code),
                                    country_of_origin: getValue(fields.item_country_of_origin),
                                    quantity: getValue(fields.item_quantity),
                                    unit_price: getValue(fields.item_unit_price),
                                    total_value: getValue(fields.item_total_value),
                                    net_weight: getValue(fields.item_net_weight),
                                    gross_weight: getValue(fields.item_gross_weight)
                                });
                                
                                // Extract bboxes for each field (if they exist)
                                const bboxFields = [
                                    'item_description', 'item_hs_code', 'item_country_of_origin',
                                    'item_quantity', 'item_unit_price', 'item_net_weight', 'item_gross_weight'
                                ];
                                
                                bboxFields.forEach(fieldKey => {
                                    const bbox = getBbox(fields[fieldKey]);
                                    if (bbox && Array.isArray(bbox) && bbox.length === 4) {
                                        const fieldName = fieldKey.replace('item_', '');
                                        lineItemBboxes[`${rowId}.${fieldName}`] = {
                                            x: bbox[0],
                                            y: bbox[1],
                                            width: bbox[2] - bbox[0],
                                            height: bbox[3] - bbox[1],
                                            confidence: fields[fieldKey]?.confidence || 0
                                        };
                                    }
                                });
                            }
                        });
                        
                        console.log(`[Real-time] ✅ Adding ${formattedItems.length} line items to UI`);
                        console.log(`[Real-time] ✅ Extracted ${Object.keys(lineItemBboxes).length} bounding boxes`);
                        
                        // Update bounding boxes state with line item bboxes
                        setBoundingBoxes(prev => ({
                            ...prev,
                            ...lineItemBboxes
                        }));
                        
                        // Merge with existing line items instead of replacing
                        setLineItems(prevItems => {
                            if (prevItems.length === 0) {
                                return formattedItems;
                            }
                            
                            // Merge by line_number or row
                            const merged = [...prevItems];
                            formattedItems.forEach(newItem => {
                                const existingIndex = merged.findIndex(
                                    item => item.line_number === newItem.line_number
                                );
                                
                                if (existingIndex >= 0) {
                                    // Merge fields, keeping non-empty values from both
                                    merged[existingIndex] = {
                                        ...merged[existingIndex],
                                        ...newItem,
                                        // Keep existing non-empty values
                                        description: newItem.description || merged[existingIndex].description,
                                        hs_code: newItem.hs_code || merged[existingIndex].hs_code,
                                        country_of_origin: newItem.country_of_origin || merged[existingIndex].country_of_origin,
                                        quantity: newItem.quantity || merged[existingIndex].quantity,
                                        unit_price: newItem.unit_price || merged[existingIndex].unit_price,
                                        net_weight: newItem.net_weight || merged[existingIndex].net_weight,
                                        gross_weight: newItem.gross_weight || merged[existingIndex].gross_weight
                                    };
                                } else {
                                    merged.push(newItem);
                                }
                            });
                            
                            return merged.sort((a, b) => a.line_number - b.line_number);
                        });
                        return; // Don't add to extractedFields
                    } else {
                        console.warn('[Real-time] line_items is not an array:', parsedLineItems);
                    }
                } catch (e) {
                    console.error('[Real-time] Failed to parse line_items:', e, value);
                }
                return;
            }
            
            // Handle per-line item field updates (item_description_1, hs_code_2, etc.)
            const lineItemMatch = field.match(/^(item_description|item_quantity|item_unit_price|item_total_value|item_unit|item_no|material_no|hs_code|country_of_origin)_(\d+)$/);
            if (lineItemMatch) {
                const [, rawKey, indexStr] = lineItemMatch;
                const lineIndex = Number(indexStr) - 1;

                const keyMap = {
                    item_description: 'description',
                    item_quantity: 'quantity',
                    item_unit_price: 'unit_price',
                    item_total_value: 'total_value',
                    item_unit: 'unit',
                    item_no: 'item_no',
                    material_no: 'item_code',
                    hs_code: 'hs_code',
                    country_of_origin: 'country_of_origin'
                };

                const mappedKey = keyMap[rawKey] || rawKey;

                setLineItems(prevItems => {
                    const updated = [...prevItems];
                    while (updated.length <= lineIndex) {
                        updated.push({
                            id: `temp-${Date.now()}-${updated.length}`,
                            line_number: updated.length + 1,
                            description: '',
                            hs_code: '',
                            country_of_origin: '',
                            quantity: '',
                            unit: '',
                            unit_price: '',
                            total_value: '',
                            net_weight: '',
                            gross_weight: '',
                            item_no: '',
                            item_code: ''
                        });
                    }

                    updated[lineIndex] = {
                        ...updated[lineIndex],
                        [mappedKey]: value
                    };

                    return updated;
                });

                // Still track extracted fields for debug panel
                setExtractedFields(prev => ({
                    ...prev,
                    [field]: value
                }));

                return;
            }

            // Update extracted fields state
            setExtractedFields(prev => ({
                ...prev,
                [field]: value
            }));

            // Also update invoice state for immediate display
            setInvoice(prev => {
                if (!prev) return prev;
                return {
                    ...prev,
                    [field]: value
                };
            });
            
            // Update parties for seller/buyer fields in real-time
            const sellerFields = ['seller_name', 'seller_address', 'seller_vat_number', 'seller_vat', 'seller_country', 'seller_tax_id'];
            const buyerFields = ['buyer_name', 'buyer_address', 'buyer_vat_number', 'buyer_vat', 'buyer_country', 'buyer_tax_id'];
            
            if (sellerFields.includes(field)) {
                const fieldKey = field.replace('seller_', '');
                const mappedKey = fieldKey === 'vat_number' || fieldKey === 'vat' ? 'vat_number' : fieldKey === 'tax_id' ? 'tax_id' : fieldKey;
                setParties(prev => {
                    const sellerIndex = prev.findIndex(p => p.party_type === 'vendor' || p.party_type === 'seller');
                    if (sellerIndex >= 0) {
                        const updated = [...prev];
                        updated[sellerIndex] = { ...updated[sellerIndex], [mappedKey]: value };
                        return updated;
                    } else {
                        // Create new vendor party
                        return [...prev, { party_type: 'vendor', [mappedKey]: value }];
                    }
                });
            } else if (buyerFields.includes(field)) {
                const fieldKey = field.replace('buyer_', '');
                const mappedKey = fieldKey === 'vat_number' || fieldKey === 'vat' ? 'vat_number' : fieldKey === 'tax_id' ? 'tax_id' : fieldKey;
                setParties(prev => {
                    const buyerIndex = prev.findIndex(p => p.party_type === 'buyer');
                    if (buyerIndex >= 0) {
                        const updated = [...prev];
                        updated[buyerIndex] = { ...updated[buyerIndex], [mappedKey]: value };
                        return updated;
                    } else {
                        // Create new buyer party
                        return [...prev, { party_type: 'buyer', [mappedKey]: value }];
                    }
                });
            }
        });
        
        return unsubscribe;
    }, [id, connected, onFieldUpdate]);
    
    // Listen for extraction completion
    useEffect(() => {
        if (!id || !connected) return;
        
        const unsubscribe = onExtractionComplete((data) => {
            console.log('[Extraction Complete]', data);
            setExtracting(false);
            setExtractedFields({});
            
            // Refresh invoice data to get final results
            if (data.invoiceId === id) {
                console.log('[Extraction Complete] Refreshing invoice details...');
                // Add a small delay to ensure DB transaction is committed
                setTimeout(() => {
                    fetchInvoiceDetails(true); // Pass true for background refresh
                }, 2000);
            }
        });
        
        return unsubscribe;
    }, [id, connected, onExtractionComplete, fetchInvoiceDetails]);
    
    // Add generic polling fallback for processing status
    useEffect(() => {
        if (!invoice || (invoice.extraction_status !== 'processing' && invoice.extraction_status !== 'extracting')) {
            return;
        }

        console.log('[Polling] Invoice is processing, starting poll...');
        const pollInterval = setInterval(() => {
            fetchInvoiceDetails(true);
        }, 3000);

        return () => clearInterval(pollInterval);
    }, [invoice?.extraction_status, fetchInvoiceDetails]);

    // Handle field acceptance
    const handleAcceptField = async (fieldPath, value) => {
        try {
            await correctionsApi.acceptFieldValue(
                id, 
                fieldPath, 
                value, 
                invoice?.extraction_confidence || 0
            );
            
            // Refresh data
            fetchInvoiceDetails();
        } catch (err) {
            console.error('Error accepting field:', err);
        }
    };
    
    // Handle bounding box update (drag/resize)
    const handleBoundingBoxUpdate = async (fieldPath, bbox) => {
        try {
            // Update local state immediately for smooth UX
            setBoundingBoxes(prev => ({
                ...prev,
                [fieldPath]: {
                    ...bbox,
                    source: 'user_adjusted'
                }
            }));
            
            // Add to corrections queue
            setCorrections(prev => [
                ...prev.filter(c => c.field_path !== fieldPath),
                {
                    field_path: fieldPath,
                    corrected_bbox: bbox,
                    correction_type: 'bounding_box',
                    comment: 'User adjusted bounding box'
                }
            ]);
            
            // Debounce the API call (wait for user to finish adjusting)
            // For now, submit immediately
            await correctionsApi.submitBboxCorrection(
                id,
                fieldPath,
                bbox,
                'User adjusted bounding box for better extraction'
            );
            
        } catch (err) {
            console.error('Error updating bounding box:', err);
        }
    };
    
    // Handle field correction (manual edit)
    const handleFieldCorrection = async (fieldPath, originalValue, correctedValue, mlConfidence) => {
        try {
            await correctionsApi.submitFieldCorrection(id, {
                fieldPath,
                originalValue,
                correctedValue,
                correctionType: 'manual_edit',
                mlConfidence
            });
            
            // Refresh data
            fetchInvoiceDetails();
        } catch (err) {
            console.error('Error submitting field correction:', err);
        }
    };
    
    // Handle field query
    const handleQueryField = async (fieldPath, value) => {
        setSelectedField({ fieldPath, value });
        setModalAction('query');
        setShowQueryModal(true);
    };
    
    // Handle field rejection
    const handleRejectField = async (fieldPath, value) => {
        setSelectedField({ fieldPath, value });
        setModalAction('reject');
        setShowQueryModal(true);
    };
    
    // Handle query/reject modal submit
    const handleModalSubmit = async (comment, recipientEmail) => {
        try {
            if (modalAction === 'query') {
                await correctionsApi.queryFieldValue(
                    id,
                    selectedField.fieldPath,
                    selectedField.value,
                    comment
                );
            } else if (modalAction === 'reject') {
                await correctionsApi.rejectFieldValue(
                    id,
                    selectedField.fieldPath,
                    selectedField.value,
                    comment
                );
            }
            
            // Also update invoice status
            await fetch(`/api/invoices/${id}/status`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    status: modalAction === 'query' ? 'queried' : 'rejected',
                    comment,
                    recipientEmail
                })
            });
            
            setShowQueryModal(false);
            setSelectedField(null);
            fetchInvoiceDetails();
        } catch (err) {
            console.error('Error submitting query/rejection:', err);
        }
    };
    
    // Handle export
    const handleExport = async (format) => {
        try {
            const response = await fetch(`/api/invoices/${id}/export`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ format })
            });
            
            if (!response.ok) {
                throw new Error('Export failed');
            }
            
            // Refresh data to show new status
            fetchInvoiceDetails();
            
            alert(`Invoice exported as ${format.toUpperCase()} successfully!`);
        } catch (err) {
            console.error('Error exporting invoice:', err);
            alert('Export failed: ' + err.message);
        }
    };
    
    // Handle ML extraction
    const handleExtract = async () => {
        setExtracting(true);
        setExtractionProgress(0);
        setExtractionStage('Starting...');
        
        try {
            const response = await fetch(`/api/invoices/${id}/extract`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error('Extraction failed');
            }
            
            // Note: Extraction progress is handled by Socket.IO events
            // and the polling fallback in the useEffect hook.
            
        } catch (err) {
            console.error('Extraction error:', err);
            alert('Failed to start extraction: ' + err.message);
            setExtracting(false);
        }
    };
    
    // Handle back navigation
    const handleBack = () => {
        navigate('/invoices');
    };
    
    if (loading) {
        return (
            <div className={styles.loading}>
                <div className={styles.spinner}></div>
                <p>Loading invoice...</p>
            </div>
        );
    }
    
    if (error) {
        return (
            <div className={styles.error}>
                <h2>Error</h2>
                <p>{error}</p>
                <button onClick={handleBack}>Back to Invoices</button>
            </div>
        );
    }
    
    if (!invoice) {
        return (
            <div className={styles.error}>
                <h2>Invoice not found</h2>
                <button onClick={handleBack}>Back to Invoices</button>
            </div>
        );
    }
    
    const buyer = parties.find(p => p.party_type === 'buyer');
    const seller = parties.find(p => p.party_type === 'vendor' || p.party_type === 'seller');
    
    const liveInvoice = {
        ...invoice,
        ...extractedFields
    };
    
    const liveSeller = {
        ...(seller || { party_type: 'vendor' }),
        name: extractedFields.seller_name || seller?.name,
        address: extractedFields.seller_address || seller?.address,
        vat_number: extractedFields.seller_vat_number || extractedFields.seller_vat || seller?.vat_number,
        tax_id: extractedFields.seller_tax_id || seller?.tax_id,
        country: extractedFields.seller_country || seller?.country
    };
    
    const liveBuyer = {
        ...(buyer || { party_type: 'buyer' }),
        name: extractedFields.buyer_name || buyer?.name,
        address: extractedFields.buyer_address || buyer?.address,
        vat_number: extractedFields.buyer_vat_number || extractedFields.buyer_vat || buyer?.vat_number,
        tax_id: extractedFields.buyer_tax_id || buyer?.tax_id,
        country: extractedFields.buyer_country || buyer?.country
    };
    
    return (
        <div className={styles.container}>
            {/* Header */}
            <div className={styles.header}>
                <div className={styles.headerLeft}>
                    <button onClick={handleBack} className={styles.backBtn}>
                        ← Back
                    </button>
                    <div className={styles.headerInfo}>
                        <h1 className={styles.title}>{liveInvoice.file_name}</h1>
                        <span className={styles.invoiceNumber}>
                            {liveInvoice.invoice_number || 'No Invoice Number'}
                        </span>
                    </div>
                </div>
                <div className={styles.headerRight}>
                    <button 
                        onClick={() => setShowFieldManager(true)}
                        className={styles.manageFieldsBtn}
                        title="Manage customs fields (HS Code, Incoterms, Weights)"
                    >
                        📋 Manage Fields
                    </button>
                    <button 
                        onClick={handleExtract}
                        className={styles.extractBtn}
                        disabled={extracting || invoice?.extraction_status === 'processing'}
                    >
                        {extracting || invoice?.extraction_status === 'processing' ? '🔄 Extracting...' : '🤖 Extract Data'}
                    </button>
                    <button 
                        onClick={() => handleExport('xml')}
                        className={styles.exportBtn}
                    >
                        Export XML
                    </button>
                    <button 
                        onClick={() => handleExport('csv')}
                        className={styles.exportBtn}
                    >
                        Export CSV
                    </button>
                    <button 
                        onClick={() => handleExport('xls')}
                        className={styles.exportBtn}
                    >
                        Export XLS
                    </button>
                </div>
            </div>
            
            {/* Progressive Extraction Indicator */}
            {(extracting || invoice?.extraction_status === 'processing') && (
                <div className={styles.progressBanner}>
                    <div className={styles.progressHeader}>
                        <span className={styles.progressIcon}>🔄</span>
                        <div style={{ flex: 1, marginLeft: '10px' }}>
                            <div className={styles.progressStage}>
                                <span>{extractionStage}</span>
                                <span>{extractionProgress}%</span>
                            </div>
                            <div className={styles.progressBarContainer}>
                                <div 
                                    className={styles.progressBarFill} 
                                    style={{ width: `${extractionProgress}%` }}
                                />
                            </div>
                        </div>
                    </div>
                    {/* OCR Preview while waiting for LLM */}
                    {ocrPreview && Object.keys(extractedFields).length === 0 && (
                        <div className={styles.ocrPreview}>
                            <div className={styles.ocrPreviewHeader}>
                                📄 OCR Complete: {ocrPreview.tableCount} table(s) detected
                            </div>
                            <div className={styles.ocrPreviewText}>
                                {ocrPreview.text?.substring(0, 300)}...
                            </div>
                        </div>
                    )}
                </div>
            )}
            
            {/* Main Content */}
            <div className={styles.content}>
                {/* Left Panel - PDF Viewer */}
                <div className={styles.leftPanel}>
                    <PDFViewer
                        invoiceId={id}
                        fileName={invoice.file_name}
                        fileType={invoice.file_type}
                        selectedField={selectedField}
                    >
                        {/* Bounding Box Overlay */}
                        <BoundingBoxOverlay
                            boundingBoxes={boundingBoxes}
                            selectedField={selectedField}
                            onBoundingBoxUpdate={handleBoundingBoxUpdate}
                        />
                    </PDFViewer>
                </div>
                
                {/* Right Panel - Fields */}
                <div className={styles.rightPanel}>
                    <FieldsPanel
                        invoice={liveInvoice}
                        buyer={liveBuyer}
                        seller={liveSeller}
                        onAccept={handleAcceptField}
                        onQuery={handleQueryField}
                        onReject={handleRejectField}
                        onCorrect={handleFieldCorrection}
                    />
                    
                    {/* Line Items Table */}
                    <div className={styles.lineItemsSection}>
                        <h3>Line Items</h3>
                        {console.log('[Render] lineItems state:', lineItems)}
                        <LineItemsTable
                            lineItems={lineItems}
                            invoiceId={id}
                            onUpdate={fetchInvoiceDetails}
                            onFieldClick={setSelectedField}
                        />
                    </div>
                </div>
            </div>
            
            {/* Query/Reject Modal */}
            {showQueryModal && (
                <QueryRejectModal
                    action={modalAction}
                    field={selectedField}
                    onSubmit={handleModalSubmit}
                    onClose={() => {
                        setShowQueryModal(false);
                        setSelectedField(null);
                    }}
                />
            )}
            
            {/* Field Manager Modal */}
            {showFieldManager && (
                <div className={styles.modalOverlay} onClick={() => setShowFieldManager(false)}>
                    <div className={styles.modalContent} onClick={(e) => e.stopPropagation()}>
                        <div className={styles.modalHeader}>
                            <h2>📋 Customs Field Manager</h2>
                            <button onClick={() => setShowFieldManager(false)} className={styles.closeBtn}>
                                ✕
                            </button>
                        </div>
                        <div className={styles.modalBody}>
                            <p className={styles.infoText}>
                                Manage customs-specific fields with validation and bounding box adjustments.
                            </p>
                            
                            <div className={styles.fieldManagerGrid}>
                                {/* Required Fields */}
                                <div className={styles.fieldCategory}>
                                    <h3>Required Customs Fields</h3>
                                    <div className={styles.fieldList}>
                                        <div className={styles.fieldItem}>
                                            <strong>HS Code</strong>
                                            <span className={styles.fieldValue}>{invoice?.hs_code || 'Not extracted'}</span>
                                            {boundingBoxes['hs_code'] && <span className={styles.hasBbox}>📍 Has bbox</span>}
                                        </div>
                                        <div className={styles.fieldItem}>
                                            <strong>Currency</strong>
                                            <span className={styles.fieldValue}>{invoice?.currency || 'Not extracted'}</span>
                                            {boundingBoxes['currency'] && <span className={styles.hasBbox}>📍 Has bbox</span>}
                                        </div>
                                        <div className={styles.fieldItem}>
                                            <strong>Item Description</strong>
                                            <span className={styles.fieldValue}>{invoice?.item_description || 'Not extracted'}</span>
                                            {boundingBoxes['item_description'] && <span className={styles.hasBbox}>📍 Has bbox</span>}
                                        </div>
                                    </div>
                                </div>
                                
                                {/* Optional Fields */}
                                <div className={styles.fieldCategory}>
                                    <h3>Optional Customs Fields</h3>
                                    <div className={styles.fieldList}>
                                        <div className={styles.fieldItem}>
                                            <strong>Incoterms</strong>
                                            <span className={styles.fieldValue}>{invoice?.incoterms || 'Not extracted'}</span>
                                            {boundingBoxes['incoterms'] && <span className={styles.hasBbox}>📍 Has bbox</span>}
                                        </div>
                                        <div className={styles.fieldItem}>
                                            <strong>Net Weight</strong>
                                            <span className={styles.fieldValue}>{invoice?.item_net_weight || 'Not extracted'}</span>
                                            {boundingBoxes['item_net_weight'] && <span className={styles.hasBbox}>📍 Has bbox</span>}
                                        </div>
                                        <div className={styles.fieldItem}>
                                            <strong>Gross Weight</strong>
                                            <span className={styles.fieldValue}>{invoice?.item_gross_weight || 'Not extracted'}</span>
                                            {boundingBoxes['item_gross_weight'] && <span className={styles.hasBbox}>📍 Has bbox</span>}
                                        </div>
                                        <div className={styles.fieldItem}>
                                            <strong>Country of Origin</strong>
                                            <span className={styles.fieldValue}>{invoice?.country_of_origin || 'Not extracted'}</span>
                                            {boundingBoxes['country_of_origin'] && <span className={styles.hasBbox}>📍 Has bbox</span>}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div className={styles.fieldManagerFooter}>
                                <p className={styles.helperText}>
                                    💡 Click on fields in the right panel to edit values, or drag bounding boxes on the PDF to adjust positions.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default InvoiceAnnotationPage;
