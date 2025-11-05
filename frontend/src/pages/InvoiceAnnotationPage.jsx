import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useSocket } from '../contexts/SocketContext';
import PDFViewer from '../components/invoice/PDFViewer';
import FieldsPanel from '../components/invoice/FieldsPanel';
import LineItemsTable from '../components/invoice/LineItemsTable';
import QueryRejectModal from '../components/invoice/QueryRejectModal';
import styles from './InvoiceAnnotationPage.module.css';

const InvoiceAnnotationPage = () => {
    const { id } = useParams();
    const { getToken } = useAuth();
    const { joinInvoice, leaveInvoice, onFieldUpdate, connected } = useSocket();
    const navigate = useNavigate();
    
    const [invoice, setInvoice] = useState(null);
    const [parties, setParties] = useState([]);
    const [lineItems, setLineItems] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [selectedField, setSelectedField] = useState(null);
    const [showQueryModal, setShowQueryModal] = useState(false);
    const [modalAction, setModalAction] = useState(null); // 'query' or 'reject'
    const [extracting, setExtracting] = useState(false);
    const [extractedFields, setExtractedFields] = useState({}); // Progressive field updates
    
    // Fetch invoice details
    const fetchInvoiceDetails = async () => {
        setLoading(true);
        setError(null);
        
        try {
            const response = await fetch(`/api/invoices/${id}`, {
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to fetch invoice details');
            }
            
            const data = await response.json();
            
            setInvoice(data.invoice);
            setParties(data.parties || []);
            setLineItems(data.lineItems || []);
            
        } catch (err) {
            console.error('Error fetching invoice:', err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };
    
    useEffect(() => {
        if (id) {
            fetchInvoiceDetails();
            
            // Join invoice room for real-time updates
            joinInvoice(id);
            
            // Cleanup: leave room on unmount
            return () => {
                leaveInvoice(id);
            };
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [id]);
    
    // Listen for progressive field updates via Socket.IO
    useEffect(() => {
        if (!id || !connected) return;
        
        const unsubscribe = onFieldUpdate((data) => {
            const { field, value, source } = data;
            console.log(`[Real-time Update] ${field} = ${value} (from ${source})`);
            
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
        });
        
        return unsubscribe;
    }, [id, connected, onFieldUpdate]);
    
    // Handle field acceptance
    const handleAcceptField = async (fieldPath, value) => {
        try {
            await fetch(`/api/invoices/${id}/correct`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${getToken()}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    fieldPath,
                    originalValue: value,
                    correctedValue: value,
                    mlConfidence: invoice?.extraction_confidence || 0
                })
            });
            
            // Refresh data
            fetchInvoiceDetails();
        } catch (err) {
            console.error('Error accepting field:', err);
        }
    };
    
    // Handle field query
    const handleQueryField = (fieldPath, value) => {
        setSelectedField({ fieldPath, value });
        setModalAction('query');
        setShowQueryModal(true);
    };
    
    // Handle field rejection
    const handleRejectField = (fieldPath, value) => {
        setSelectedField({ fieldPath, value });
        setModalAction('reject');
        setShowQueryModal(true);
    };
    
    // Handle query/reject modal submit
    const handleModalSubmit = async (comment, recipientEmail) => {
        try {
            // Update invoice status
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
            
            alert('Extraction started! The invoice will be processed in the background.');
            
            // Poll for updates
            const pollInterval = setInterval(async () => {
                const checkResponse = await fetch(`/api/invoices/${id}`, {
                    headers: {
                        'Authorization': `Bearer ${getToken()}`,
                        'Content-Type': 'application/json'
                    }
                });
                
                if (checkResponse.ok) {
                    const data = await checkResponse.json();
                    if (data.invoice.extraction_status === 'completed') {
                        clearInterval(pollInterval);
                        fetchInvoiceDetails();
                        alert('Extraction completed successfully!');
                        setExtracting(false);
                    } else if (data.invoice.extraction_status === 'failed') {
                        clearInterval(pollInterval);
                        alert('Extraction failed. Please try again.');
                        setExtracting(false);
                    }
                }
            }, 3000); // Check every 3 seconds
            
            // Stop polling after 2 minutes
            setTimeout(() => {
                clearInterval(pollInterval);
                setExtracting(false);
            }, 120000);
            
        } catch (err) {
            console.error('Error extracting invoice:', err);
            alert('Extraction failed: ' + err.message);
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
    const seller = parties.find(p => p.party_type === 'seller');
    
    return (
        <div className={styles.container}>
            {/* Header */}
            <div className={styles.header}>
                <div className={styles.headerLeft}>
                    <button onClick={handleBack} className={styles.backBtn}>
                        ← Back
                    </button>
                    <div className={styles.headerInfo}>
                        <h1 className={styles.title}>{invoice.file_name}</h1>
                        <span className={styles.invoiceNumber}>
                            {invoice.invoice_number || 'No Invoice Number'}
                        </span>
                    </div>
                </div>
                <div className={styles.headerRight}>
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
            {(extracting || invoice?.extraction_status === 'processing') && Object.keys(extractedFields).length > 0 && (
                <div className={styles.progressBanner}>
                    <div className={styles.progressHeader}>
                        <span className={styles.progressIcon}>🔄</span>
                        <span className={styles.progressText}>Extracting fields in real-time...</span>
                    </div>
                    <div className={styles.progressFields}>
                        {Object.entries(extractedFields).map(([field, value]) => (
                            <span key={field} className={styles.progressField}>
                                ✅ {field}: {value}
                            </span>
                        ))}
                    </div>
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
                    />
                </div>
                
                {/* Right Panel - Fields */}
                <div className={styles.rightPanel}>
                    <FieldsPanel
                        invoice={invoice}
                        buyer={buyer}
                        seller={seller}
                        onAccept={handleAcceptField}
                        onQuery={handleQueryField}
                        onReject={handleRejectField}
                    />
                    
                    {/* Line Items Table */}
                    <div className={styles.lineItemsSection}>
                        <h3>Line Items</h3>
                        <LineItemsTable
                            lineItems={lineItems}
                            invoiceId={id}
                            onUpdate={fetchInvoiceDetails}
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
        </div>
    );
};

export default InvoiceAnnotationPage;
