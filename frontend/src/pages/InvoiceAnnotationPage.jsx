import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import PDFViewer from '../components/invoice/PDFViewer';
import FieldsPanel from '../components/invoice/FieldsPanel';
import LineItemsTable from '../components/invoice/LineItemsTable';
import QueryRejectModal from '../components/invoice/QueryRejectModal';
import styles from './InvoiceAnnotationPage.module.css';

const InvoiceAnnotationPage = () => {
    const { id } = useParams();
    const { token } = useAuth();
    const navigate = useNavigate();
    
    const [invoice, setInvoice] = useState(null);
    const [parties, setParties] = useState([]);
    const [lineItems, setLineItems] = useState([]);
    const [corrections, setCorrections] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [selectedField, setSelectedField] = useState(null);
    const [showQueryModal, setShowQueryModal] = useState(false);
    const [modalAction, setModalAction] = useState(null); // 'query' or 'reject'
    
    // Fetch invoice details
    const fetchInvoiceDetails = async () => {
        setLoading(true);
        setError(null);
        
        try {
            const response = await fetch(`/api/invoices/${id}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
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
            setCorrections(data.corrections || []);
            
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
        }
    }, [id]);
    
    // Handle field acceptance
    const handleAcceptField = async (fieldPath, value) => {
        try {
            await fetch(`/api/invoices/${id}/correct`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
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
                    'Authorization': `Bearer ${token}`,
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
                    'Authorization': `Bearer ${token}`,
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
            
            {/* Main Content */}
            <div className={styles.content}>
                {/* Left Panel - PDF Viewer */}
                <div className={styles.leftPanel}>
                    <PDFViewer
                        filePath={invoice.file_path}
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
