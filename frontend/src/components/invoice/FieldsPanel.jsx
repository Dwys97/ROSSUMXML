import React from 'react';
import ConfidenceIndicator from './ConfidenceIndicator';
import styles from './FieldsPanel.module.css';

const FieldsPanel = ({ invoice, buyer, seller, onAccept, onQuery, onReject }) => {
    
    // Helper to get confidence score
    const getConfidence = (scores, field) => {
        if (!scores) return 0;
        try {
            const parsed = typeof scores === 'string' ? JSON.parse(scores) : scores;
            return parsed[field] || parsed.overall || 0;
        } catch {
            return 0;
        }
    };
    
    // Render field with actions
    const FieldRow = ({ label, value, confidence, fieldPath }) => (
        <div className={styles.fieldRow}>
            <div className={styles.fieldHeader}>
                <span className={styles.fieldLabel}>{label}</span>
                <ConfidenceIndicator confidence={confidence} />
            </div>
            <div className={styles.fieldValue}>
                {value || <span className={styles.emptyValue}>Not extracted</span>}
            </div>
            <div className={styles.fieldActions}>
                <button
                    onClick={() => onAccept(fieldPath, value)}
                    className={`${styles.actionBtn} ${styles.acceptBtn}`}
                    title="Accept"
                >
                    ✓
                </button>
                <button
                    onClick={() => onQuery(fieldPath, value)}
                    className={`${styles.actionBtn} ${styles.queryBtn}`}
                    title="Query"
                >
                    ⚠
                </button>
                <button
                    onClick={() => onReject(fieldPath, value)}
                    className={`${styles.actionBtn} ${styles.rejectBtn}`}
                    title="Reject"
                >
                    ✗
                </button>
            </div>
        </div>
    );
    
    return (
        <div className={styles.container}>
            <div className={styles.section}>
                <h3 className={styles.sectionTitle}>Invoice Details</h3>
                
                <FieldRow
                    label="Invoice Number"
                    value={invoice?.invoice_number}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="invoice.number"
                />
                
                <FieldRow
                    label="Invoice Date"
                    value={invoice?.invoice_date}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="invoice.date"
                />
                
                <FieldRow
                    label="Currency"
                    value={invoice?.currency}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="invoice.currency"
                />
            </div>
            
            <div className={styles.section}>
                <h3 className={styles.sectionTitle}>Buyer (Importer)</h3>
                
                {buyer ? (
                    <>
                        <FieldRow
                            label="Name"
                            value={buyer.name}
                            confidence={getConfidence(buyer.confidence_scores, 'name')}
                            fieldPath="buyer.name"
                        />
                        
                        <FieldRow
                            label="Address"
                            value={buyer.address_line1}
                            confidence={getConfidence(buyer.confidence_scores, 'address')}
                            fieldPath="buyer.address"
                        />
                        
                        <FieldRow
                            label="Country"
                            value={buyer.country}
                            confidence={getConfidence(buyer.confidence_scores, 'country')}
                            fieldPath="buyer.country"
                        />
                        
                        <FieldRow
                            label="VAT Number"
                            value={buyer.vat_number}
                            confidence={getConfidence(buyer.confidence_scores, 'vat_number')}
                            fieldPath="buyer.vat_number"
                        />
                    </>
                ) : (
                    <p className={styles.noData}>No buyer information extracted</p>
                )}
            </div>
            
            <div className={styles.section}>
                <h3 className={styles.sectionTitle}>Seller (Exporter)</h3>
                
                {seller ? (
                    <>
                        <FieldRow
                            label="Name"
                            value={seller.name}
                            confidence={getConfidence(seller.confidence_scores, 'name')}
                            fieldPath="seller.name"
                        />
                        
                        <FieldRow
                            label="Address"
                            value={seller.address_line1}
                            confidence={getConfidence(seller.confidence_scores, 'address')}
                            fieldPath="seller.address"
                        />
                        
                        <FieldRow
                            label="Country"
                            value={seller.country}
                            confidence={getConfidence(seller.confidence_scores, 'country')}
                            fieldPath="seller.country"
                        />
                        
                        <FieldRow
                            label="VAT Number"
                            value={seller.vat_number}
                            confidence={getConfidence(seller.confidence_scores, 'vat_number')}
                            fieldPath="seller.vat_number"
                        />
                    </>
                ) : (
                    <p className={styles.noData}>No seller information extracted</p>
                )}
            </div>
            
            <div className={styles.section}>
                <h3 className={styles.sectionTitle}>Totals</h3>
                
                <FieldRow
                    label="Subtotal"
                    value={invoice?.subtotal}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="totals.subtotal"
                />
                
                <FieldRow
                    label="Tax/VAT"
                    value={invoice?.tax_amount}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="totals.tax"
                />
                
                <FieldRow
                    label="Total Amount"
                    value={invoice?.total_amount}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="totals.total"
                />
                
                <FieldRow
                    label="Gross Weight (kg)"
                    value={invoice?.total_gross_weight}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="totals.gross_weight"
                />
                
                <FieldRow
                    label="Net Weight (kg)"
                    value={invoice?.total_net_weight}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="totals.net_weight"
                />
            </div>
            
            <div className={styles.section}>
                <h3 className={styles.sectionTitle}>Customs Data</h3>
                
                <FieldRow
                    label="Incoterms"
                    value={invoice?.incoterms}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="shipping.incoterms"
                />
                
                <FieldRow
                    label="HS Code"
                    value={invoice?.hs_code}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="shipping.hs_code"
                />
                
                <FieldRow
                    label="Country of Origin"
                    value={invoice?.country_of_origin}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="shipping.country_of_origin"
                />
            </div>
        </div>
    );
};

export default FieldsPanel;
