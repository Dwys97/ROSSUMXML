import React, { useState, forwardRef } from 'react';
import ConfidenceIndicator from './ConfidenceIndicator';
import styles from './FieldsPanel.module.css';

const FieldsPanel = forwardRef(({ invoice, buyer, seller, onAccept, onQuery, onReject, onCorrect }, ref) => {
    const [editingField, setEditingField] = useState(null);
    const [editValue, setEditValue] = useState('');

    const formatDecimal = (value, decimals) => {
        if (value === null || value === undefined || value === '') return '';
        const raw = String(value).trim();
        if (!raw) return '';
        let cleaned = raw.replace(/[^0-9,.-]/g, '');
        if (!cleaned || cleaned === '-' || cleaned === '.') return '';
        const hasDot = cleaned.includes('.');
        const hasComma = cleaned.includes(',');
        if (hasDot && hasComma) {
            const lastDot = cleaned.lastIndexOf('.');
            const lastComma = cleaned.lastIndexOf(',');
            if (lastComma > lastDot) {
                cleaned = cleaned.replace(/\./g, '').replace(',', '.');
            } else {
                cleaned = cleaned.replace(/,/g, '');
            }
        } else if (!hasDot && hasComma) {
            cleaned = cleaned.replace(',', '.');
        }
        const num = Number(cleaned);
        if (Number.isNaN(num)) return '';
        return num.toFixed(decimals);
    };
    
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
    
    // Start editing a field
    const handleStartEdit = (fieldPath, currentValue, confidence) => {
        setEditingField({ fieldPath, originalValue: currentValue, confidence });
        setEditValue(currentValue || '');
    };
    
    // Save correction
    const handleSaveEdit = () => {
        if (editingField && onCorrect) {
            onCorrect(
                editingField.fieldPath,
                editingField.originalValue,
                editValue,
                editingField.confidence
            );
        }
        setEditingField(null);
        setEditValue('');
    };
    
    // Cancel editing
    const handleCancelEdit = () => {
        setEditingField(null);
        setEditValue('');
    };
    
    // Render field with actions
    const FieldRow = ({ label, value, confidence, fieldPath }) => {
        const isEditing = editingField?.fieldPath === fieldPath;
        
        return (
            <div className={styles.fieldRow} data-field={fieldPath}>
                <div className={styles.fieldHeader}>
                    <span className={styles.fieldLabel}>{label}</span>
                    <ConfidenceIndicator confidence={confidence} />
                </div>
                <div className={styles.fieldValue}>
                    {isEditing ? (
                        <div className={styles.editMode}>
                            <input
                                type="text"
                                value={editValue}
                                onChange={(e) => setEditValue(e.target.value)}
                                className={styles.editInput}
                                autoFocus
                                onKeyDown={(e) => {
                                    if (e.key === 'Enter') handleSaveEdit();
                                    if (e.key === 'Escape') handleCancelEdit();
                                }}
                            />
                            <div className={styles.editActions}>
                                <button
                                    onClick={handleSaveEdit}
                                    className={`${styles.editBtn} ${styles.saveBtn}`}
                                    title="Save correction"
                                >
                                    ✓ Save
                                </button>
                                <button
                                    onClick={handleCancelEdit}
                                    className={`${styles.editBtn} ${styles.cancelBtn}`}
                                    title="Cancel"
                                >
                                    ✗ Cancel
                                </button>
                            </div>
                        </div>
                    ) : (
                        <div 
                            className={styles.valueDisplay}
                            onDoubleClick={() => handleStartEdit(fieldPath, value, confidence)}
                            title="Double-click to edit"
                        >
                            {value || <span className={styles.emptyValue}>Not extracted</span>}
                        </div>
                    )}
                </div>
                {!isEditing && (
                    <div className={styles.fieldActions}>
                        <button
                            onClick={() => handleStartEdit(fieldPath, value, confidence)}
                            className={`${styles.actionBtn} ${styles.editIconBtn}`}
                            title="Edit"
                        >
                            ✎
                        </button>
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
                )}
            </div>
        );
    };
    
    return (
        <div className={styles.container} ref={ref}>
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
                    value={formatDecimal(invoice?.subtotal, 2)}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="totals.subtotal"
                />
                
                <FieldRow
                    label="Tax/VAT"
                    value={formatDecimal(invoice?.tax_amount, 2)}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="totals.tax"
                />
                
                <FieldRow
                    label="Total Amount"
                    value={formatDecimal(invoice?.total_amount, 2)}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="totals.total"
                />
                
                <FieldRow
                    label="Gross Weight (kg)"
                    value={formatDecimal(invoice?.total_gross_weight, 3)}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="totals.gross_weight"
                />
                
                <FieldRow
                    label="Net Weight (kg)"
                    value={formatDecimal(invoice?.total_net_weight, 3)}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="totals.net_weight"
                />
                
                <FieldRow
                    label="Incoterms"
                    value={invoice?.incoterms}
                    confidence={invoice?.extraction_confidence}
                    fieldPath="shipping.incoterms"
                />
            </div>
        </div>
    );
});

FieldsPanel.displayName = 'FieldsPanel';

export default FieldsPanel;
