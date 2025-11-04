import React, { useState } from 'react';
import styles from './LineItemsTable.module.css';

const LineItemsTable = ({ lineItems, invoiceId, onUpdate }) => {
    const [isEditing, setIsEditing] = useState(false);
    const [editedItems, setEditedItems] = useState(lineItems || []);
    
    // Format number for display
    const formatNumber = (value) => {
        if (!value) return '-';
        return parseFloat(value).toFixed(2);
    };
    
    // Handle add new line item
    const handleAddItem = () => {
        const newItem = {
            id: `temp-${Date.now()}`,
            line_number: editedItems.length + 1,
            description: '',
            hs_code: '',
            country_of_origin: '',
            quantity: 0,
            unit_price: 0,
            total_value: 0,
            net_weight: 0,
            gross_weight: 0
        };
        setEditedItems([...editedItems, newItem]);
    };
    
    // Handle remove line item
    const handleRemoveItem = (index) => {
        const updated = editedItems.filter((_, i) => i !== index);
        setEditedItems(updated);
    };
    
    // Handle field change
    const handleFieldChange = (index, field, value) => {
        const updated = [...editedItems];
        updated[index] = {
            ...updated[index],
            [field]: value
        };
        
        // Auto-calculate total_value
        if (field === 'quantity' || field === 'unit_price') {
            const quantity = parseFloat(updated[index].quantity) || 0;
            const unitPrice = parseFloat(updated[index].unit_price) || 0;
            updated[index].total_value = quantity * unitPrice;
        }
        
        setEditedItems(updated);
    };
    
    // Handle save
    const handleSave = async () => {
        // TODO: Implement save logic via API
        console.log('Saving line items:', editedItems);
        setIsEditing(false);
        if (onUpdate) {
            onUpdate();
        }
    };
    
    // Handle cancel
    const handleCancel = () => {
        setEditedItems(lineItems || []);
        setIsEditing(false);
    };
    
    if (editedItems.length === 0 && !isEditing) {
        return (
            <div className={styles.empty}>
                <p>No line items extracted</p>
                <button onClick={() => setIsEditing(true)} className={styles.addBtn}>
                    Add Line Item
                </button>
            </div>
        );
    }
    
    return (
        <div className={styles.container}>
            <div className={styles.tableWrapper}>
                <table className={styles.table}>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Description</th>
                            <th>HS Code</th>
                            <th>Origin</th>
                            <th>Qty</th>
                            <th>Unit Price</th>
                            <th>Total</th>
                            <th>Net Wt (kg)</th>
                            <th>Gross Wt (kg)</th>
                            {isEditing && <th>Actions</th>}
                        </tr>
                    </thead>
                    <tbody>
                        {editedItems.map((item, index) => (
                            <tr key={item.id || index}>
                                <td>{index + 1}</td>
                                <td>
                                    {isEditing ? (
                                        <input
                                            type="text"
                                            value={item.description || ''}
                                            onChange={(e) => handleFieldChange(index, 'description', e.target.value)}
                                            className={styles.input}
                                        />
                                    ) : (
                                        item.description || '-'
                                    )}
                                </td>
                                <td>
                                    {isEditing ? (
                                        <input
                                            type="text"
                                            value={item.hs_code || ''}
                                            onChange={(e) => handleFieldChange(index, 'hs_code', e.target.value)}
                                            className={styles.input}
                                        />
                                    ) : (
                                        item.hs_code || '-'
                                    )}
                                </td>
                                <td>
                                    {isEditing ? (
                                        <input
                                            type="text"
                                            value={item.country_of_origin || ''}
                                            onChange={(e) => handleFieldChange(index, 'country_of_origin', e.target.value)}
                                            className={styles.input}
                                            maxLength="2"
                                        />
                                    ) : (
                                        item.country_of_origin || '-'
                                    )}
                                </td>
                                <td>
                                    {isEditing ? (
                                        <input
                                            type="number"
                                            value={item.quantity || 0}
                                            onChange={(e) => handleFieldChange(index, 'quantity', e.target.value)}
                                            className={styles.inputSmall}
                                        />
                                    ) : (
                                        formatNumber(item.quantity)
                                    )}
                                </td>
                                <td>
                                    {isEditing ? (
                                        <input
                                            type="number"
                                            step="0.01"
                                            value={item.unit_price || 0}
                                            onChange={(e) => handleFieldChange(index, 'unit_price', e.target.value)}
                                            className={styles.inputSmall}
                                        />
                                    ) : (
                                        formatNumber(item.unit_price)
                                    )}
                                </td>
                                <td>{formatNumber(item.total_value)}</td>
                                <td>
                                    {isEditing ? (
                                        <input
                                            type="number"
                                            step="0.01"
                                            value={item.net_weight || 0}
                                            onChange={(e) => handleFieldChange(index, 'net_weight', e.target.value)}
                                            className={styles.inputSmall}
                                        />
                                    ) : (
                                        formatNumber(item.net_weight)
                                    )}
                                </td>
                                <td>
                                    {isEditing ? (
                                        <input
                                            type="number"
                                            step="0.01"
                                            value={item.gross_weight || 0}
                                            onChange={(e) => handleFieldChange(index, 'gross_weight', e.target.value)}
                                            className={styles.inputSmall}
                                        />
                                    ) : (
                                        formatNumber(item.gross_weight)
                                    )}
                                </td>
                                {isEditing && (
                                    <td>
                                        <button
                                            onClick={() => handleRemoveItem(index)}
                                            className={styles.removeBtn}
                                            title="Remove"
                                        >
                                            ✗
                                        </button>
                                    </td>
                                )}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
            
            <div className={styles.actions}>
                {isEditing ? (
                    <>
                        <button onClick={handleAddItem} className={styles.addBtn}>
                            + Add Item
                        </button>
                        <div className={styles.editActions}>
                            <button onClick={handleSave} className={styles.saveBtn}>
                                Save
                            </button>
                            <button onClick={handleCancel} className={styles.cancelBtn}>
                                Cancel
                            </button>
                        </div>
                    </>
                ) : (
                    <button onClick={() => setIsEditing(true)} className={styles.editBtn}>
                        Edit Line Items
                    </button>
                )}
            </div>
        </div>
    );
};

export default LineItemsTable;
