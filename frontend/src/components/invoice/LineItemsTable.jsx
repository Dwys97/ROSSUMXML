import React, { useState, useEffect } from 'react';
import styles from './LineItemsTable.module.css';

const LineItemsTable = ({ lineItems, onUpdate, onFieldClick }) => {
    const [editedItems, setEditedItems] = useState(lineItems || []);
    
    useEffect(() => {
        console.log('[LineItemsTable] Received lineItems prop:', lineItems);
        setEditedItems(lineItems || []);
    }, [lineItems]);
    
    const handleFieldChange = (index, field, value) => {
        const updated = [...editedItems];
        updated[index] = { ...updated[index], [field]: value };
        
        if (field === 'quantity' || field === 'unit_price') {
            const quantity = parseFloat(updated[index].quantity) || 0;
            const unitPrice = parseFloat(updated[index].unit_price) || 0;
            updated[index].total_value = quantity * unitPrice;
        }
        setEditedItems(updated);
    };
    
    const handleFieldClick = (index, field) => {
        if (onFieldClick) {
            onFieldClick(`line_${index}.${field}`);
        }
    };
    
    const handleAddItem = () => {
        setEditedItems([...editedItems, {
            id: `temp-${Date.now()}`,
            line_number: editedItems.length + 1,
            description: '', hs_code: '', country_of_origin: '',
            quantity: '', unit_price: '', total_value: '',
            net_weight: '', gross_weight: ''
        }]);
    };
    
    const handleRemoveItem = (index) => {
        setEditedItems(editedItems.filter((_, i) => i !== index));
    };
    
    if (editedItems.length === 0) {
        return (
            <div className={styles.empty}>
                <p>No line items extracted</p>
                <button onClick={handleAddItem} className={styles.addBtn}>Add Line Item</button>
            </div>
        );
    }
    
    return (
        <div className={styles.container}>
            <div className={styles.tableWrapper}>
                <table className={styles.table}>
                    <thead>
                        <tr>
                            <th>#</th><th>Description</th><th>HS Code</th><th>Origin</th>
                            <th>Qty</th><th>Unit Price</th><th>Total</th>
                            <th>Net Wt</th><th>Gross Wt</th><th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {editedItems.map((item, index) => (
                            <tr key={item.id || index}>
                                <td>{index + 1}</td>
                                <td>
                                    <input type="text" value={item.description || ''} 
                                        onChange={(e) => handleFieldChange(index, 'description', e.target.value)}
                                        onFocus={() => handleFieldClick(index, 'description')} 
                                        className={styles.input} />
                                </td>
                                <td>
                                    <input type="text" value={item.hs_code || ''} 
                                        onChange={(e) => handleFieldChange(index, 'hs_code', e.target.value)}
                                        onFocus={() => handleFieldClick(index, 'hs_code')} 
                                        className={styles.inputSmall} />
                                </td>
                                <td>
                                    <input type="text" value={item.country_of_origin || ''} 
                                        onChange={(e) => handleFieldChange(index, 'country_of_origin', e.target.value)}
                                        onFocus={() => handleFieldClick(index, 'country_of_origin')} 
                                        className={styles.inputSmall} maxLength="2" />
                                </td>
                                <td>
                                    <input type="text" value={item.quantity || ''} 
                                        onChange={(e) => handleFieldChange(index, 'quantity', e.target.value)}
                                        onFocus={() => handleFieldClick(index, 'quantity')} 
                                        className={styles.inputSmall} />
                                </td>
                                <td>
                                    <input type="text" value={item.unit_price || ''} 
                                        onChange={(e) => handleFieldChange(index, 'unit_price', e.target.value)}
                                        onFocus={() => handleFieldClick(index, 'unit_price')} 
                                        className={styles.inputSmall} />
                                </td>
                                <td>
                                    <input type="text" value={item.total_value || ''} readOnly 
                                        className={styles.inputSmall} />
                                </td>
                                <td>
                                    <input type="text" value={item.net_weight || ''} 
                                        onChange={(e) => handleFieldChange(index, 'net_weight', e.target.value)}
                                        onFocus={() => handleFieldClick(index, 'net_weight')} 
                                        className={styles.inputSmall} />
                                </td>
                                <td>
                                    <input type="text" value={item.gross_weight || ''} 
                                        onChange={(e) => handleFieldChange(index, 'gross_weight', e.target.value)}
                                        onFocus={() => handleFieldClick(index, 'gross_weight')} 
                                        className={styles.inputSmall} />
                                </td>
                                <td>
                                    <button onClick={() => handleRemoveItem(index)} 
                                        className={styles.removeBtn}>✗</button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
            <div className={styles.actions}>
                <button onClick={handleAddItem} className={styles.addBtn}>+ Add Item</button>
                <button onClick={onUpdate} className={styles.saveBtn}>Save Changes</button>
            </div>
        </div>
    );
};

export default LineItemsTable;
