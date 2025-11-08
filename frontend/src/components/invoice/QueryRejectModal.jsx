import React, { useState } from 'react';
import styles from './QueryRejectModal.module.css';

const QueryRejectModal = ({ action, field, onSubmit, onClose }) => {
    const [comment, setComment] = useState('');
    const [recipientEmail, setRecipientEmail] = useState('');
    const [error, setError] = useState('');
    
    const handleSubmit = (e) => {
        e.preventDefault();
        setError('');
        
        if (!comment.trim()) {
            setError('Please provide a comment');
            return;
        }
        
        if (action === 'query' && !recipientEmail.trim()) {
            setError('Please provide a recipient email for the query');
            return;
        }
        
        // Basic email validation
        if (recipientEmail && !isValidEmail(recipientEmail)) {
            setError('Please provide a valid email address');
            return;
        }
        
        onSubmit(comment, recipientEmail);
    };
    
    const isValidEmail = (email) => {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    };
    
    const title = action === 'query' ? 'Query Field' : 'Reject Field';
    const description = action === 'query' 
        ? 'Send a question about this field to the supplier'
        : 'Mark this field as rejected with a reason';
    
    return (
        <div className={styles.overlay} onClick={onClose}>
            <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
                <div className={styles.header}>
                    <h2 className={styles.title}>{title}</h2>
                    <button onClick={onClose} className={styles.closeBtn}>✕</button>
                </div>
                
                <p className={styles.description}>{description}</p>
                
                {field && (
                    <div className={styles.fieldInfo}>
                        <strong>Field:</strong> {field.fieldPath}
                        <br />
                        <strong>Value:</strong> {field.value || 'Not extracted'}
                    </div>
                )}
                
                <form onSubmit={handleSubmit} className={styles.form}>
                    <div className={styles.formGroup}>
                        <label htmlFor="comment" className={styles.label}>
                            {action === 'query' ? 'Question / Comment' : 'Rejection Reason'}
                            <span className={styles.required}>*</span>
                        </label>
                        <textarea
                            id="comment"
                            value={comment}
                            onChange={(e) => setComment(e.target.value)}
                            className={styles.textarea}
                            rows="4"
                            placeholder={action === 'query' 
                                ? 'Enter your question about this field...'
                                : 'Explain why this field is being rejected...'
                            }
                            required
                        />
                    </div>
                    
                    {action === 'query' && (
                        <div className={styles.formGroup}>
                            <label htmlFor="email" className={styles.label}>
                                Recipient Email
                                <span className={styles.required}>*</span>
                            </label>
                            <input
                                id="email"
                                type="email"
                                value={recipientEmail}
                                onChange={(e) => setRecipientEmail(e.target.value)}
                                className={styles.input}
                                placeholder="supplier@example.com"
                                required
                            />
                            <span className={styles.hint}>
                                The supplier will receive an email with your query
                            </span>
                        </div>
                    )}
                    
                    {error && (
                        <div className={styles.error}>
                            {error}
                        </div>
                    )}
                    
                    <div className={styles.actions}>
                        <button type="button" onClick={onClose} className={styles.cancelBtn}>
                            Cancel
                        </button>
                        <button 
                            type="submit" 
                            className={action === 'query' ? styles.queryBtn : styles.rejectBtn}
                        >
                            {action === 'query' ? 'Send Query' : 'Reject Field'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default QueryRejectModal;
