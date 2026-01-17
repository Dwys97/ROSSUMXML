import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import TopNav from '../components/TopNav';
import FieldTemplateManager from '../components/invoice/FieldTemplateManager';
import styles from './FieldTemplatesPage.module.css';

const FieldTemplatesPage = () => {
    const { user } = useAuth();
    const navigate = useNavigate();

    return (
        <div className={styles.page}>
            <TopNav />
            <div className={styles.container}>
                <div className={styles.pageHeader}>
                    <div className={styles.breadcrumb}>
                        <span onClick={() => navigate('/invoices')}>Invoices</span>
                        <span className={styles.separator}>/</span>
                        <span className={styles.current}>Field Templates</span>
                    </div>
                    <h1>Extraction Field Manager</h1>
                    <p className={styles.subtitle}>
                        Define custom fields to extract from invoices. These templates instruct the NuExtract LLM 
                        what data to extract from your documents.
                    </p>
                </div>
                
                <div className={styles.content}>
                    <FieldTemplateManager />
                </div>
            </div>
        </div>
    );
};

export default FieldTemplatesPage;
