-- Test data for Invoice Extraction System
-- Run this to create sample invoices for testing

-- Insert test invoice
INSERT INTO invoices (
    organization_id, 
    user_id, 
    file_name, 
    file_path, 
    file_type, 
    file_size,
    invoice_number,
    invoice_date,
    total_amount,
    currency,
    status,
    extraction_status,
    extraction_confidence
) VALUES (
    (SELECT id FROM organizations LIMIT 1),
    (SELECT id FROM users LIMIT 1),
    'test-invoice-001.pdf',
    '/tmp/invoices/test-invoice-001.pdf',
    'pdf',
    245678,
    'INV-2025-001',
    '2025-10-15',
    15750.00,
    'GBP',
    'to_review',
    'completed',
    0.89
) ON CONFLICT DO NOTHING
RETURNING id;

-- Insert buyer and seller parties
WITH invoice_id AS (
    SELECT id FROM invoices WHERE invoice_number = 'INV-2025-001' LIMIT 1
)
INSERT INTO invoice_parties (
    invoice_id,
    party_type,
    party_name,
    party_address,
    party_city,
    party_country,
    party_postal_code,
    party_vat_number,
    party_eori_number,
    confidence_scores
) VALUES 
(
    (SELECT id FROM invoice_id),
    'buyer',
    'ABC Import Ltd',
    '123 High Street',
    'London',
    'GB',
    'SW1A 1AA',
    'GB123456789',
    'GB123456789000',
    '{"party_name": 0.95, "party_address": 0.87, "party_vat_number": 0.92}'::jsonb
),
(
    (SELECT id FROM invoice_id),
    'seller',
    'XYZ Manufacturing Co',
    '456 Factory Road',
    'Shanghai',
    'CN',
    '200000',
    'CN987654321',
    'CN987654321000',
    '{"party_name": 0.93, "party_address": 0.85, "party_vat_number": 0.90}'::jsonb
)
ON CONFLICT DO NOTHING;

-- Insert line items
WITH invoice_id AS (
    SELECT id FROM invoices WHERE invoice_number = 'INV-2025-001' LIMIT 1
)
INSERT INTO invoice_line_items (
    invoice_id,
    line_number,
    item_description,
    hs_code,
    country_of_origin,
    quantity,
    unit_of_measure,
    unit_price,
    line_total,
    net_weight_kg,
    gross_weight_kg,
    confidence_scores
) VALUES 
(
    (SELECT id FROM invoice_id),
    1,
    'Electronic Components - Resistors 100pcs',
    '8533.21.00',
    'CN',
    1000,
    'PCE',
    5.25,
    5250.00,
    12.5,
    15.0,
    '{"item_description": 0.91, "hs_code": 0.78, "quantity": 0.95}'::jsonb
),
(
    (SELECT id FROM invoice_id),
    2,
    'Electronic Components - Capacitors 50pcs',
    '8532.24.00',
    'CN',
    500,
    'PCE',
    12.50,
    6250.00,
    8.0,
    10.0,
    '{"item_description": 0.89, "hs_code": 0.75, "quantity": 0.93}'::jsonb
),
(
    (SELECT id FROM invoice_id),
    3,
    'Electronic Components - LED Lights',
    '8541.41.00',
    'CN',
    2000,
    'PCE',
    2.125,
    4250.00,
    5.5,
    7.0,
    '{"item_description": 0.92, "hs_code": 0.82, "quantity": 0.96}'::jsonb
)
ON CONFLICT DO NOTHING;

-- Insert audit log entries
WITH invoice_id AS (
    SELECT id FROM invoices WHERE invoice_number = 'INV-2025-001' LIMIT 1
)
INSERT INTO invoice_audit_log (
    invoice_id,
    user_id,
    action,
    status_to,
    ip_address,
    user_agent
) VALUES 
(
    (SELECT id FROM invoice_id),
    (SELECT id FROM users LIMIT 1),
    'upload',
    'to_review',
    '127.0.0.1',
    'Mozilla/5.0 Test'
),
(
    (SELECT id FROM invoice_id),
    (SELECT id FROM users LIMIT 1),
    'extract',
    NULL,
    '127.0.0.1',
    'Mozilla/5.0 Test'
)
ON CONFLICT DO NOTHING;

-- Display created data
SELECT 
    i.id,
    i.invoice_number,
    i.file_name,
    i.status,
    i.extraction_status,
    i.total_amount,
    i.currency,
    COUNT(DISTINCT p.id) as party_count,
    COUNT(DISTINCT li.id) as line_item_count
FROM invoices i
LEFT JOIN invoice_parties p ON i.id = p.invoice_id
LEFT JOIN invoice_line_items li ON i.id = li.invoice_id
WHERE i.invoice_number = 'INV-2025-001'
GROUP BY i.id, i.invoice_number, i.file_name, i.status, i.extraction_status, i.total_amount, i.currency;
