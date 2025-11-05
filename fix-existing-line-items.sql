-- Temporary script to populate line items from existing extracted_data
-- This fixes the missing line items for already-extracted invoices

DO $$
DECLARE
    invoice_record RECORD;
    line_item RECORD;
    line_num INTEGER;
BEGIN
    -- Loop through all invoices with extracted line items data
    FOR invoice_record IN 
        SELECT id, extracted_data
        FROM invoices
        WHERE extracted_data->'raw_fields'->'line_items' IS NOT NULL
    LOOP
        line_num := 0;
        
        -- Loop through each line item in the raw_fields
        FOR line_item IN 
            SELECT value
            FROM jsonb_array_elements(invoice_record.extracted_data->'raw_fields'->'line_items')
        LOOP
            line_num := line_num + 1;
            
            -- Insert line item
            INSERT INTO invoice_line_items (
                invoice_id,
                line_number,
                quantity,
                unit_price,
                confidence_scores
            )
            VALUES (
                invoice_record.id,
                line_num,
                NULLIF((line_item.value->'fields'->>'item_quantity'), '')::DECIMAL,
                NULLIF((line_item.value->'fields'->>'item_unit_price'), '')::DECIMAL,
                jsonb_build_object(
                    'quantity', COALESCE((line_item.value->'fields'->'item_quantity'->>'confidence')::FLOAT, 0),
                    'unit_price', COALESCE((line_item.value->'fields'->'item_unit_price'->>'confidence')::FLOAT, 0)
                )
            );
        END LOOP;
        
        RAISE NOTICE 'Populated % line items for invoice %', line_num, invoice_record.id;
    END LOOP;
END $$;

-- Verify the results
SELECT 
    i.invoice_number,
    COUNT(li.id) as line_item_count
FROM invoices i
LEFT JOIN invoice_line_items li ON i.id = li.invoice_id
GROUP BY i.id, i.invoice_number
ORDER BY i.created_at DESC;
