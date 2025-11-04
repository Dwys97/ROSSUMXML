/**
 * Invoice Export Service
 * Generates XML, CSV, and XLS exports from invoice data
 * HMRC CDS Schema compliant for XML exports
 */

const db = require('../db');

/**
 * Export invoice as XML (HMRC CDS Schema compliant)
 * @param {string} invoiceId - Invoice UUID
 * @returns {Promise<string>} - XML content
 */
async function exportAsXML(invoiceId) {
    const invoiceData = await getInvoiceData(invoiceId);
    
    // Build HMRC CDS compliant XML structure
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<customs:Declaration xmlns:customs="urn:wco:datamodel:WCO:DEC-DMS:2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <customs:FunctionalReferenceID>${invoiceData.invoice.invoice_number || 'N/A'}</customs:FunctionalReferenceID>
    <customs:FunctionCode>9</customs:FunctionCode>
    <customs:TypeCode>IM</customs:TypeCode>
    
    <!-- Invoice Details -->
    <customs:InvoiceAmount currencyID="${invoiceData.invoice.currency || 'GBP'}">
        ${invoiceData.invoice.total_amount || 0}
    </customs:InvoiceAmount>
    
    <!-- Parties -->
    ${generatePartyXML(invoiceData.buyer, 'Buyer')}
    ${generatePartyXML(invoiceData.seller, 'Seller')}
    
    <!-- Goods Shipment -->
    <customs:GoodsShipment>
        ${invoiceData.lineItems.map((item, index) => generateLineItemXML(item, index + 1)).join('\n        ')}
        
        <!-- Totals -->
        <customs:TotalGrossMassMeasure unitCode="KGM">
            ${invoiceData.invoice.total_gross_weight || 0}
        </customs:TotalGrossMassMeasure>
        <customs:TotalNetMassMeasure unitCode="KGM">
            ${invoiceData.invoice.total_net_weight || 0}
        </customs:TotalNetMassMeasure>
    </customs:GoodsShipment>
    
    <!-- Declaration Date -->
    <customs:IssueDateTime>
        <customs:DateTimeString formatCode="102">${new Date().toISOString()}</customs:DateTimeString>
    </customs:IssueDateTime>
</customs:Declaration>`;
    
    return xml;
}

/**
 * Export invoice as CSV
 * @param {string} invoiceId - Invoice UUID
 * @returns {Promise<string>} - CSV content
 */
async function exportAsCSV(invoiceId) {
    const invoiceData = await getInvoiceData(invoiceId);
    
    // CSV Header
    let csv = 'Invoice Number,Invoice Date,Currency,Incoterms,';
    csv += 'Buyer Name,Buyer Address,Buyer VAT,';
    csv += 'Seller Name,Seller Address,Seller VAT,';
    csv += 'Line Number,Description,HS Code,Origin,Quantity,Unit Price,Total Value,Net Weight,Gross Weight,';
    csv += 'Subtotal,Tax Amount,Total Amount,Total Gross Weight,Total Net Weight\n';
    
    // Invoice data rows (one row per line item)
    invoiceData.lineItems.forEach((item, index) => {
        csv += escapeCSV(invoiceData.invoice.invoice_number || '') + ',';
        csv += escapeCSV(invoiceData.invoice.invoice_date || '') + ',';
        csv += escapeCSV(invoiceData.invoice.currency || '') + ',';
        csv += escapeCSV(invoiceData.invoice.incoterms || '') + ',';
        
        csv += escapeCSV(invoiceData.buyer?.name || '') + ',';
        csv += escapeCSV(invoiceData.buyer?.address_line1 || '') + ',';
        csv += escapeCSV(invoiceData.buyer?.vat_number || '') + ',';
        
        csv += escapeCSV(invoiceData.seller?.name || '') + ',';
        csv += escapeCSV(invoiceData.seller?.address_line1 || '') + ',';
        csv += escapeCSV(invoiceData.seller?.vat_number || '') + ',';
        
        csv += (index + 1) + ',';
        csv += escapeCSV(item.description || '') + ',';
        csv += escapeCSV(item.hs_code || '') + ',';
        csv += escapeCSV(item.country_of_origin || '') + ',';
        csv += (item.quantity || 0) + ',';
        csv += (item.unit_price || 0) + ',';
        csv += (item.total_value || 0) + ',';
        csv += (item.net_weight || 0) + ',';
        csv += (item.gross_weight || 0) + ',';
        
        csv += (invoiceData.invoice.subtotal || 0) + ',';
        csv += (invoiceData.invoice.tax_amount || 0) + ',';
        csv += (invoiceData.invoice.total_amount || 0) + ',';
        csv += (invoiceData.invoice.total_gross_weight || 0) + ',';
        csv += (invoiceData.invoice.total_net_weight || 0) + '\n';
    });
    
    return csv;
}

/**
 * Export invoice as XLS (Excel) - Returns CSV format with Excel-friendly formatting
 * Note: For true .xls generation, would need additional library like 'xlsx'
 * @param {string} invoiceId - Invoice UUID
 * @returns {Promise<string>} - CSV content (Excel compatible)
 */
async function exportAsXLS(invoiceId) {
    // For simplicity, returning CSV format which Excel can open
    // To generate true .xls/.xlsx files, integrate 'xlsx' library
    return await exportAsCSV(invoiceId);
}

/**
 * Get complete invoice data
 * @param {string} invoiceId - Invoice UUID
 * @returns {Promise<object>} - Complete invoice data
 */
async function getInvoiceData(invoiceId) {
    const client = await db.getClient();
    
    try {
        // Get invoice
        const invoiceResult = await client.query(
            'SELECT * FROM invoices WHERE id = $1',
            [invoiceId]
        );
        
        if (invoiceResult.rows.length === 0) {
            throw new Error('Invoice not found');
        }
        
        const invoice = invoiceResult.rows[0];
        
        // Get parties
        const partiesResult = await client.query(
            'SELECT * FROM invoice_parties WHERE invoice_id = $1',
            [invoiceId]
        );
        
        const buyer = partiesResult.rows.find(p => p.party_type === 'buyer');
        const seller = partiesResult.rows.find(p => p.party_type === 'seller');
        
        // Get line items
        const lineItemsResult = await client.query(
            'SELECT * FROM invoice_line_items WHERE invoice_id = $1 ORDER BY line_number',
            [invoiceId]
        );
        
        return {
            invoice,
            buyer,
            seller,
            lineItems: lineItemsResult.rows
        };
        
    } finally {
        client.release();
    }
}

/**
 * Generate party XML block
 * @param {object} party - Party data
 * @param {string} role - Party role (Buyer/Seller)
 * @returns {string} - XML fragment
 */
function generatePartyXML(party, role) {
    if (!party) return `<!-- ${role} information not available -->`;
    
    return `<customs:${role}>
        <customs:Name>${escapeXML(party.name || 'N/A')}</customs:Name>
        <customs:Address>
            <customs:CityName>${escapeXML(party.city || '')}</customs:CityName>
            <customs:CountryCode>${escapeXML(party.country || '')}</customs:CountryCode>
            <customs:Line>${escapeXML(party.address_line1 || '')}</customs:Line>
            <customs:PostcodeID>${escapeXML(party.postal_code || '')}</customs:PostcodeID>
        </customs:Address>
        ${party.vat_number ? `<customs:ID>${escapeXML(party.vat_number)}</customs:ID>` : ''}
    </customs:${role}>`;
}

/**
 * Generate line item XML block
 * @param {object} item - Line item data
 * @param {number} sequenceNumber - Item sequence
 * @returns {string} - XML fragment
 */
function generateLineItemXML(item, sequenceNumber) {
    return `<customs:GovernmentAgencyGoodsItem>
            <customs:SequenceNumeric>${sequenceNumber}</customs:SequenceNumeric>
            <customs:Commodity>
                <customs:Description>${escapeXML(item.description || 'N/A')}</customs:Description>
                <customs:Classification>
                    <customs:ID>${escapeXML(item.hs_code || '')}</customs:ID>
                    <customs:IdentificationTypeCode>TSP</customs:IdentificationTypeCode>
                </customs:Classification>
            </customs:Commodity>
            <customs:GovernmentProcedure>
                <customs:CurrentCode>40</customs:CurrentCode>
                <customs:PreviousCode>00</customs:PreviousCode>
            </customs:GovernmentProcedure>
            <customs:Origin>
                <customs:CountryCode>${escapeXML(item.country_of_origin || '')}</customs:CountryCode>
            </customs:Origin>
            <customs:Packaging>
                <customs:QuantityQuantity>${item.quantity || 0}</customs:QuantityQuantity>
            </customs:Packaging>
            <customs:ValuationAdjustment>
                <customs:AdditionCode>0000</customs:AdditionCode>
            </customs:ValuationAdjustment>
        </customs:GovernmentAgencyGoodsItem>`;
}

/**
 * Escape XML special characters
 * @param {string} str - Input string
 * @returns {string} - Escaped string
 */
function escapeXML(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

/**
 * Escape CSV special characters
 * @param {string} str - Input string
 * @returns {string} - Escaped string
 */
function escapeCSV(str) {
    if (!str) return '';
    str = String(str);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
        return '"' + str.replace(/"/g, '""') + '"';
    }
    return str;
}

module.exports = {
    exportAsXML,
    exportAsCSV,
    exportAsXLS,
    getInvoiceData
};
