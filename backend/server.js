require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const authRoutes = require('./routes/auth.routes');
const apiSettingsRoutes = require('./routes/api-settings.routes');
const adminRoutes = require('./routes/admin.routes');
const organizationRoutes = require('./routes/organization.routes');
const invitationRoutes = require('./routes/invitation.routes');
const { parseXmlToTree } = require('./services/xmlParser.service');
const { getCorsOptions, helmetConfig } = require('./middleware/securityHeaders');
const { ipRateLimiter } = require('./middleware/rateLimiter');
const db = require('./db');

const app = express();

// Security Headers Middleware (ISO 27001 - A.13.1)
app.use(helmetConfig);

// CORS Configuration with whitelist
app.use(cors(getCorsOptions()));

// Global IP-based rate limiting (ISO 27001 - A.9.4)
app.use(ipRateLimiter(100, 60000)); // 100 requests per minute per IP

// Body parsing
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/api-settings', apiSettingsRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/organizations', organizationRoutes);
app.use('/api/invitations', invitationRoutes);

// XML Transform endpoints
app.post('/transform', async (req, res) => {
    const { sourceXml, destinationXml, mappingJson, removeEmptyTags } = req.body;
    if (!sourceXml || !destinationXml || !mappingJson) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    try {
        const transformed = transformSingleFile(sourceXml, destinationXml, mappingJson, removeEmptyTags);
        res.header('Content-Type', 'application/xml').send(transformed);
    } catch (err) {
        console.error('Transform error:', err);
        res.status(500).json({ error: 'Transform failed', details: err.message });
    }
});

app.post('/transform-json', async (req, res) => {
    const { sourceXml, destinationXml, mappingJson, removeEmptyTags } = req.body;
    if (!sourceXml || !destinationXml || !mappingJson) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    try {
        const transformed = transformSingleFile(sourceXml, destinationXml, mappingJson, removeEmptyTags);
        res.json({ transformed });
    } catch (err) {
        console.error('Transform error:', err);
        res.status(500).json({ error: 'Transform failed', details: err.message });
    }
});

app.post('/schema/parse', async (req, res) => {
    const { xmlString } = req.body;
    if (!xmlString) {
        return res.status(400).json({ error: 'Missing xmlString' });
    }
    try {
        const tree = parseXmlToTree(xmlString);
        res.json({ tree });
    } catch (err) {
        console.error('Parse error:', err);
        res.status(400).json({ error: err.message });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Global error:', err);
    res.status(500).json({
        error: 'Internal Server Error',
        details: err.message
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔒 Security headers enabled (ISO 27001 - A.13.1)`);
});
