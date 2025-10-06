require('dotenv').config();
const express = require('express');
const cors = require('cors');
const authRoutes = require('./routes/auth.routes');
const userRoutes = require('./routes/user.routes');
const { parseXmlToTree } = require('./services/xmlParser.service');
const { transformSingleFile } = require('./services/transform.service');
const db = require('./db');

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

// Routes
app.use('/auth', authRoutes);
app.use('/user', userRoutes);

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

// Try to initialize database, but start server regardless
db.initDatabase()
    .then(() => {
        console.log('Database initialized successfully');
    })
    .catch(err => {
        console.warn('Database initialization skipped (database may not be available yet):', err.message);
    });

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
});