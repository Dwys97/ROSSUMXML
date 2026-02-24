/**
 * Extraction Fields Routes
 * Manages custom field templates for invoice extraction with NuExtract
 */

const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticateToken } = require('../middleware/auth');

// Get all field templates for user/organization
router.get('/templates', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get user's organization
        const orgResult = await db.query(`
            SELECT organization_id FROM user_organization_roles 
            WHERE user_id = $1 LIMIT 1
        `, [userId]);
        
        const orgId = orgResult.rows[0]?.organization_id;
        
        // Get templates: system default + user's + org's
        const result = await db.query(`
            SELECT 
                t.id, t.name, t.description, t.is_default, t.is_active,
                t.organization_id, t.user_id, t.created_at, t.updated_at,
                COUNT(f.id) as field_count
            FROM extraction_field_templates t
            LEFT JOIN extraction_fields f ON f.template_id = t.id
            WHERE t.is_default = true 
               OR t.user_id = $1
               OR t.organization_id = $2
            GROUP BY t.id
            ORDER BY t.is_default DESC, t.created_at DESC
        `, [userId, orgId]);
        
        res.json({
            success: true,
            templates: result.rows
        });
    } catch (error) {
        console.error('Error fetching templates:', error);
        res.status(500).json({ error: 'Failed to fetch templates' });
    }
});

// Get single template with all fields
router.get('/templates/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;
        
        // Get template
        const templateResult = await db.query(`
            SELECT * FROM extraction_field_templates 
            WHERE id = $1 AND (is_default = true OR user_id = $2)
        `, [id, userId]);
        
        if (templateResult.rows.length === 0) {
            return res.status(404).json({ error: 'Template not found' });
        }
        
        // Get fields
        const fieldsResult = await db.query(`
            SELECT * FROM extraction_fields 
            WHERE template_id = $1 
            ORDER BY display_order ASC
        `, [id]);
        
        res.json({
            success: true,
            template: templateResult.rows[0],
            fields: fieldsResult.rows
        });
    } catch (error) {
        console.error('Error fetching template:', error);
        res.status(500).json({ error: 'Failed to fetch template' });
    }
});

// Create new template
router.post('/templates', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { name, description, fields, organizationId } = req.body;
        
        if (!name) {
            return res.status(400).json({ error: 'Template name is required' });
        }
        
        const client = await db.getClient();
        
        try {
            await client.query('BEGIN');
            
            // Create template
            const templateResult = await client.query(`
                INSERT INTO extraction_field_templates 
                (name, description, user_id, organization_id, is_default, is_active)
                VALUES ($1, $2, $3, $4, false, true)
                RETURNING *
            `, [name, description || '', userId, organizationId || null]);
            
            const template = templateResult.rows[0];
            
            // Insert fields if provided
            if (fields && Array.isArray(fields)) {
                for (let i = 0; i < fields.length; i++) {
                    const field = fields[i];
                    await client.query(`
                        INSERT INTO extraction_fields
                        (template_id, field_key, field_label, field_description, 
                         field_type, is_required, format_hint, nested_schema, display_order)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    `, [
                        template.id,
                        field.field_key,
                        field.field_label || field.field_key,
                        field.field_description || '',
                        field.field_type || 'string',
                        field.is_required || false,
                        field.format_hint || null,
                        field.nested_schema ? JSON.stringify(field.nested_schema) : null,
                        field.display_order || i * 10
                    ]);
                }
            }
            
            await client.query('COMMIT');
            
            res.json({
                success: true,
                template: template,
                message: 'Template created successfully'
            });
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Error creating template:', error);
        res.status(500).json({ error: 'Failed to create template' });
    }
});

// Update template
router.put('/templates/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;
        const { name, description, is_active } = req.body;
        
        // Check ownership
        const ownerCheck = await db.query(`
            SELECT id FROM extraction_field_templates 
            WHERE id = $1 AND user_id = $2 AND is_default = false
        `, [id, userId]);
        
        if (ownerCheck.rows.length === 0) {
            return res.status(403).json({ error: 'Cannot modify this template' });
        }
        
        const result = await db.query(`
            UPDATE extraction_field_templates 
            SET name = COALESCE($1, name),
                description = COALESCE($2, description),
                is_active = COALESCE($3, is_active),
                updated_at = NOW()
            WHERE id = $4
            RETURNING *
        `, [name, description, is_active, id]);
        
        res.json({
            success: true,
            template: result.rows[0]
        });
    } catch (error) {
        console.error('Error updating template:', error);
        res.status(500).json({ error: 'Failed to update template' });
    }
});

// Delete template
router.delete('/templates/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;
        
        // Check ownership and prevent deleting default
        const result = await db.query(`
            DELETE FROM extraction_field_templates 
            WHERE id = $1 AND user_id = $2 AND is_default = false
            RETURNING id
        `, [id, userId]);
        
        if (result.rows.length === 0) {
            return res.status(403).json({ error: 'Cannot delete this template' });
        }
        
        res.json({ success: true, message: 'Template deleted' });
    } catch (error) {
        console.error('Error deleting template:', error);
        res.status(500).json({ error: 'Failed to delete template' });
    }
});

// Add field to template
router.post('/templates/:id/fields', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;
        const { field_key, field_label, field_description, field_type, is_required, format_hint, nested_schema, display_order } = req.body;
        
        if (!field_key) {
            return res.status(400).json({ error: 'field_key is required' });
        }
        
        // Check template ownership
        const ownerCheck = await db.query(`
            SELECT id FROM extraction_field_templates 
            WHERE id = $1 AND (user_id = $2 OR is_default = true)
        `, [id, userId]);
        
        if (ownerCheck.rows.length === 0) {
            return res.status(403).json({ error: 'Template not found' });
        }
        
        // Get max display order
        const orderResult = await db.query(`
            SELECT COALESCE(MAX(display_order), 0) + 10 as next_order 
            FROM extraction_fields WHERE template_id = $1
        `, [id]);
        
        const result = await db.query(`
            INSERT INTO extraction_fields
            (template_id, field_key, field_label, field_description, 
             field_type, is_required, format_hint, nested_schema, display_order)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
        `, [
            id,
            field_key,
            field_label || field_key,
            field_description || '',
            field_type || 'string',
            is_required || false,
            format_hint || null,
            nested_schema ? JSON.stringify(nested_schema) : null,
            display_order || orderResult.rows[0].next_order
        ]);
        
        res.json({
            success: true,
            field: result.rows[0]
        });
    } catch (error) {
        console.error('Error adding field:', error);
        if (error.code === '23505') {
            return res.status(400).json({ error: 'Field key already exists in template' });
        }
        res.status(500).json({ error: 'Failed to add field' });
    }
});

// Update field
router.put('/fields/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;
        const { field_label, field_description, field_type, is_required, format_hint, nested_schema, display_order } = req.body;
        
        // Verify user can edit this field's template
        const checkResult = await db.query(`
            SELECT f.id FROM extraction_fields f
            JOIN extraction_field_templates t ON f.template_id = t.id
            WHERE f.id = $1 AND (t.user_id = $2 OR t.is_default = false)
        `, [id, userId]);
        
        if (checkResult.rows.length === 0) {
            return res.status(403).json({ error: 'Cannot modify this field' });
        }
        
        const result = await db.query(`
            UPDATE extraction_fields SET
                field_label = COALESCE($1, field_label),
                field_description = COALESCE($2, field_description),
                field_type = COALESCE($3, field_type),
                is_required = COALESCE($4, is_required),
                format_hint = COALESCE($5, format_hint),
                nested_schema = COALESCE($6, nested_schema),
                display_order = COALESCE($7, display_order),
                updated_at = NOW()
            WHERE id = $8
            RETURNING *
        `, [field_label, field_description, field_type, is_required, format_hint, 
            nested_schema ? JSON.stringify(nested_schema) : null, display_order, id]);
        
        res.json({
            success: true,
            field: result.rows[0]
        });
    } catch (error) {
        console.error('Error updating field:', error);
        res.status(500).json({ error: 'Failed to update field' });
    }
});

// Delete field
router.delete('/fields/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;
        
        // Verify user can delete (not from default template)
        const result = await db.query(`
            DELETE FROM extraction_fields f
            USING extraction_field_templates t
            WHERE f.template_id = t.id 
              AND f.id = $1 
              AND t.user_id = $2 
              AND t.is_default = false
            RETURNING f.id
        `, [id, userId]);
        
        if (result.rows.length === 0) {
            return res.status(403).json({ error: 'Cannot delete this field' });
        }
        
        res.json({ success: true, message: 'Field deleted' });
    } catch (error) {
        console.error('Error deleting field:', error);
        res.status(500).json({ error: 'Failed to delete field' });
    }
});

// Convert template to NuExtract schema format
router.get('/templates/:id/schema', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Get fields
        const fieldsResult = await db.query(`
            SELECT field_key, field_type, nested_schema 
            FROM extraction_fields 
            WHERE template_id = $1 
            ORDER BY display_order ASC
        `, [id]);
        
        if (fieldsResult.rows.length === 0) {
            return res.status(404).json({ error: 'Template not found or has no fields' });
        }
        
        // Build NuExtract schema
        const schema = {};
        for (const field of fieldsResult.rows) {
            if (field.field_type === 'array' && field.nested_schema) {
                // Array type with nested structure
                const nestedObj = {};
                const nested = typeof field.nested_schema === 'string' 
                    ? JSON.parse(field.nested_schema) 
                    : field.nested_schema;
                    
                for (const [key, def] of Object.entries(nested)) {
                    nestedObj[key] = "";
                }
                schema[field.field_key] = [nestedObj];
            } else {
                schema[field.field_key] = "";
            }
        }
        
        res.json({
            success: true,
            schema: schema,
            template_id: id
        });
    } catch (error) {
        console.error('Error generating schema:', error);
        res.status(500).json({ error: 'Failed to generate schema' });
    }
});

module.exports = router;
