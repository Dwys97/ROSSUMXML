// backend/services/aiMapping.service.js
const { GoogleGenerativeAI } = require('@google/generative-ai');

// Initialize Gemini AI
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
let genAI = null;

if (GEMINI_API_KEY && GEMINI_API_KEY !== 'YOUR_GEMINI_API_KEY_HERE') {
    genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
}

/**
 * Generate AI-powered mapping suggestions for XML schema mapping
 * @param {Object} sourceNode - Source XML schema node
 * @param {Array} targetNodes - Array of potential target nodes
 * @param {Object} context - Additional context (existing mappings, schema info)
 * @returns {Promise<Object>} Suggestion with confidence score and reasoning
 */
async function generateMappingSuggestion(sourceNode, targetNodes, context = {}) {
    if (!genAI) {
        throw new Error('Gemini API is not configured. Please set GEMINI_API_KEY in env.json');
    }

    try {
        // Use Gemini 1.5 Flash for fast, free-tier responses
        const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });

        // Craft a highly specific prompt for XML schema mapping
        const prompt = `You are an expert in XML schema mapping and data transformation. Your task is to suggest the best target element for mapping a source XML element.

**Source Element:**
- Name: ${sourceNode.name}
- Path: ${sourceNode.path}
- Type: ${sourceNode.type || 'element'}
- Sample Value: ${sourceNode.sampleValue || 'N/A'}
- Parent Context: ${sourceNode.parentPath || 'N/A'}

**Available Target Elements:**
${targetNodes.map((node, idx) => `${idx + 1}. Name: ${node.name}
   Path: ${node.path}
   Type: ${node.type || 'element'}
   Parent: ${node.parentPath || 'N/A'}`).join('\n\n')}

**Additional Context:**
- Source Schema Type: ${context.sourceSchemaType || 'Unknown'}
- Target Schema Type: ${context.targetSchemaType || 'Unknown'}
- Existing Mappings: ${context.existingMappingsCount || 0} mappings created
- Business Domain: ${context.domain || 'General data transformation'}

**Instructions:**
1. Analyze the source element name, path, and context
2. Compare against each target element
3. Consider semantic similarity, naming conventions, data types, and hierarchical structure
4. Select the BEST matching target element
5. Provide a confidence score (0-100)
6. Explain your reasoning in 1-2 sentences

**Response Format (JSON only):**
{
  "targetIndex": <index of best match from the list above (0-based)>,
  "confidence": <score from 0-100>,
  "reasoning": "<brief explanation>",
  "alternative": {
    "targetIndex": <index of second-best option or null>,
    "confidence": <score or null>
  }
}

Respond with ONLY the JSON object, no additional text.`;

        const result = await model.generateContent(prompt);
        const response = await result.response;
        const text = response.text();

        // Parse the JSON response
        let suggestion;
        try {
            // Try to extract JSON from markdown code blocks if present
            const jsonMatch = text.match(/```json\s*([\s\S]*?)\s*```/) || text.match(/```\s*([\s\S]*?)\s*```/);
            const jsonText = jsonMatch ? jsonMatch[1] : text;
            suggestion = JSON.parse(jsonText.trim());
        } catch (parseError) {
            console.error('Failed to parse AI response:', text);
            throw new Error('AI response was not in valid JSON format');
        }

        // Validate the suggestion
        if (typeof suggestion.targetIndex !== 'number' || suggestion.targetIndex < 0 || suggestion.targetIndex >= targetNodes.length) {
            throw new Error('Invalid target index in AI suggestion');
        }

        // Add the actual target node to the suggestion
        suggestion.targetNode = targetNodes[suggestion.targetIndex];
        
        // Add alternative if present
        if (suggestion.alternative && suggestion.alternative.targetIndex !== null) {
            suggestion.alternative.targetNode = targetNodes[suggestion.alternative.targetIndex];
        }

        return suggestion;

    } catch (error) {
        console.error('Gemini API error:', error);
        throw new Error(`AI suggestion failed: ${error.message}`);
    }
}

/**
 * Generate multiple mapping suggestions for batch processing
 * @param {Array} sourceMappingRequests - Array of {sourceNode, targetNodes, context}
 * @returns {Promise<Array>} Array of suggestions
 */
async function generateBatchMappingSuggestions(sourceMappingRequests) {
    if (!genAI) {
        throw new Error('Gemini API is not configured. Please set GEMINI_API_KEY in env.json');
    }

    // Process in parallel (Gemini free tier allows multiple requests)
    const suggestions = await Promise.all(
        sourceMappingRequests.map(req => 
            generateMappingSuggestion(req.sourceNode, req.targetNodes, req.context)
                .catch(error => ({
                    error: error.message,
                    sourceNode: req.sourceNode
                }))
        )
    );

    return suggestions;
}

/**
 * Check if user has access to AI features (Pro or Enterprise subscription)
 * @param {Object} pool - Database connection pool
 * @param {String} userId - User ID
 * @returns {Promise<Boolean>} True if user has access
 */
async function checkAIFeatureAccess(pool, userId) {
    try {
        const result = await pool.query(
            `SELECT level, status 
             FROM subscriptions 
             WHERE user_id = $1 AND status = 'active'`,
            [userId]
        );

        if (result.rows.length === 0) {
            return false; // No active subscription
        }

        const level = result.rows[0].level.toLowerCase();
        return level === 'pro' || level === 'enterprise';
    } catch (error) {
        console.error('Error checking AI feature access:', error);
        return false;
    }
}

module.exports = {
    generateMappingSuggestion,
    generateBatchMappingSuggestions,
    checkAIFeatureAccess
};
