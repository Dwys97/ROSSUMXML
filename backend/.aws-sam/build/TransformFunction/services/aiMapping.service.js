// backend/services/aiMapping.service.js

// Initialize Gemini AI
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

// Direct REST API approach using fetch to bypass v1beta issue
async function makeDirectGeminiRequest(prompt, apiKey) {
    const url = `https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key=${apiKey}`;
    
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            contents: [{
                parts: [{
                    text: prompt
                }]
            }]
        })
    });
    
    if (!response.ok) {
        const errorText = await response.text();
        console.error('Gemini API error:', errorText);
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    return data.candidates[0].content.parts[0].text;
}

/**
 * Generate AI-powered mapping suggestions for XML schema mapping
 * @param {Object} sourceNode - Source XML schema node
 * @param {Array} targetNodes - Array of potential target nodes
 * @param {Object} context - Additional context (existing mappings, schema info)
 * @returns {Promise<Object>} Suggestion with confidence score and reasoning
 */
async function generateMappingSuggestion(sourceNode, targetNodes, context = {}) {    
    if (!GEMINI_API_KEY || GEMINI_API_KEY === 'YOUR_GEMINI_API_KEY_HERE') {
        throw new Error('Gemini API is not configured. Please set GEMINI_API_KEY in env.json');
    }

    try {
        console.log('🔧 Using direct REST API approach with Gemini 2.5 Flash...');
        
        // Limit target nodes to prevent massive prompts causing timeouts
        const MAX_TARGETS = 80;
        const limitedTargetNodes = targetNodes.length > MAX_TARGETS 
            ? targetNodes.slice(0, MAX_TARGETS)
            : targetNodes;
            
        if (targetNodes.length > MAX_TARGETS) {
            console.log(`⚠️  Truncating ${targetNodes.length} target nodes to ${MAX_TARGETS} to reduce prompt size`);
        }
        
        // Compact, optimized prompt for XML schema mapping
        const prompt = `You are an expert in XML schema mapping. Find the best target for this source element.

SOURCE: ${sourceNode.name}
Path: ${sourceNode.path}

TARGETS (ZERO-BASED, 0-${limitedTargetNodes.length - 1}):
${limitedTargetNodes.map((node, index) => `${index}. ${node.name}`).join('\n')}

CONTEXT: ${context.sourceSchema || 'Source'} → ${context.targetSchema || 'Target'}

Match by semantic meaning, naming patterns, and data type. Respond with ONLY valid JSON:

{
  "targetElementIndex": <number 0-${limitedTargetNodes.length - 1}>,
  "confidence": <number 0-100>,
  "reasoning": "<brief explanation>",
  "dataTypeMatch": "<high|medium|low>",
  "semanticMatch": "<high|medium|low>"
}

CRITICAL: targetElementIndex MUST be 0-${limitedTargetNodes.length - 1}. NO other text, ONLY JSON.`;

        console.log('📤 Requesting AI mapping suggestion...');
        const aiResponse = await makeDirectGeminiRequest(prompt, GEMINI_API_KEY);
        console.log('📥 Received response from Gemini API');

        // Parse the AI response
        let suggestion;
        try {
            const cleanResponse = aiResponse.replace(/```json\n?|\n?```/g, '').trim();
            suggestion = JSON.parse(cleanResponse);
            console.log('✅ Successfully parsed AI response:', JSON.stringify(suggestion, null, 2));
        } catch (parseError) {
            console.log('Failed to parse AI response as JSON, using fallback parsing...');
            console.log('Raw AI Response:', aiResponse);
            
            // Fallback: extract information from natural language response
            const targetElementMatch = aiResponse.match(/targetElementIndex['":\s]*(\d+)/i);
            const confidenceMatch = aiResponse.match(/confidence['":\s]*(\d+)/i);
            const reasoningMatch = aiResponse.match(/reasoning['":\s]*["']([^"']+)["']/i);
            
            suggestion = {
                targetElementIndex: targetElementMatch ? parseInt(targetElementMatch[1]) : 0,
                confidence: confidenceMatch ? parseInt(confidenceMatch[1]) : 50,
                reasoning: reasoningMatch ? reasoningMatch[1] : 'AI provided suggestion without structured reasoning',
                dataTypeMatch: 'medium',
                semanticMatch: 'medium'
            };
            console.log('📝 Fallback parsed suggestion:', JSON.stringify(suggestion, null, 2));
        }

        console.log(`🔍 Available target nodes count: ${limitedTargetNodes.length}`);
        console.log(`🎯 AI suggested target index: ${suggestion.targetElementIndex}`);

        // Validate and auto-correct common AI indexing errors
        if (suggestion.targetElementIndex < 0 || suggestion.targetElementIndex >= limitedTargetNodes.length) {
            console.log(`❌ Invalid target index ${suggestion.targetElementIndex}, available indices: 0-${limitedTargetNodes.length - 1}`);
            
            // Try to correct common off-by-one errors
            if (suggestion.targetElementIndex === limitedTargetNodes.length) {
                console.log('🔧 Correcting off-by-one error: reducing index from', suggestion.targetElementIndex, 'to', limitedTargetNodes.length - 1);
                suggestion.targetElementIndex = limitedTargetNodes.length - 1;
            } else if (suggestion.targetElementIndex > limitedTargetNodes.length) {
                console.log('🔧 Correcting 1-based indexing error: setting index to', limitedTargetNodes.length - 1);
                suggestion.targetElementIndex = limitedTargetNodes.length - 1;
            } else if (suggestion.targetElementIndex < 0) {
                console.log('🔧 Correcting negative index: setting to 0');
                suggestion.targetElementIndex = 0;
            } else {
                throw new Error('AI suggested an invalid target element index');
            }
        }

        // Validate and return the suggestion
        const selectedTarget = limitedTargetNodes[suggestion.targetElementIndex];
        if (!selectedTarget) {
            console.log(`❌ Still invalid target index ${suggestion.targetElementIndex} after correction, available indices: 0-${limitedTargetNodes.length - 1}`);
            throw new Error('AI suggested an invalid target element index');
        }

        return {
            suggestion: {
                sourceElement: sourceNode,
                targetElement: selectedTarget,
                confidence: Math.min(100, Math.max(0, suggestion.confidence || 50)),
                reasoning: suggestion.reasoning || 'AI analysis completed',
                metadata: {
                    aiModel: 'gemini-2.5-flash',
                    timestamp: new Date().toISOString(),
                    dataTypeMatch: suggestion.dataTypeMatch || 'unknown',
                    semanticMatch: suggestion.semanticMatch || 'unknown'
                }
            }
        };

    } catch (error) {
        console.error('Gemini API error:', error);
        throw new Error(`AI suggestion failed: ${error.message}`);
    }
}

/**
 * Generate batch mapping suggestions for multiple source elements
 * Uses controlled parallelism to avoid overwhelming the API while staying under Lambda timeout
 * @param {Array} sourceNodes - Array of source XML schema nodes  
 * @param {Array} targetNodes - Array of potential target nodes
 * @param {Object} context - Additional context (existing mappings, schema info)
 * @returns {Promise<Array>} Array of suggestions with confidence scores
 */
async function generateBatchMappingSuggestions(sourceNodes, targetNodes, context = {}) {
    try {
        console.log(`🚀 Starting batch AI suggestions for ${sourceNodes.length} elements...`);
        console.log(`📊 Processing with ${targetNodes.length} target candidates per source`);
        
        // Process requests with controlled concurrency to avoid timeout
        // Lambda has 60s timeout, each request takes 5-15s
        // Process 3 at a time to balance speed and reliability
        const CONCURRENT_LIMIT = 3;
        const suggestions = [];
        
        for (let i = 0; i < sourceNodes.length; i += CONCURRENT_LIMIT) {
            const batch = sourceNodes.slice(i, i + CONCURRENT_LIMIT);
            console.log(`🔄 Processing batch ${Math.floor(i / CONCURRENT_LIMIT) + 1}/${Math.ceil(sourceNodes.length / CONCURRENT_LIMIT)} (elements ${i + 1}-${Math.min(i + CONCURRENT_LIMIT, sourceNodes.length)})`);
            
            const batchPromises = batch.map(sourceNode => 
                generateMappingSuggestion(sourceNode, targetNodes, context)
                    .then(result => {
                        console.log(`✅ Completed suggestion for ${sourceNode.name}`);
                        return result;
                    })
                    .catch(error => {
                        console.error(`❌ Failed suggestion for ${sourceNode.name}:`, error.message);
                        return {
                            error: error.message,
                            sourceNode: sourceNode
                        };
                    })
            );
            
            const batchResults = await Promise.all(batchPromises);
            suggestions.push(...batchResults);
        }
        
        console.log(`🎉 Batch processing complete: ${suggestions.length} suggestions generated`);
        return suggestions;
        
    } catch (error) {
        console.error('Batch mapping error:', error);
        throw new Error(`Batch mapping failed: ${error.message}`);
    }
}

/**
 * Check if user has access to AI features based on subscription level
 * @param {number} userId - User ID to check subscription
 * @returns {Promise<boolean>} True if user has access to AI features
 */
async function checkAIFeatureAccess(userId) {
    const db = require('../db');
    
    try {
        const result = await db.query(`
            SELECT s.level, s.status
            FROM subscriptions s
            WHERE s.user_id = $1 AND s.status = 'active'
        `, [userId]);
        
        if (result.rows.length === 0) {
            console.log(`No active subscription found for user ID: ${userId}`);
            return false;
        }
        
        const subscription = result.rows[0];
        const hasAIAccess = ['pro', 'enterprise'].includes(subscription.level.toLowerCase());
        
        console.log(`User ${userId} subscription level: ${subscription.level}, AI access: ${hasAIAccess}`);
        return hasAIAccess;
        
    } catch (error) {
        console.error('Subscription check error:', error);
        return false;
    }
}

module.exports = {
    generateMappingSuggestion,
    generateBatchMappingSuggestions,
    checkAIFeatureAccess
};