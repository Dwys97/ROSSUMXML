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
        
        // Craft a highly specific prompt for XML schema mapping
        const prompt = `You are an expert in XML schema mapping and data transformation. Your task is to suggest the best target element for mapping a source XML element.

SOURCE ELEMENT TO MAP:
Name: ${sourceNode.name}
Path: ${sourceNode.path}
Type: ${sourceNode.type || 'element'}

AVAILABLE TARGET ELEMENTS (ZERO-BASED INDEXING):
${targetNodes.map((node, index) => `${index}. ${node.name} (Path: ${node.path})`).join('\n')}

CONTEXT:
- Source Schema: ${context.sourceSchema || 'Unknown'}
- Target Schema: ${context.targetSchema || 'Unknown'}
- Existing Mappings: ${context.existingMappings ? context.existingMappings.length : 0} mappings already created

TASK:
Analyze the source element "${sourceNode.name}" and suggest the BEST target element to map to. Consider:
1. Semantic similarity (meaning and purpose)
2. Data type compatibility
3. Naming conventions and patterns
4. Business logic relationships
5. Existing mapping context

RESPONSE FORMAT (JSON):
{
  "targetElementIndex": <number 0-${targetNodes.length - 1}>,
  "confidence": <number 0-100>,
  "reasoning": "<explanation>",
  "dataTypeMatch": "<high|medium|low>",
  "semanticMatch": "<high|medium|low>"
}

CRITICAL INDEXING RULES:
- targetElementIndex MUST be between 0 and ${targetNodes.length - 1} (inclusive)
- The target elements are numbered starting from 0 (ZERO-BASED)
- Element 0 is the first element, element ${targetNodes.length - 1} is the last element
- DO NOT use 1-based indexing or indices beyond ${targetNodes.length - 1}

Choose the SINGLE best match and respond ONLY with valid JSON.`;

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

        console.log(`🔍 Available target nodes count: ${targetNodes.length}`);
        console.log(`🎯 AI suggested target index: ${suggestion.targetElementIndex}`);

        // Validate and auto-correct common AI indexing errors
        if (suggestion.targetElementIndex < 0 || suggestion.targetElementIndex >= targetNodes.length) {
            console.log(`❌ Invalid target index ${suggestion.targetElementIndex}, available indices: 0-${targetNodes.length - 1}`);
            
            // Try to correct common off-by-one errors
            if (suggestion.targetElementIndex === targetNodes.length) {
                console.log('🔧 Correcting off-by-one error: reducing index from', suggestion.targetElementIndex, 'to', targetNodes.length - 1);
                suggestion.targetElementIndex = targetNodes.length - 1;
            } else if (suggestion.targetElementIndex > targetNodes.length) {
                console.log('🔧 Correcting 1-based indexing error: setting index to', targetNodes.length - 1);
                suggestion.targetElementIndex = targetNodes.length - 1;
            } else if (suggestion.targetElementIndex < 0) {
                console.log('🔧 Correcting negative index: setting to 0');
                suggestion.targetElementIndex = 0;
            } else {
                throw new Error('AI suggested an invalid target element index');
            }
        }

        // Validate and return the suggestion
        const selectedTarget = targetNodes[suggestion.targetElementIndex];
        if (!selectedTarget) {
            console.log(`❌ Still invalid target index ${suggestion.targetElementIndex} after correction, available indices: 0-${targetNodes.length - 1}`);
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
 * Generate batch mapping suggestions for multiple target elements
 * @param {Array} sourceNodes - Array of source XML schema nodes  
 * @param {Array} targetNodes - Array of potential target nodes
 * @param {Object} context - Additional context (existing mappings, schema info)
 * @returns {Promise<Array>} Array of suggestions with confidence scores
 */
async function generateBatchMappingSuggestions(sourceNodes, targetNodes, context = {}) {
    try {
        const suggestions = [];
        
        // Process in smaller batches to avoid API limits
        const batchSize = 5;
        for (let i = 0; i < sourceNodes.length; i += batchSize) {
            const batch = sourceNodes.slice(i, i + batchSize);
            const batchPromises = batch.map(sourceNode => 
                generateMappingSuggestion(sourceNode, targetNodes, context)
                    .catch(error => ({
                        error: error.message,
                        sourceNode: sourceNode
                    }))
            );
            
            const batchResults = await Promise.all(batchPromises);
            suggestions.push(...batchResults);
            
            // Add a small delay between batches to respect API limits
            if (i + batchSize < sourceNodes.length) {
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }
        
        return suggestions;
    } catch (error) {
        console.error('Batch mapping error:', error);
        throw new Error(`Batch mapping failed: ${error.message}`);
    }
}

/**
 * Check if user has access to AI features based on subscription level
 * @param {string} userEmail - User email to check subscription
 * @returns {Promise<Object>} Access information and subscription details
 */
async function checkAIFeatureAccess(userEmail) {
    const db = require('../db');
    
    try {
        const result = await db.query(`
            SELECT u.email, s.level, s.status, s.features
            FROM users u
            JOIN subscriptions s ON u.id = s.user_id
            WHERE u.email = $1 AND s.status = 'active'
        `, [userEmail]);
        
        if (result.rows.length === 0) {
            return {
                hasAccess: false,
                reason: 'No active subscription found',
                currentLevel: 'free'
            };
        }
        
        const subscription = result.rows[0];
        const hasAIAccess = ['pro', 'enterprise'].includes(subscription.level.toLowerCase());
        
        return {
            hasAccess: hasAIAccess,
            currentLevel: subscription.level,
            features: subscription.features || [],
            reason: hasAIAccess ? null : 'AI features require Pro or Enterprise subscription'
        };
        
    } catch (error) {
        console.error('Subscription check error:', error);
        return {
            hasAccess: false,
            reason: 'Error checking subscription status',
            currentLevel: 'unknown'
        };
    }
}

module.exports = {
    generateMappingSuggestion,
    generateBatchMappingSuggestions,
    checkAIFeatureAccess
};