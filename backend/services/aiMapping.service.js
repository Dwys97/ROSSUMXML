// backend/services/aiMapping.service.js

// Initialize Gemini AI
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

// Direct REST API approach using fetch to bypass v1beta issue
// Includes retry logic with exponential backoff for rate limiting (429 errors)
async function makeDirectGeminiRequest(prompt, apiKey, retryCount = 0) {
    const MAX_RETRIES = 3;
    const BASE_DELAY = 2000; // 2 seconds
    
    const url = `https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key=${apiKey}`;
    
    try {
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
        
        // Handle rate limiting (429 Too Many Requests)
        if (response.status === 429 && retryCount < MAX_RETRIES) {
            const delay = BASE_DELAY * Math.pow(2, retryCount); // Exponential backoff: 2s, 4s, 8s
            console.log(`⏳ Rate limited (429). Retrying in ${delay/1000}s... (attempt ${retryCount + 1}/${MAX_RETRIES})`);
            
            await new Promise(resolve => setTimeout(resolve, delay));
            return makeDirectGeminiRequest(prompt, apiKey, retryCount + 1);
        }
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Gemini API error:', errorText);
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        return data.candidates[0].content.parts[0].text;
        
    } catch (error) {
        // Network errors or other fetch failures
        if (retryCount < MAX_RETRIES) {
            const delay = BASE_DELAY * Math.pow(2, retryCount);
            console.log(`⚠️ Request failed: ${error.message}. Retrying in ${delay/1000}s... (attempt ${retryCount + 1}/${MAX_RETRIES})`);
            
            await new Promise(resolve => setTimeout(resolve, delay));
            return makeDirectGeminiRequest(prompt, apiKey, retryCount + 1);
        }
        
        throw error;
    }
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
        
        // Extract element values from names (format: "ElementName: 'value'" or "ElementName")
        const extractValue = (name) => {
            const valueMatch = name.match(/:\s*["']([^"']+)["']/);
            return valueMatch ? valueMatch[1] : null;
        };
        
        const sourceValue = extractValue(sourceNode.name);
        const sourceBaseName = sourceNode.name.split(':')[0].trim();
        
        // Extract base field name without path prefixes for better matching
        const getFieldName = (fullName) => {
            // Extract schema_id or last path component
            const schemaIdMatch = fullName.match(/schema_id="([^"]+)"/);
            if (schemaIdMatch) return schemaIdMatch[1];
            
            // Otherwise get last part of path
            const parts = fullName.split(' > ');
            return parts[parts.length - 1].split('[')[0].split(':')[0].trim();
        };
        
        // Extract hierarchical context from path (parent elements)
        const getPathContext = (path) => {
            if (!path) return [];
            const parts = path.split(' > ');
            // Return all parent elements for context
            return parts.map(p => p.split('[')[0].trim());
        };
        
        const sourceFieldName = getFieldName(sourceNode.name);
        const sourcePathContext = getPathContext(sourceNode.path);
        
        // Extract immediate parent for focused context
        const sourceParent = sourcePathContext.length > 1 
            ? sourcePathContext[sourcePathContext.length - 2] 
            : 'root';
        
        // Extract section type for Rossum data (basic_info, vendor, line_items, etc.)
        const extractSectionType = (path) => {
            const sectionMatch = path.match(/section[^>]*schema_id="([^"]+)"/);
            if (sectionMatch) return sectionMatch[1];
            
            // Check for multivalue/tuple (line items)
            if (path.includes('multivalue') && path.includes('tuple')) return 'line_items';
            if (path.includes('section')) return 'header_section';
            
            return null;
        };
        
        const sourceSectionType = extractSectionType(sourceNode.path);
        
        // Normalize field names by removing common prefixes/suffixes
        const normalizeFieldName = (fieldName) => {
            let normalized = fieldName.toLowerCase();
            
            // Remove common prefixes: Item_, Line_, Field_, Src_, Dest_, Doc_, Inv_, Order_
            normalized = normalized.replace(/^(item|line|field|src|dest|doc|inv|invoice|order|header|detail|row)_/, '');
            
            // Remove common suffixes: _value, _code, _text, _id, _number
            normalized = normalized.replace(/_(value|code|text|id|number|num|no)$/, '');
            
            return normalized;
        };
        
        // Calculate string similarity hints for the AI
        const calculateSimilarity = (str1, str2) => {
            // Apply normalization FIRST to remove prefixes/suffixes
            const normalized1 = normalizeFieldName(str1);
            const normalized2 = normalizeFieldName(str2);
            
            const s1 = normalized1.replace(/[_\s-]/g, '');
            const s2 = normalized2.replace(/[_\s-]/g, '');
            
            // Exact match (after normalization)
            if (s1 === s2) return 100;
            
            // Contains match
            if (s1.includes(s2) || s2.includes(s1)) return 85;
            
            // Common abbreviations
            const abbrevMap = {
                'invoice': 'inv',
                'number': 'no|num|nbr',
                'amount': 'amt|total',
                'date': 'dt',
                'quantity': 'qty',
                'description': 'desc',
                'address': 'addr',
                'reference': 'ref',
                'document': 'doc',
                'vendor': 'supplier|seller|exporter',
                'customer': 'buyer|importer|consignee'
            };
            
            for (const [full, abbrevs] of Object.entries(abbrevMap)) {
                const patterns = abbrevs.split('|');
                if ((s1.includes(full) && patterns.some(p => s2.includes(p))) ||
                    (s2.includes(full) && patterns.some(p => s1.includes(p)))) {
                    return 75;
                }
            }
            
            // Levenshtein distance approximation
            const maxLen = Math.max(s1.length, s2.length);
            let matches = 0;
            for (let i = 0; i < Math.min(s1.length, s2.length); i++) {
                if (s1[i] === s2[i]) matches++;
            }
            return Math.round((matches / maxLen) * 100);
        };
        
        // Pre-calculate top candidates with path context analysis
        const targetCandidatesWithScores = limitedTargetNodes.map((node, index) => {
            const targetFieldName = getFieldName(node.name);
            const targetPathContext = getPathContext(node.path);
            const targetValue = extractValue(node.name);
            const targetParent = targetPathContext.length > 1 
                ? targetPathContext[targetPathContext.length - 2] 
                : 'root';
            
            // Calculate field name similarity (most important)
            const nameSimilarity = calculateSimilarity(sourceFieldName, targetFieldName);
            
            // Log normalization for debugging (only for high similarity matches)
            if (nameSimilarity >= 70 && index < 10) {
                console.log(`🔍 Field match: "${sourceFieldName}" → "${targetFieldName}" = ${nameSimilarity}%`);
                console.log(`   Normalized: "${normalizeFieldName(sourceFieldName)}" → "${normalizeFieldName(targetFieldName)}"`);
            }
            
            // Calculate parent context similarity (immediate parent match is critical)
            const parentSimilarity = calculateSimilarity(sourceParent, targetParent);
            
            // Calculate full path context similarity (for additional validation)
            let pathSimilarity = 0;
            const sourceParents = sourcePathContext.slice(0, -1); // exclude field itself
            const targetParents = targetPathContext.slice(0, -1);
            
            if (sourceParents.length > 0 && targetParents.length > 0) {
                // Check if paths share common parent structures
                let matchingParents = 0;
                sourceParents.forEach(srcParent => {
                    targetParents.forEach(tgtParent => {
                        if (calculateSimilarity(srcParent, tgtParent) > 70) {
                            matchingParents++;
                        }
                    });
                });
                pathSimilarity = Math.min(100, (matchingParents / Math.max(sourceParents.length, targetParents.length)) * 100);
            }
            
            // Calculate value compatibility
            let valueCompatibility = 0;
            if (sourceValue && targetValue) {
                valueCompatibility = calculateSimilarity(sourceValue, targetValue);
            }
            
            // Combined score with updated weights:
            // - Field name: 60% (most important)
            // - Immediate parent: 25% (critical for context)
            // - Full path: 10% (additional validation)
            // - Value: 5% (data validation)
            const combinedScore = Math.round(
                (nameSimilarity * 0.60) + 
                (parentSimilarity * 0.25) +
                (pathSimilarity * 0.10) + 
                (valueCompatibility * 0.05)
            );
            
            return {
                index,
                name: targetFieldName,
                fullName: node.name.split(':')[0].trim(),
                value: targetValue,
                path: node.path,
                pathContext: targetPathContext,
                parent: targetParent,
                nameSimilarity,
                parentSimilarity,
                pathSimilarity,
                valueCompatibility,
                combinedScore
            };
        });
        
        // Sort by combined score to prioritize likely matches
        const topCandidates = targetCandidatesWithScores
            .sort((a, b) => b.combinedScore - a.combinedScore)
            .slice(0, 20); // Show top 20 most similar
        
        const otherCandidates = targetCandidatesWithScores
            .filter(c => !topCandidates.includes(c));
        
        // Create a mapping of display index to actual array index for AI response parsing
        // This is needed because we show AI a re-ordered list (top 20 first)
        const displayIndexToActualIndex = new Map();
        
        // Top 20 candidates keep their original indices but are shown first
        topCandidates.forEach((candidate) => {
            displayIndexToActualIndex.set(candidate.index, candidate.index);
        });
        
        // Other candidates also keep their original indices
        otherCandidates.forEach((candidate) => {
            displayIndexToActualIndex.set(candidate.index, candidate.index);
        });
        
        // Enhanced prompt with deep path structure analysis - PATH-FIRST approach
        const prompt = `You are an XML schema mapping expert. You MUST analyze path structures FIRST before considering field names.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 SOURCE ELEMENT ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Field: "${sourceFieldName}"${sourceValue ? ` | Sample: "${sourceValue}"` : ''}

PATH STRUCTURE:
${sourcePathContext.map((el, idx) => {
    const indent = '  '.repeat(idx);
    const icon = idx === 0 ? '📦' : idx === sourcePathContext.length - 1 ? '🎯' : idx === sourcePathContext.length - 2 ? '📂' : '📁';
    return `${indent}${icon} ${el}`;
}).join('\n')}

CONTEXT INDICATORS:
• Depth: ${sourcePathContext.length} levels
• Parent: "${sourceParent}"
${sourceSectionType ? `• Section: ${sourceSectionType}` : ''}
${sourcePathContext.includes('section') && !sourcePathContext.includes('multivalue') ? '• ✅ HEADER-LEVEL FIELD (in "section", not in "multivalue")' : ''}
${sourcePathContext.includes('multivalue') && sourcePathContext.includes('tuple') ? '• ✅ LINE ITEM FIELD (in "multivalue > tuple")' : ''}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 TARGET CANDIDATES (${limitedTargetNodes.length} total, showing top ${topCandidates.length} by score)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${topCandidates.map(c => {
    const isHeaderLevel = c.pathContext.includes('Header') || c.pathContext.length <= 3;
    const isLineItemLevel = c.pathContext.includes('LineItem') || c.pathContext.includes('Line');
    
    return `┌─ INDEX ${c.index}: ${c.name} │ SCORE: ${c.combinedScore}% │ Name: ${c.nameSimilarity}% │ Parent: ${c.parentSimilarity}%
│  ${c.value ? `Sample: "${c.value}"` : 'No sample data'}
│  Parent: "${c.parent}"
│  Path: ${c.pathContext.join(' → ')}
│  ${isHeaderLevel ? '✅ HEADER-LEVEL' : isLineItemLevel ? '✅ LINE ITEM-LEVEL' : '⚠️  Other level'}
└─────────────────────────────────────────────────────────────────────────`;
}).join('\n\n')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🧠 MAPPING DECISION PROCESS (FOLLOW EXACTLY)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

STEP 1️⃣ : IDENTIFY SOURCE LEVEL
${sourcePathContext.includes('multivalue') && sourcePathContext.includes('tuple') 
    ? '   → SOURCE IS LINE ITEM LEVEL (in multivalue > tuple)' 
    : '   → SOURCE IS HEADER LEVEL (in section, not in multivalue)'}

STEP 2️⃣ : FILTER TARGETS BY LEVEL
${sourcePathContext.includes('multivalue') && sourcePathContext.includes('tuple')
    ? '   → ONLY consider candidates with "LineItem" or "Line" in path'
    : '   → ONLY consider candidates with "Header" in path OR root-level (depth ≤ 3)'}
   → REJECT candidates at wrong hierarchical level!

STEP 3️⃣ : WITHIN CORRECT LEVEL, MATCH FIELD NAME
   → Source field: "${sourceFieldName}"
   → Find target with most similar name
   → Consider: exact match > abbreviation > synonym

STEP 4️⃣ : VERIFY PARENT CONTEXT
   → Source parent: "${sourceParent}"
   → Check if target parent is semantically similar
   → Boost confidence if parents align

STEP 5️⃣ : VALIDATE VALUE/TYPE
   ${sourceValue ? `→ Source value: "${sourceValue}"` : '→ No source value to validate'}
   → Ensure data types are compatible

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ CORRECT MATCH EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Example 1: HEADER-LEVEL FIELD
Source: section > InvoiceNumber
Target: Header > DocNumber ✅ CORRECT
Reason: Both header-level, similar names, same business context

Example 2: LINE ITEM FIELD
Source: multivalue > tuple > Item_description
Target: LineItems > LineItem > Description ✅ CORRECT
Reason: Both line-item level, field name match

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❌ WRONG MATCH EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Example 1: WRONG LEVEL (even with name match!)
Source: section > Description (HEADER-LEVEL)
Target: LineItems > LineItem > Description ❌ WRONG!
Reason: Header field mapped to line item - hierarchical mismatch!

Example 2: WRONG LEVEL (even with name match!)
Source: multivalue > tuple > Quantity (LINE ITEM-LEVEL)
Target: Header > TotalQuantity ❌ WRONG!
Reason: Line item field mapped to header total - different context!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📏 PATH LEVEL RULES (CRITICAL - DO NOT VIOLATE)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Rossum "section" (without multivalue) → Target "Header" or root-level only
Rossum "multivalue > tuple" → Target "LineItem" or "Line" children only

PARENT EQUIVALENTS:
"section" ≈ "Header", "Root", "Document"
"tuple" ≈ "LineItem", "Item", "Line"
"multivalue" ≈ "LineItems", "Items", "Lines" (parent of repeating elements)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔢 CONFIDENCE SCORING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

95-100%: Correct level + exact field name + matching parent
90-94%:  Correct level + near-exact field name (abbreviation)
80-89%:  Correct level + synonym field name + compatible type
70-79%:  Correct level + related field name
<70%:    Wrong hierarchical level OR weak field name match
<50%:    REJECT - incompatible path structures

CRITICAL: If path levels don't match (header vs line item), confidence MUST be <60%!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📤 RESPONSE (JSON ONLY)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{
  "targetElementIndex": <0-${limitedTargetNodes.length - 1}>,
  "confidence": <0-100>,
  "reasoning": "1. Path level: [header/line item match]. 2. Field name: [similarity]. 3. Parent: [alignment]",
  "dataTypeMatch": "high|medium|low",
  "semanticMatch": "high|medium|low"
}

REMEMBER: PATH STRUCTURE MATCH IS MANDATORY! Field name similarity is secondary.
Return ONLY JSON, no markdown.`;

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
        
        // Debug: Log the target node at the suggested index
        if (suggestion.targetElementIndex >= 0 && suggestion.targetElementIndex < limitedTargetNodes.length) {
            const suggestedNode = limitedTargetNodes[suggestion.targetElementIndex];
            console.log(`📍 Suggested target node:`, {
                name: suggestedNode.name,
                path: suggestedNode.path,
                type: suggestedNode.type
            });
        }

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
            console.log(`❌ limitedTargetNodes at index:`, limitedTargetNodes[suggestion.targetElementIndex]);
            throw new Error('AI suggested an invalid target element index');
        }
        
        console.log(`✅ Final selected target:`, {
            name: selectedTarget.name,
            path: selectedTarget.path,
            type: selectedTarget.type
        });

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
        
        // Process requests with controlled concurrency to avoid rate limiting
        // Reduced from 3 to 2 concurrent requests to prevent 429 errors
        const CONCURRENT_LIMIT = 2;
        const DELAY_BETWEEN_BATCHES = 1000; // 1 second delay between batches
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
            
            // Add delay between batches to prevent rate limiting (except for last batch)
            if (i + CONCURRENT_LIMIT < sourceNodes.length) {
                console.log(`⏳ Waiting ${DELAY_BETWEEN_BATCHES}ms before next batch...`);
                await new Promise(resolve => setTimeout(resolve, DELAY_BETWEEN_BATCHES));
            }
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