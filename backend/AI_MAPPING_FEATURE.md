# AI-Powered Mapping Suggestion Feature

## Overview
This feature provides intelligent XML mapping suggestions using Google's Gemini AI API. It's available exclusively for **Pro** and **Enterprise** subscription tiers.

## Architecture

### Backend Components

#### 1. AI Service (`backend/services/aiMapping.service.js`)
- **Purpose**: Core AI integration with Google Gemini API
- **Key Functions**:
  - `generateMappingSuggestion(sourceNode, targetNodes, context)`: Generates a single mapping suggestion
  - `generateBatchMappingSuggestions(mappingRequests)`: Processes multiple mapping requests efficiently
  - `checkAIFeatureAccess(pool, userId)`: Verifies subscription level

#### 2. API Endpoints (`backend/index.js`)

##### `/api/ai/suggest-mapping` (POST)
- **Purpose**: Generate single AI mapping suggestion
- **Authentication**: JWT required
- **Subscription**: Pro or Enterprise
- **Request Body**:
  ```json
  {
    "sourceNode": {
      "name": "InvoiceNumber",
      "path": "/Export/Invoices/Invoice/InvoiceNumber",
      "type": "element",
      "value": "99146873"
    },
    "targetNodes": [
      {
        "name": "DocumentID",
        "path": "/Import/Documents/Document/DocumentID",
        "type": "element"
      },
      {
        "name": "RefNumber",
        "path": "/Import/Documents/Document/RefNumber",
        "type": "element"
      }
    ],
    "context": {
      "sourceSchema": "Rossum Export Schema",
      "targetSchema": "CloudWorks Import Schema",
      "existingMappings": []
    }
  }
  ```
- **Response**:
  ```json
  {
    "suggestion": {
      "sourceElement": "/Export/Invoices/Invoice/InvoiceNumber",
      "targetElement": "/Import/Documents/Document/DocumentID",
      "confidence": 0.95,
      "reasoning": "InvoiceNumber semantically matches DocumentID as primary identifier"
    }
  }
  ```

##### `/api/ai/suggest-mappings-batch` (POST)
- **Purpose**: Generate multiple AI mapping suggestions in one request
- **Authentication**: JWT required
- **Subscription**: Pro or Enterprise
- **Request Body**:
  ```json
  {
    "mappingRequests": [
      {
        "sourceNode": {...},
        "targetNodes": [...],
        "context": {...}
      },
      ...
    ]
  }
  ```
- **Response**:
  ```json
  {
    "suggestions": [
      {
        "sourceElement": "...",
        "targetElement": "...",
        "confidence": 0.95,
        "reasoning": "..."
      },
      ...
    ]
  }
  ```

##### `/api/ai/check-access` (GET)
- **Purpose**: Check if current user has access to AI features
- **Authentication**: JWT required
- **Response**:
  ```json
  {
    "hasAccess": true,
    "message": "AI features are available"
  }
  ```

### Error Responses

#### 403 Forbidden (Free Tier)
```json
{
  "error": "AI features are only available for Pro and Enterprise subscribers",
  "upgradeUrl": "/pricing"
}
```

#### 400 Bad Request
```json
{
  "error": "Missing required fields: sourceNode and targetNodes (array)"
}
```

#### 500 Internal Server Error
```json
{
  "error": "Failed to generate AI suggestion",
  "details": "Error message here"
}
```

## Frontend Integration

### User Flow

1. **Check Access**: On Editor page load, call `/api/ai/check-access`
2. **Show AI Button**: If `hasAccess === true`, show "AI Suggest" button next to unmapped elements
3. **Request Suggestion**: When user clicks "AI Suggest", call `/api/ai/suggest-mapping`
4. **Display Results**: Show suggestion with confidence score and reasoning
5. **User Action**: User can:
   - **Accept**: Apply the suggested mapping
   - **Reject**: Dismiss the suggestion
   - **Regenerate**: Request a new suggestion with different context

### UI Components (To Be Created)

#### `AISuggestionButton.jsx`
- Button component shown next to target elements
- Shows loading state during AI processing
- Hidden for free tier users

#### `AISuggestionModal.jsx`
- Modal displaying AI suggestion
- Shows confidence score (visual indicator)
- Shows reasoning (why this mapping was suggested)
- Action buttons: Accept, Reject, Regenerate

#### `UpgradePrompt.jsx`
- Shown when free tier user clicks AI features
- Links to /pricing page
- Explains Pro/Enterprise benefits

## Environment Configuration

Add to `backend/env.json`:
```json
{
  "TransformFunction": {
    "GEMINI_API_KEY": "your-google-gemini-api-key-here"
  }
}
```

Get API key from: https://makersuite.google.com/app/apikey

## Database Schema

The feature uses the existing `subscriptions` table:
```sql
CREATE TABLE IF NOT EXISTS subscriptions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    level VARCHAR(20) NOT NULL,  -- 'free', 'pro', 'enterprise'
    status VARCHAR(20) NOT NULL,  -- 'active', 'canceled', 'expired'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Gemini API Configuration

- **Model**: `gemini-pro`
- **Temperature**: 0.2 (lower = more deterministic)
- **Top K**: 40
- **Top P**: 0.95
- **Max Output Tokens**: 2048
- **Rate Limit**: Free tier = 60 requests/minute

## Prompt Engineering

The AI service uses a sophisticated prompt that includes:
1. **Context**: Source and target schema descriptions
2. **XML Structure**: Full XPath information for semantic understanding
3. **Existing Mappings**: To avoid duplicate suggestions and maintain consistency
4. **Task**: Clear instruction to map source element to best target match
5. **Constraints**: Output format (JSON), confidence scoring rules
6. **Examples**: Few-shot learning with sample mappings

## Testing

### Manual Testing
```bash
# 1. Check AI access
curl -X GET http://localhost:3000/api/ai/check-access \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# 2. Request single suggestion
curl -X POST http://localhost:3000/api/ai/suggest-mapping \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "sourceNode": {
      "name": "InvoiceNumber",
      "path": "/Export/Invoices/Invoice/InvoiceNumber",
      "type": "element"
    },
    "targetNodes": [
      {
        "name": "DocumentID",
        "path": "/Import/Documents/Document/DocumentID",
        "type": "element"
      }
    ],
    "context": {
      "sourceSchema": "Rossum Export",
      "targetSchema": "CloudWorks Import"
    }
  }'
```

## Future Enhancements

1. **Confidence Threshold**: Only show suggestions above certain confidence level
2. **User Feedback Loop**: Let users rate suggestions to improve prompts
3. **Batch Auto-Mapping**: Auto-map high confidence (>90%) suggestions
4. **Learning from User Corrections**: Store user corrections to improve future suggestions
5. **Schema Understanding**: Pre-analyze schemas to build semantic understanding
6. **Multi-Model Support**: Add support for Claude, GPT-4, etc.

## Security Considerations

- API key stored in environment variables (not in code)
- Subscription verification on every request
- Rate limiting to prevent abuse
- No sensitive data sent to Gemini API (only schema structure)
- JWT authentication required for all endpoints

## Performance

- Single suggestion: ~2-5 seconds (Gemini API latency)
- Batch suggestions: ~5-10 seconds for 10 mappings (sequential processing)
- Caching: Consider implementing schema-level caching for repeated requests

## Cost Analysis (Gemini Free Tier)

- **Free Quota**: 60 requests/minute
- **Cost**: $0 (free tier)
- **Upgrade Path**: Google Cloud billing if exceeding free limits
- **Alternative**: Add Claude/GPT-4 with paid plans

## Support

For issues or questions:
- Check backend logs: `get_task_output` for "Start Backend" task
- Verify GEMINI_API_KEY is set in env.json
- Check subscription level in database
- Test with curl commands above
