# AI Mapping Suggestions - User Guide

## Quick Start

### How to Use AI Suggestions

1. **Upload XML Files**
   - Upload Source XML schema
   - Upload Target XML schema

2. **Single Element Suggestion**
   - Hover over any **target** element
   - Click the ✨ **AI** button
   - Review the suggestion
   - Click **Accept** or **Reject**
   - Click **Regenerate** for a different suggestion

3. **Batch Suggestions**
   - Click **"Suggest All Mappings"** button in Mappings panel
   - Wait for AI to process (5-45 seconds)
   - Review all suggestions in modal
   - Select checkboxes for suggestions you want
   - Click **"Accept Selected"** or **"Accept All"**
   - Click **"Regenerate"** on individual suggestions to try again
   - Click **"Done"** when finished

---

## Features

### ✨ Smart Mapping
- AI analyzes element names, types, and schema context
- Suggests best matches with confidence scores
- Learns from existing mappings

### 🎯 Intelligent Filtering
- Only suggests unmapped elements
- Handles duplicate names at different paths
- Example: "InvoiceNumber" at header level vs item level treated separately

### 🔄 Flexible Regeneration
- **Individual:** Regenerate one suggestion at a time
- **Batch:** Regenerate all suggestions together
- **Persistent:** Modal stays open for multiple accepts

### 🎨 Delightful UX
- **Poof Animation:** Accepted suggestions disappear with smooth animation
- **Auto-Close:** Modal closes automatically when all suggestions accepted
- **Dynamic Counts:** See remaining suggestions update in real-time

### ⚡ Performance Optimized
- Processes 5 elements at a time (60s timeout limit)
- Automatically handles large schemas
- Shows progress for remaining elements

---

## Tips for Best Results

1. **Map Key Fields First**
   - Manually map a few obvious fields (e.g., ID, Name, Date)
   - AI uses these as context for better suggestions

2. **Use Batch for Bulk Work**
   - Good for initial mapping setup
   - Quickly map similar/obvious fields

3. **Use Single for Complex Fields**
   - Better for ambiguous or business-specific fields
   - More control over each mapping

4. **Review Confidence Scores**
   - 🟢 High (80-100%): Very likely correct
   - 🟡 Medium (60-79%): Review carefully
   - 🔴 Low (<60%): Double-check mapping

5. **Regenerate if Unsure**
   - AI might find better match on second try
   - Different suggestions for different contexts

---

## Subscription Requirements

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| Manual Mapping | ✅ | ✅ | ✅ |
| AI Single Suggestion | ❌ | ✅ | ✅ |
| AI Batch Suggestions | ❌ | ✅ | ✅ |

**Upgrade to Pro or Enterprise to unlock AI features!**

---

## Troubleshooting

### "AI features are only available for Pro/Enterprise subscribers"
- You're on Free tier
- Click upgrade prompt to see pricing

### Batch suggestions taking long time
- Normal for first batch (5-45 seconds)
- Processing 5 elements at a time
- Run again for next batch of remaining elements

### No suggestions showing up
- Ensure both Source and Target XML files are uploaded
- Check that there are unmapped elements
- Try single suggestion first to test AI access

### Suggestion doesn't look right
- Click **"Regenerate"** to get a different suggestion
- Confidence score might be low - review carefully
- You can always manually drag-and-drop instead

---

## Keyboard Shortcuts

- **Tab**: Navigate between suggestions
- **Space**: Toggle checkbox selection
- **Enter**: Accept selected suggestions
- **Esc**: Close modal

---

## Technical Limits

- **Batch Size:** 5 elements per batch (prevents timeout)
- **Timeout:** 60 seconds maximum per batch
- **Targets per Request:** 50 maximum (optimized for speed)
- **Regenerate:** Unlimited (no rate limit)

---

## Feedback

Found a bug or have a suggestion? Contact support or submit an issue on GitHub.

**Enjoy faster XML mapping with AI! 🚀**
