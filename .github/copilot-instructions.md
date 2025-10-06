# Project Overview: ROSSUMXML Mapping Tool

This is a full-stack project for XML data visualization and transformation. The codebase is divided into two parts: 'frontend' and 'backend'.

## A. Current Development Setup and Tech Stack

- **Architecture:** Monorepo with a dedicated Frontend and Backend.
- **Frontend (Directory: 'frontend'):**
    - **Stack:** React using Vite.
    - **Dev Environment:** Runs on port 5173. HMR is currently disabled for stability (likely due to a development container setup).
    - **API Gateway:** All requests to `/api` are proxied to the backend at `http://localhost:3000`.
- **Backend (Directory: 'backend'):**
    - **Stack:** Node.js (JavaScript).
    - **Core Function:** Provides an API to parse and structure XML data from strings.
    - **Database:** PostgreSQL (Postgres:13) is defined in Docker Compose, running on port 5432.

## B. 🛑 ABSOLUTE CONSTRAINTS: DO NOT MODIFY 🛑

The existing XML parsing, transformation, and selector logic is considered stable and production-ready. **DO NOT modify this code** unless explicitly directed by the user for a new feature outside of core parsing mechanics.

**Protected Logic:** Do NOT modify the functions in `backend/services/xmlParser.service.js` or any other file related to XML processing, tree creation, or mapping/transformation rules.

## C. 🎯 Copilot Behavior Rules (Accuracy & Safety) 🎯

### 1. **Code Safety and Minimal Intervention**
- **Rule:** Prioritize minimal viable changes. Only generate the exact code needed for the user's request.
- **Rule:** **Never** add unnecessary comments, redundant code, or introduce external libraries/dependencies unless explicitly told to install them.
- **Rule:** Before any change, confirm that the request does not violate the Absolute Constraints (Section B).

### 2. **Context Refresh Routine (To Preserve Accuracy)**
- **Rule:** After every **5 prompts** (including the current prompt), Copilot **must** output the following message:

> **[Context Refresh]** I am summarizing the last 5 prompts, resetting my internal context, and re-applying the core project constraints for fresh accuracy. Please confirm to continue the conversation.

***

## 2. Update VS Code `settings.json` (Slowing Inline Suggestions)

To reduce the aggressiveness of the inline suggestions and increase goal understanding, you need to update your VS Code settings. The `minShowDelay` value introduces a slight pause before suggestions appear, helping prevent irrelevant suggestions from "spiraling off."

**File:** `.vscode/settings.json`

Merge the following new settings into your existing file:

```json
{
    "python-envs.defaultEnvManager": "ms-python.python:system",
    "python-envs.pythonProjects": [],
    
    // --- Copilot / Editor Settings for Careful Interaction ---
    
    "editor.inlineSuggest.minShowDelay": 500, 
    // ^ Delay in milliseconds before inline suggestions appear. Set to 500ms (0.5 seconds) to slow down aggressive suggestions.

    "github.copilot.nextEditSuggestions.enabled": false,
    // ^ Disabling this prevents Copilot from trying to predict and offer multi-line refactoring/next steps, forcing single-file focus.

    "github.copilot.internal.editor.inlineSuggest.debounce": 200,
    // ^ Adds a slight debounce to when completions are requested, improving accuracy.

    "github.copilot.nextEditSuggestions.fixes": false
    // ^ Disables automatically suggesting fixes based on diagnostics, ensuring you control the fix.
}
```
