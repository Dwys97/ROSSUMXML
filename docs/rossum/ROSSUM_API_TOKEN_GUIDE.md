# 🔍 Rossum API Token - Where to Find It

**Updated:** October 15, 2025  
**Issue:** No "API Tokens" option visible in Rossum settings

---

## ✅ What You've Done So Far

- ✅ Configured Extension in Rossum
- ✅ Added Webhook URL: `https://rossumxml-webhook.loca.lt/api/webhook/rossum`
- ✅ Added Configuration JSON
- ✅ Added Secrets JSON with `x-api-key`

**Great! The webhook part is configured correctly.**

---

## 🔑 How to Get Rossum API Token

## Method 1: Using the Rossum API (Recommended)

The most reliable way to obtain your Rossum API token is through the authentication API endpoint.

**Important:** Each Rossum account has its own unique URL prefix (subdomain). The URL format is:
```
https://<your-organization>.rossum.app/api/v1/auth/login
```

For example:
- `https://xmlmapper.rossum.app/api/v1/auth/login`
- `https://acme-corp.rossum.app/api/v1/auth/login`
- `https://east-west-trading.rossum.app/api/v1/auth/login`

**Note:** It's NOT `api.rossum.ai` - each account has a custom prefix!

### Step 1: Login via API

Replace `<your-organization>` with your Rossum account prefix:

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"username": "your-email@example.com", "password": "your-password"}' \
  'https://<your-organization>.rossum.app/api/v1/auth/login'
```

**Example Response:**
```json
{"key": "db313f24f5738c8e04635e036ec8a45cdd6d6b03"}
```

**Important Notes:**
- Use your **Rossum login email** and **password** (same credentials you use to log into Rossum UI)
- The returned `key` is your API token
- This key is valid for **162 hours** (approximately 7 days) by default
- The key remains valid until you explicitly log out or it expires

**To obtain YOUR token, run this command:**

### Step 2: Find Your Organization Prefix

If you don't know your organization prefix, check:
1. The URL you use to log into Rossum (e.g., `https://xmlmapper.rossum.app`)
2. Your Rossum welcome email or account setup documentation
3. Contact your Rossum administrator

### Step 3: Use the Token

The `key` value in the response is your **Rossum API Token**. This token:
- Is valid for **162 hours** (approximately 6.75 days) by default
- Can be used to authenticate API requests to Rossum
- Will expire when you log out or after the timeout period

**Copy this key** - you'll need to add it to your ROSSUMXML API Settings.

---

## Quick Copy-Paste Commands

### Get Token via API
```bash
# Replace YOUR_ORGANIZATION with your Rossum prefix (e.g., xmlmapper, acme-corp, etc.)
# Replace YOUR_EMAIL and YOUR_PASSWORD with your credentials
curl -s -H 'Content-Type: application/json' \
  -d '{"username": "YOUR_EMAIL", "password": "YOUR_PASSWORD"}' \
  'https://YOUR_ORGANIZATION.rossum.app/api/v1/auth/login' | jq -r '.key'
```

### Example (xmlmapper organization):
```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"username": "jijesiv423@bdnets.com", "password": "Cancunmexico2025"}' \
  'https://xmlmapper.rossum.app/api/v1/auth/login' | jq -r '.key'
```

Replace `YOUR_PASSWORD` with your actual Rossum password.

---

### **Method 2: UI-based Token Generation**

The API token location depends on your Rossum account type and version. Here are all the possible locations:

### **Option 1: User Settings → API Tokens**

1. Click your **profile picture** (top right)
2. Click **"Settings"** or **"User Settings"**
3. Look for **"API Tokens"** or **"Access Tokens"** tab
4. Click **"Generate Token"** or **"Create Token"**
5. **Scopes needed:** `annotations:read`, `documents:read`, `exports:read`

### **Option 2: Workspace Settings → API Access**

1. Click **Settings** (gear icon)
2. Click **"Workspace"** or **"Organization"**
3. Look for **"API Access"** or **"API Keys"**
4. Click **"Generate API Key"** or **"Create Token"**

### **Option 3: Organization Settings → Developers**

1. Click **Settings** (gear icon)
2. Click **"Organization Settings"**
3. Look for **"Developers"** or **"API Access"**
4. Click **"Create API Token"**

### **Option 4: Your User Profile**

1. Click your **name/email** (top right)
2. Click **"My Profile"** or **"Account Settings"**
3. Look for **"API Tokens"** or **"Personal Access Tokens"**
4. Click **"Generate"**

---

## 🤔 If You Can't Find API Tokens Option

### **Possible Reasons:**

1. **Your account type doesn't have API access**
   - Solution: Contact Rossum support or upgrade your plan

2. **API tokens are managed by your organization admin**
   - Solution: Ask your Rossum admin to generate a token for you

3. **You need to request API access**
   - Solution: Contact Rossum support at support@rossum.ai

4. **Rossum version/plan doesn't require manual token**
   - Solution: The extension might handle authentication automatically (see below)

---

## 💡 Alternative: Extension Might Handle Authentication

Since you're using a Rossum **Extension** (not a raw webhook), Rossum might:

### **Auto-Authentication:**
- Rossum may automatically authenticate requests to your webhook
- The extension might include authentication headers automatically
- You might not need to configure a Rossum API token manually

### **Test Without Token First:**

Let's test if the webhook works without manually adding a Rossum API token:

1. **Upload a test invoice** to Rossum
2. **Process and export** the annotation
3. **Check ROSSUMXML logs** to see what happens:

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  created_at,
  status,
  error_message,
  request_payload
FROM webhook_events
ORDER BY created_at DESC
LIMIT 5;
"
```

---

## 🔧 What Happens When Rossum Sends Webhook

### **Scenario 1: Extension Provides XML Directly**

If Rossum's extension sends the **XML content directly** in the webhook payload (instead of just a URL), we need to modify our endpoint to handle this.

**Check the webhook payload:**
```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT request_payload 
FROM webhook_events 
ORDER BY created_at DESC 
LIMIT 1;
"
```

If the payload contains XML content directly, we'll need to update the endpoint.

### **Scenario 2: Extension Provides Authenticated URL**

If Rossum sends a pre-authenticated URL to download the XML, our current endpoint should work without needing a separate API token.

### **Scenario 3: We Need API Token (Current Implementation)**

Our current implementation expects:
1. Rossum sends webhook with `annotation.url`
2. We fetch XML from `annotation.url/export` using Rossum API token
3. We transform the XML

---

## 🧪 Testing Steps

### **Step 1: Export a Test Invoice**

1. Go to Rossum
2. Upload a test invoice (or use existing one)
3. Process it
4. Click **"Export"** or mark status as **"Exported"**

### **Step 2: Check if Webhook Was Received**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT 
  TO_CHAR(created_at, 'HH24:MI:SS') as time,
  status,
  error_message,
  LENGTH(request_payload) as payload_size
FROM webhook_events
ORDER BY created_at DESC
LIMIT 5;
"
```

### **Step 3: View the Actual Payload**

```bash
docker exec rossumxml-db-1 psql -U postgres -d rossumxml -c "
SELECT request_payload 
FROM webhook_events 
ORDER BY created_at DESC 
LIMIT 1;
" | head -50
```

### **Step 4: Check Backend Logs**

```bash
docker logs rossumxml-backend-1 --tail 50 2>&1 | grep -i rossum
```

Or if using SAM local:
```bash
ps aux | grep "sam local" | grep -v grep
# Then check the terminal where SAM is running
```

---

## � Troubleshooting Login API

### **Error: "Unable to log in with provided credentials"**

If you get this error, check the following:

1. **Verify your credentials in Rossum UI:**
   - Go to https://rossum.app or your organization's Rossum domain
   - Try logging in with the same email and password
   - If login fails, reset your password

2. **Check for organization-specific domain:**
   - Some organizations use custom Rossum domains like `https://your-company.rossum.app`
   - Try replacing `api.rossum.app` with your organization's domain in the API URL:
   ```bash
   curl -s -H 'Content-Type: application/json' \
     -d '{"username": "your-email@example.com", "password": "your-password"}' \
     'https://your-company.rossum.app/api/v1/auth/login'
   ```

3. **Check for SSO/SAML authentication:**
   - If your organization uses SSO (Single Sign-On), you might need to:
   - Contact your Rossum admin to generate an API token for you
   - OR use the UI-based token generation methods below

4. **Password special characters:**
   - If your password contains special characters (`!`, `$`, `@`, etc.), make sure they're properly escaped
   - Or use single quotes around the JSON payload

---

## �📊 Expected Results

### **✅ Success (No Token Needed):**
```
status: success
error_message: null
```

### **⚠️ Need Token:**
```
status: failed
error_message: "Network error connecting to Rossum API"
```

### **❌ Authentication Issue:**
```
status: failed
error_message: "Invalid API key" or "Missing API key"
```

---

## 🔄 If We Need to Update the Endpoint

If Rossum's extension sends data differently than expected, we can modify the endpoint to handle:

1. **Direct XML in payload** - Extract XML from webhook body
2. **Pre-authenticated URLs** - Use provided URL without additional auth
3. **Extension-specific headers** - Handle Rossum extension authentication

Just share the webhook payload and error messages, and I'll adjust the code!

---

## 📞 Next Steps

1. **Try exporting an invoice** in Rossum
2. **Share the results** of the test queries above
3. Based on the payload, we'll either:
   - ✅ Confirm it works as-is
   - 🔧 Adjust the endpoint to handle Rossum's extension format
   - 🔑 Help you find/request the API token

---

## 💬 Contact Rossum Support

If you need an API token and can't find it:

**Email:** support@rossum.ai  
**Subject:** "API Token for Webhook Integration"  
**Message:**
> Hi Rossum Team,
> 
> I'm integrating Rossum with an external transformation system using webhooks/extensions. I need an API token to fetch exported XML from the Rossum API.
> 
> My account: [your email]
> Workspace: [your workspace name]
> 
> Could you please help me generate an API token with the following scopes:
> - annotations:read
> - documents:read
> - exports:read
> 
> Thank you!

---

**Let's test what Rossum sends first!** Export an invoice and share the results. 🚀

---

**Updated:** October 15, 2025  
**Status:** Waiting for test results from Rossum export
