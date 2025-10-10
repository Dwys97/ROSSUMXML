# Quick Start: API Settings

## Accessing the Page

**URL**: http://localhost:5173/api-settings (when logged in)

**Navigation**: Look for "API Settings" link in the top navigation bar (visible only when authenticated)

## Quick Actions

### Generate Your First API Key
1. Visit `/api-settings`
2. Find "API Keys" section
3. Enter name: "My First API Key"
4. Select expiration: "Never"
5. Click "Generate New Key"
6. **Copy both the key and secret immediately!**

### Test Your API Key
```bash
curl -X GET http://localhost:3000/api/user/profile \
  -H "Authorization: Bearer YOUR_API_KEY_HERE"
```

### Enable Webhooks
1. Go to "Webhook Settings" section
2. Check "Enable Webhooks"
3. Enter URL: `https://webhook.site/YOUR-UUID` (for testing)
4. Select events you want to track
5. Save settings

### Set Output Delivery to Email
1. Go to "Output Delivery" section
2. Click "Email" tab
3. Enter recipient email addresses
4. Click "Add" for each email
5. Customize subject if desired
6. Save settings

## Database Check

Verify tables were created:
```bash
docker exec -it rossumxml-db-1 psql -U postgres -d rossumxml -c "\dt"
```

You should see:
- `api_keys`
- `webhook_settings`
- `output_delivery_settings`

## Common Issues

**"Cannot read property 'getToken' of undefined"**
- Make sure you're logged in
- Clear browser localStorage and login again

**"API endpoint not found"**
- Restart the backend server
- Check backend logs for errors

**Database errors**
- Run the migration script:
  ```bash
  cat backend/db/migrations/001_api_settings.sql | docker exec -i rossumxml-db-1 psql -U postgres -d rossumxml
  ```

## File Structure

```
backend/
  ├── index.js (updated with API settings routes)
  ├── routes/
  │   └── api-settings.routes.js (standalone version, not used in Lambda)
  └── db/
      └── migrations/
          └── 001_api_settings.sql

frontend/
  └── src/
      ├── pages/
      │   ├── ApiSettingsPage.jsx
      │   └── ApiSettingsPage.module.css
      └── App.jsx (updated with /api-settings route)
```

## Next Steps

1. ✅ Create an API key
2. ✅ Test it with a curl command
3. ✅ Set up webhook (optional)
4. ✅ Configure output delivery method
5. 📖 Read full documentation: [API_SETTINGS_DOCUMENTATION.md](API_SETTINGS_DOCUMENTATION.md)

---

**Need Help?** Check the full documentation or review console logs for detailed error messages.
