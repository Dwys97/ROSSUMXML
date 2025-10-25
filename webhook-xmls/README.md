# Webhook XML Storage

This directory stores XML files generated from Rossum webhook processing.

## 📁 Directory Structure

```
webhook-xmls/
├── source/           # Source XML files (converted from Rossum JSON)
│   └── source-{annotationId}.xml
└── transformed/      # Transformed XML files (after mapping applied)
    └── transformed-{annotationId}.xml
```

## 📄 File Naming Convention

Files are named using the Rossum annotation ID:

- **Source XML:** `source-23133592.xml`
  - Original Rossum JSON data converted to XML format
  - Before any transformation mapping is applied
  - Size: ~2-3 KB

- **Transformed XML:** `transformed-23133592.xml`
  - Final output after transformation mapping
  - Ready for delivery to destination system
  - Size: ~3-4 KB

## 🔄 How Files Are Created

When a Rossum webhook is received:

1. **Rossum sends JSON** → webhook endpoint receives it
2. **JSON → Source XML** → saved to `source/source-{annotationId}.xml`
3. **Apply mapping** → transformation logic runs
4. **Output → Transformed XML** → saved to `transformed/transformed-{annotationId}.xml`

## 📊 Storage Details

- **Format:** UTF-8 encoded XML
- **Retention:** Files persist until manually deleted
- **Version Control:** Excluded from git (see `.gitignore`)
- **Access:** Direct file system access

## 🔍 How to View Files

### View Source XML (Before Transformation)
```bash
cat webhook-xmls/source/source-23133592.xml
```

### View Transformed XML (After Transformation)
```bash
cat webhook-xmls/transformed/transformed-23133592.xml
```

### List All Files
```bash
ls -lh webhook-xmls/source/
ls -lh webhook-xmls/transformed/
```

### View with Formatting
```bash
xmllint --format webhook-xmls/source/source-23133592.xml
xmllint --format webhook-xmls/transformed/transformed-23133592.xml
```

## 🗑️ Cleanup

To remove old files:

```bash
# Remove files older than 7 days
find webhook-xmls/source/ -name "*.xml" -mtime +7 -delete
find webhook-xmls/transformed/ -name "*.xml" -mtime +7 -delete

# Remove all files
rm webhook-xmls/source/*.xml
rm webhook-xmls/transformed/*.xml
```

## 📈 Monitoring Storage

Check disk usage:
```bash
du -sh webhook-xmls/
du -sh webhook-xmls/source/
du -sh webhook-xmls/transformed/
```

Count files:
```bash
ls webhook-xmls/source/ | wc -l
ls webhook-xmls/transformed/ | wc -l
```

## 🔐 Security Notes

- Files contain customer data - treat as sensitive
- Not backed up in git repository
- Review retention policy regularly
- Consider encryption for production deployments

## 💡 Tips

- **Compare transformations:** Use `diff` to compare source vs transformed
  ```bash
  diff webhook-xmls/source/source-23133592.xml webhook-xmls/transformed/transformed-23133592.xml
  ```

- **Search for specific annotation:**
  ```bash
  grep -r "23133592" webhook-xmls/
  ```

- **Export specific annotation:**
  ```bash
  cp webhook-xmls/transformed/transformed-23133592.xml ~/my-exports/
  ```

---

**Auto-generated:** Files are created automatically by the Rossum webhook handler  
**Last Updated:** October 16, 2025
