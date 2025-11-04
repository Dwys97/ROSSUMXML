#!/usr/bin/env python3
"""
Create sample invoice images and annotations for testing LoRA training
"""

import os
import json
from PIL import Image, ImageDraw, ImageFont

# Create directories
os.makedirs('/tmp/data/daily_corrections', exist_ok=True)

def create_sample_invoice(filename, invoice_data):
    """Create a simple invoice image with text"""
    # Create blank white image
    img = Image.new('RGB', (800, 1000), color='white')
    draw = ImageDraw.Draw(img)
    
    # Try to use a nice font, fallback to default
    try:
        font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 24)
        font_medium = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 18)
        font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)
    except:
        font_large = ImageFont.load_default()
        font_medium = ImageFont.load_default()
        font_small = ImageFont.load_default()
    
    # Draw invoice header
    draw.text((50, 50), "INVOICE", fill='black', font=font_large)
    
    # Draw invoice details
    y_pos = 120
    for key, value in invoice_data.items():
        draw.text((50, y_pos), f"{key}:", fill='black', font=font_medium)
        draw.text((250, y_pos), str(value), fill='black', font=font_medium)
        y_pos += 40
    
    # Save image
    img_path = f'/tmp/data/daily_corrections/{filename}.png'
    img.save(img_path)
    return img_path

# Sample invoices
invoices = [
    {
        'filename': 'invoice_001',
        'data': {
            'Invoice Number': 'INV-2025-001',
            'Date': '2025-01-15',
            'Seller': 'Tech Solutions Ltd',
            'Buyer': 'Global Imports Inc',
            'Total': '$1,250.00',
            'Currency': 'USD',
            'VAT': '$250.00'
        },
        'labels': {
            'invoice_number': 'INV-2025-001',
            'invoice_date': '2025-01-15',
            'seller_name': 'Tech Solutions Ltd',
            'buyer_name': 'Global Imports Inc',
            'total_amount': '1250.00',
            'currency': 'USD',
            'vat_amount': '250.00'
        }
    },
    {
        'filename': 'invoice_002',
        'data': {
            'Invoice Number': 'INV-2025-002',
            'Date': '2025-01-20',
            'Seller': 'Manufacturing Co',
            'Buyer': 'Retail Chain Ltd',
            'Total': '€2,450.75',
            'Currency': 'EUR',
            'VAT': '€490.15'
        },
        'labels': {
            'invoice_number': 'INV-2025-002',
            'invoice_date': '2025-01-20',
            'seller_name': 'Manufacturing Co',
            'buyer_name': 'Retail Chain Ltd',
            'total_amount': '2450.75',
            'currency': 'EUR',
            'vat_amount': '490.15'
        }
    },
    {
        'filename': 'invoice_003',
        'data': {
            'Invoice Number': 'INV-2025-003',
            'Date': '2025-01-25',
            'Seller': 'Export Partners GmbH',
            'Buyer': 'Import Services SA',
            'Total': '£3,750.00',
            'Currency': 'GBP',
            'VAT': '£750.00'
        },
        'labels': {
            'invoice_number': 'INV-2025-003',
            'invoice_date': '2025-01-25',
            'seller_name': 'Export Partners GmbH',
            'buyer_name': 'Import Services SA',
            'total_amount': '3750.00',
            'currency': 'GBP',
            'vat_amount': '750.00'
        }
    }
]

print("Creating sample invoice images...")
for inv in invoices:
    img_path = create_sample_invoice(inv['filename'], inv['data'])
    
    # Save annotations
    label_path = f'/tmp/data/daily_corrections/{inv["filename"]}.json'
    with open(label_path, 'w') as f:
        json.dump(inv['labels'], f, indent=2)
    
    print(f"✓ Created {inv['filename']}: {img_path}")

print(f"\n✅ Created {len(invoices)} sample invoices in /tmp/data/daily_corrections/")
print("Files created:")
os.system('ls -lh /tmp/data/daily_corrections/')
