"""
Daily HIL Corrections Collector
Fetches corrected invoice annotations from PostgreSQL and converts to training format.
"""

import os
import json
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any
import psycopg2
from psycopg2.extras import RealDictCursor


class CorrectionCollector:
    """Collects HIL corrections from database and formats for LoRA training."""
    
    def __init__(self, db_config: Dict[str, str]):
        self.db_config = db_config
        self.conn = None
        
        # BIO label mapping (must match train_lora_cpu.py)
        self.label_map = {
            "O": 0,
            "B-INVOICE_NUMBER": 1,
            "I-INVOICE_NUMBER": 2,
            "B-DATE": 3,
            "I-DATE": 4,
            "B-TOTAL": 5,
            "I-TOTAL": 6,
            "B-VAT": 7,
            "I-VAT": 8,
            "B-CURRENCY": 9,
            "I-CURRENCY": 10,
            "B-SELLER_NAME": 11,
            "I-SELLER_NAME": 12,
            "B-SELLER_ADDRESS": 13,
            "I-SELLER_ADDRESS": 14,
            "B-BUYER_NAME": 15,
            "I-BUYER_NAME": 16,
            "B-BUYER_ADDRESS": 17,
            "I-BUYER_ADDRESS": 18,
            "B-ITEM_DESCRIPTION": 19,
            "I-ITEM_DESCRIPTION": 20,
            "B-ITEM_QUANTITY": 21,
            "I-ITEM_QUANTITY": 22,
            "B-ITEM_PRICE": 23,
            "I-ITEM_PRICE": 24,
            "B-HS_CODE": 25,
            "I-HS_CODE": 26,
            "B-INCOTERMS": 27,
            "I-INCOTERMS": 28,
        }
    
    def connect(self):
        """Establish database connection."""
        try:
            self.conn = psycopg2.connect(
                host=self.db_config['host'],
                database=self.db_config['database'],
                user=self.db_config['user'],
                password=self.db_config['password'],
                port=self.db_config.get('port', 5432)
            )
            print(f"✅ Connected to database: {self.db_config['database']}")
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            raise
    
    def disconnect(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            print("🔌 Disconnected from database")
    
    def fetch_corrections(self, date: str = "today") -> List[Dict[str, Any]]:
        """
        Fetch invoice corrections from database.
        
        Args:
            date: "today", "yesterday", or "YYYY-MM-DD"
        
        Returns:
            List of invoice correction records
        """
        if date == "today":
            target_date = datetime.now().date()
        elif date == "yesterday":
            target_date = (datetime.now() - timedelta(days=1)).date()
        else:
            target_date = datetime.strptime(date, "%Y-%m-%d").date()
        
        next_date = target_date + timedelta(days=1)
        
        query = """
            SELECT 
                i.id AS invoice_id,
                i.file_path,
                i.extracted_data,
                c.correction_data,
                c.corrected_by,
                c.corrected_at
            FROM invoices i
            INNER JOIN invoice_corrections c ON i.id = c.invoice_id
            WHERE c.corrected_at >= %s
              AND c.corrected_at < %s
              AND i.extraction_status = 'corrected'
            ORDER BY c.corrected_at ASC;
        """
        
        with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, (target_date, next_date))
            results = cursor.fetchall()
        
        print(f"📊 Found {len(results)} corrections for {target_date}")
        return results
    
    def convert_to_training_format(self, correction: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert database correction record to LayoutLMv3 training format.
        
        Expected correction_data structure:
        {
            "invoice_number": {"value": "INV-001", "bbox": {...}},
            "date": {"value": "2025-10-31", "bbox": {...}},
            "seller_name": {"value": "ACME Corp", "bbox": {...}},
            ...
        }
        
        Returns:
            {
                "image_path": "...",
                "words": ["Invoice", "Number:", "INV-001", ...],
                "boxes": [[x0, y0, x1, y1], ...],
                "labels": ["O", "O", "B-INVOICE_NUMBER", ...]
            }
        """
        correction_data = correction['correction_data']
        
        # Extract OCR data (assumed to be stored in extracted_data)
        extracted_data = correction['extracted_data'] or {}
        ocr_words = extracted_data.get('ocr_words', [])
        ocr_boxes = extracted_data.get('ocr_boxes', [])
        
        if not ocr_words:
            print(f"⚠️  No OCR data for invoice {correction['invoice_id']}, skipping")
            return None
        
        # Initialize all labels as "O" (outside)
        labels = ["O"] * len(ocr_words)
        
        # Map corrected fields to BIO labels
        for field_name, field_data in correction_data.items():
            if not isinstance(field_data, dict):
                continue
            
            value = field_data.get('value')
            bbox = field_data.get('bbox')
            
            if not value or not bbox:
                continue
            
            # Convert field name to label format
            label_base = self._normalize_field_name(field_name)
            
            # Find matching words in OCR output
            matched_indices = self._find_matching_words(
                value, ocr_words, ocr_boxes, bbox
            )
            
            # Apply BIO tagging
            if matched_indices:
                labels[matched_indices[0]] = f"B-{label_base}"
                for idx in matched_indices[1:]:
                    labels[idx] = f"I-{label_base}"
        
        return {
            "image_path": correction['file_path'],
            "invoice_id": str(correction['invoice_id']),
            "words": ocr_words,
            "boxes": ocr_boxes,
            "labels": labels,
            "corrected_by": correction['corrected_by'],
            "corrected_at": correction['corrected_at'].isoformat()
        }
    
    def _normalize_field_name(self, field_name: str) -> str:
        """Convert field name to label format."""
        mappings = {
            'invoice_number': 'INVOICE_NUMBER',
            'date': 'DATE',
            'total': 'TOTAL',
            'vat': 'VAT',
            'currency': 'CURRENCY',
            'seller_name': 'SELLER_NAME',
            'seller_address': 'SELLER_ADDRESS',
            'buyer_name': 'BUYER_NAME',
            'buyer_address': 'BUYER_ADDRESS',
            'item_description': 'ITEM_DESCRIPTION',
            'item_quantity': 'ITEM_QUANTITY',
            'item_price': 'ITEM_PRICE',
            'hs_code': 'HS_CODE',
            'incoterms': 'INCOTERMS'
        }
        return mappings.get(field_name, field_name.upper())
    
    def _find_matching_words(
        self, 
        target_value: str, 
        ocr_words: List[str],
        ocr_boxes: List[List[int]],
        target_bbox: Dict[str, int]
    ) -> List[int]:
        """
        Find OCR words that match the target value and bbox.
        
        Returns:
            List of matching word indices
        """
        # Simple spatial matching: find words inside target bbox
        matches = []
        
        for idx, (word, box) in enumerate(zip(ocr_words, ocr_boxes)):
            # Check if word box is inside target bbox
            if self._box_inside_bbox(box, target_bbox):
                matches.append(idx)
        
        return matches
    
    def _box_inside_bbox(
        self, 
        box: List[int], 
        bbox: Dict[str, int]
    ) -> bool:
        """Check if box is inside bounding box."""
        x0, y0, x1, y1 = box
        
        # Convert bbox to coordinates
        bbox_x0 = bbox.get('x', 0)
        bbox_y0 = bbox.get('y', 0)
        bbox_x1 = bbox_x0 + bbox.get('width', 0)
        bbox_y1 = bbox_y0 + bbox.get('height', 0)
        
        # Check overlap
        return (
            x0 >= bbox_x0 and
            y0 >= bbox_y0 and
            x1 <= bbox_x1 and
            y1 <= bbox_y1
        )
    
    def save_corrections(
        self, 
        corrections: List[Dict[str, Any]], 
        output_dir: str
    ):
        """Save corrections to JSON files."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        saved_count = 0
        for correction in corrections:
            formatted = self.convert_to_training_format(correction)
            if not formatted:
                continue
            
            # Generate filename
            invoice_id = formatted['invoice_id']
            timestamp = formatted['corrected_at'].replace(':', '-')
            filename = f"correction_{invoice_id}_{timestamp}.json"
            
            # Save to file
            filepath = output_path / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(formatted, f, indent=2, ensure_ascii=False)
            
            saved_count += 1
        
        print(f"💾 Saved {saved_count}/{len(corrections)} corrections to {output_dir}")
        return saved_count


def main():
    parser = argparse.ArgumentParser(description="Collect HIL corrections for LoRA training")
    parser.add_argument(
        '--date',
        default='today',
        help='Date to collect: "today", "yesterday", or "YYYY-MM-DD"'
    )
    parser.add_argument(
        '--output',
        default='data/daily_corrections/',
        help='Output directory for correction JSON files'
    )
    parser.add_argument(
        '--db-host',
        default=os.environ.get('DB_HOST', 'localhost'),
        help='Database host'
    )
    parser.add_argument(
        '--db-name',
        default=os.environ.get('DB_NAME', 'rossumxml'),
        help='Database name'
    )
    parser.add_argument(
        '--db-user',
        default=os.environ.get('DB_USER', 'postgres'),
        help='Database user'
    )
    parser.add_argument(
        '--db-password',
        default=os.environ.get('DB_PASSWORD', ''),
        help='Database password'
    )
    
    args = parser.parse_args()
    
    # Database configuration
    db_config = {
        'host': args.db_host,
        'database': args.db_name,
        'user': args.db_user,
        'password': args.db_password
    }
    
    # Collect corrections
    collector = CorrectionCollector(db_config)
    
    try:
        collector.connect()
        
        # Fetch corrections
        corrections = collector.fetch_corrections(args.date)
        
        if not corrections:
            print("ℹ️  No corrections found for the specified date")
            return
        
        # Save to training format
        saved = collector.save_corrections(corrections, args.output)
        
        print(f"\n✅ Collection complete!")
        print(f"   📅 Date: {args.date}")
        print(f"   📁 Output: {args.output}")
        print(f"   📊 Saved: {saved} files")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        raise
    finally:
        collector.disconnect()


if __name__ == "__main__":
    main()
