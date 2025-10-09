-- Add destination schema storage to transformation_mappings table
ALTER TABLE transformation_mappings
ADD COLUMN destination_schema_xml TEXT;

-- Add comment
COMMENT ON COLUMN transformation_mappings.destination_schema_xml IS 'Stores the destination XML schema template for API/webhook transformations';
