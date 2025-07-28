-- Add CVE information to scan_vulnerabilities table
ALTER TABLE scan_vulnerabilities 
ADD COLUMN IF NOT EXISTS cve_data JSONB;

-- Update existing rows to have empty CVE data
UPDATE scan_vulnerabilities 
SET cve_data = '[]'::jsonb 
WHERE cve_data IS NULL;