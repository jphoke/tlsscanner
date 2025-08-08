-- Add check_sslv3 column to scans table
ALTER TABLE scans 
ADD COLUMN IF NOT EXISTS check_sslv3 BOOLEAN DEFAULT FALSE;

-- Add check_sslv3 column to scan_queue table  
ALTER TABLE scan_queue
ADD COLUMN IF NOT EXISTS check_sslv3 BOOLEAN DEFAULT FALSE;

-- Add index for filtering scans by SSL v3 check status
CREATE INDEX IF NOT EXISTS idx_scans_check_sslv3 ON scans(check_sslv3) WHERE check_sslv3 = TRUE;