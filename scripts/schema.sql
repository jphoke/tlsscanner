-- TLS Scanner Portal Database Schema

-- Create database
-- CREATE DATABASE tlsscanner;

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target VARCHAR(255) NOT NULL,
    ip VARCHAR(45),
    port VARCHAR(10) NOT NULL,
    scan_time TIMESTAMP NOT NULL DEFAULT NOW(),
    duration_ms INTEGER,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    
    -- SSL Labs overall grade and score
    grade VARCHAR(3),  -- A+, A, B, C, D, E, F
    score INTEGER,     -- 0-100
    
    -- SSL Labs category scores
    protocol_support_score INTEGER,   -- 30% weight
    key_exchange_score INTEGER,       -- 30% weight  
    cipher_strength_score INTEGER,    -- 40% weight
    
    -- Our subcategory grades
    protocol_grade VARCHAR(2),
    protocol_score INTEGER,
    certificate_grade VARCHAR(2),
    certificate_score INTEGER,
    
    -- Certificate details
    certificate_expires_at TIMESTAMP,
    certificate_days_remaining INTEGER,
    certificate_issuer VARCHAR(255),
    certificate_key_type VARCHAR(20),
    certificate_key_size INTEGER,
    
    result JSONB,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index for searching
CREATE INDEX idx_scans_target ON scans(target);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_certificate_expires ON scans(certificate_expires_at);
CREATE INDEX idx_scans_grade ON scans(grade);

-- Scan queue table
CREATE TABLE IF NOT EXISTS scan_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target VARCHAR(255) NOT NULL,
    priority INTEGER NOT NULL DEFAULT 5,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    scan_id UUID REFERENCES scans(id)
);

CREATE INDEX idx_queue_status_priority ON scan_queue(status, priority DESC, created_at);

-- Scan vulnerabilities (actual vulnerabilities found in scans)
CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vulnerability_name VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    affected BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_vulnerabilities_scan_id ON scan_vulnerabilities(scan_id);
CREATE INDEX idx_scan_vulnerabilities_severity ON scan_vulnerabilities(severity);

-- Grade degradations (specific issues affecting the grade)
CREATE TABLE IF NOT EXISTS scan_grade_degradations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    category VARCHAR(50) NOT NULL, -- protocol, cipher, key_exchange, certificate
    issue VARCHAR(255) NOT NULL,
    details TEXT,
    impact VARCHAR(255),
    remediation TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_grade_degradations_scan_id ON scan_grade_degradations(scan_id);
CREATE INDEX idx_grade_degradations_category ON scan_grade_degradations(category);

-- Weak protocols found
CREATE TABLE IF NOT EXISTS scan_weak_protocols (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    protocol_name VARCHAR(20) NOT NULL,
    protocol_version INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_weak_protocols_scan_id ON scan_weak_protocols(scan_id);

-- Weak cipher suites found
CREATE TABLE IF NOT EXISTS scan_weak_ciphers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cipher_id INTEGER,
    cipher_name VARCHAR(100) NOT NULL,
    has_forward_secrecy BOOLEAN NOT NULL DEFAULT false,
    strength VARCHAR(20), -- WEAK, MEDIUM, STRONG, VERY_STRONG
    protocol VARCHAR(20),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_weak_ciphers_scan_id ON scan_weak_ciphers(scan_id);
CREATE INDEX idx_weak_ciphers_strength ON scan_weak_ciphers(strength);

-- Vulnerabilities reference table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    remediation TEXT,
    cve_ids TEXT[]
);

-- Insert common vulnerabilities
INSERT INTO vulnerabilities (name, severity, description, remediation) VALUES
('SSL 3.0 Support', 'HIGH', 'SSL 3.0 is obsolete and vulnerable to POODLE attack', 'Disable SSL 3.0 support'),
('TLS 1.0 Support', 'MEDIUM', 'TLS 1.0 is deprecated and has known weaknesses', 'Disable TLS 1.0 and use TLS 1.2 or higher'),
('TLS 1.1 Support', 'MEDIUM', 'TLS 1.1 is deprecated', 'Disable TLS 1.1 and use TLS 1.2 or higher'),
('Weak Ciphers', 'HIGH', 'Server supports weak cipher suites', 'Disable all weak cipher suites'),
('No Forward Secrecy', 'MEDIUM', 'Server does not support forward secrecy', 'Enable ECDHE or DHE cipher suites'),
('Heartbleed', 'CRITICAL', 'Server is vulnerable to Heartbleed attack (CVE-2014-0160)', 'Update OpenSSL to patched version'),
('POODLE', 'HIGH', 'Server is vulnerable to POODLE attack', 'Disable SSL 3.0')
ON CONFLICT (name) DO NOTHING;

-- Scheduled scans
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target VARCHAR(255) NOT NULL,
    schedule VARCHAR(100) NOT NULL, -- cron expression
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_run TIMESTAMP,
    next_run TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- API keys for access control
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    permissions JSONB NOT NULL DEFAULT '{}',
    rate_limit INTEGER NOT NULL DEFAULT 100,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT true
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    action VARCHAR(50) NOT NULL,
    target VARCHAR(255),
    api_key_id UUID REFERENCES api_keys(id),
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_api_key ON audit_log(api_key_id);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for scans table
CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();