-- TLS Scanner Portal Database Schema
-- Version: 2.0.0
-- Date: 2025-08-21
-- Description: Complete schema including authentication tables
--              Auth tables are created but only used when AUTH_MODE != none

-- =============================================================================
-- SCHEMA VERSION TRACKING
-- =============================================================================

CREATE TABLE IF NOT EXISTS schema_version (
    id INTEGER PRIMARY KEY DEFAULT 1,  -- Only one row allowed
    version VARCHAR(20) NOT NULL,      -- e.g., "2.0.0"
    installed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    description TEXT,
    CONSTRAINT single_row CHECK (id = 1)
);

-- Record the schema version
INSERT INTO schema_version (id, version, description) 
VALUES (1, '2.0.0', 'Complete schema with authentication tables')
ON CONFLICT (id) DO UPDATE 
SET version = '2.0.0', 
    installed_at = NOW(),
    description = 'Complete schema with authentication tables';

-- =============================================================================
-- CORE TABLES (Always used)
-- =============================================================================

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target VARCHAR(255) NOT NULL,
    ip VARCHAR(45),
    port VARCHAR(10) NOT NULL,
    service_type VARCHAR(20),
    connection_type VARCHAR(20),
    scan_time TIMESTAMP NOT NULL DEFAULT NOW(),
    duration_ms INTEGER,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    
    -- SSL Labs overall grade and score
    grade VARCHAR(10),  -- A+, A, B, C, D, E, F, M, ERROR
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
    
    -- User comments for scan tracking
    comments VARCHAR(100),
    
    -- Deep scan options
    check_sslv3 BOOLEAN DEFAULT FALSE,
    
    -- User tracking (only populated when AUTH_MODE != none)
    created_by UUID,  -- References users(id) when auth is enabled
    
    result JSONB,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index for searching
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_service_type ON scans(service_type);
CREATE INDEX IF NOT EXISTS idx_scans_connection_type ON scans(connection_type);
CREATE INDEX IF NOT EXISTS idx_scans_certificate_expires ON scans(certificate_expires_at);
CREATE INDEX IF NOT EXISTS idx_scans_grade ON scans(grade);
CREATE INDEX IF NOT EXISTS idx_scans_check_sslv3 ON scans(check_sslv3) WHERE check_sslv3 = TRUE;
CREATE INDEX IF NOT EXISTS idx_scans_created_by ON scans(created_by);

-- Scan queue table
CREATE TABLE IF NOT EXISTS scan_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target VARCHAR(255) NOT NULL,
    priority INTEGER NOT NULL DEFAULT 5,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    check_sslv3 BOOLEAN DEFAULT FALSE,
    created_by UUID,  -- References users(id) when auth is enabled
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    scan_id UUID REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_queue_status_priority ON scan_queue(status, priority DESC, created_at);
CREATE INDEX IF NOT EXISTS idx_queue_created_by ON scan_queue(created_by);

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

CREATE INDEX IF NOT EXISTS idx_scan_vulnerabilities_scan_id ON scan_vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_vulnerabilities_severity ON scan_vulnerabilities(severity);

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

CREATE INDEX IF NOT EXISTS idx_scan_grade_degradations_scan_id ON scan_grade_degradations(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_grade_degradations_category ON scan_grade_degradations(category);

-- =============================================================================
-- AUTHENTICATION TABLES (Created but only used when AUTH_MODE != none)
-- =============================================================================

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),  -- NULL for LDAP users
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT TRUE,
    is_ldap BOOLEAN DEFAULT FALSE,  -- Track if user is from LDAP/AD
    ldap_dn TEXT,  -- Store LDAP Distinguished Name
    last_login TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Audit log for admin actions
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- API keys for programmatic access (optional)
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    last_used TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- ADMIN FEATURES TABLES (Created but only used when AUTH_MODE != none)
-- =============================================================================

-- Data retention policies
CREATE TABLE IF NOT EXISTS data_retention_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type VARCHAR(50) NOT NULL UNIQUE,  -- 'scans', 'audit_log', etc.
    retention_days INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_run TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- System configuration (for admin-configurable settings)
CREATE TABLE IF NOT EXISTS system_config (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT,
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,  -- Hide value in UI if true
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- INDEXES FOR AUTHENTICATION AND ADMIN TABLES
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource_type ON audit_log(resource_type);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);

-- =============================================================================
-- FOREIGN KEY CONSTRAINTS (Added after all tables are created)
-- =============================================================================

-- Add foreign key constraints for user references in core tables
-- These are added as ALTER TABLE to avoid issues if tables are created in wrong order
ALTER TABLE scans 
    DROP CONSTRAINT IF EXISTS fk_scans_created_by,
    ADD CONSTRAINT fk_scans_created_by 
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE scan_queue 
    DROP CONSTRAINT IF EXISTS fk_scan_queue_created_by,
    ADD CONSTRAINT fk_scan_queue_created_by 
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;

-- =============================================================================
-- DEFAULT DATA
-- =============================================================================

-- Insert default data retention policies
INSERT INTO data_retention_policies (resource_type, retention_days, is_active) VALUES
    ('scans', 90, true),
    ('audit_log', 365, true),
    ('refresh_tokens', 7, true)
ON CONFLICT (resource_type) DO NOTHING;

-- Insert default system configuration
INSERT INTO system_config (key, value, description, is_sensitive) VALUES
    ('scan_timeout', '30', 'Maximum time in seconds for a scan to complete', false),
    ('max_concurrent_scans', '10', 'Maximum number of concurrent scans', false),
    ('auth_mode', 'none', 'Authentication mode: none, optional, required', false),
    ('allow_anonymous_scans', 'true', 'Allow scans without authentication when auth_mode=optional', false)
ON CONFLICT (key) DO NOTHING;

-- =============================================================================
-- MIGRATION HISTORY (For tracking upgrades from v1)
-- =============================================================================

CREATE TABLE IF NOT EXISTS migration_history (
    id SERIAL PRIMARY KEY,
    from_version VARCHAR(20),
    to_version VARCHAR(20) NOT NULL,
    migration_type VARCHAR(50),  -- 'install', 'upgrade', 'rollback'
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'in_progress',  -- 'in_progress', 'completed', 'failed'
    details JSONB,
    error_message TEXT
);

-- Record this installation
INSERT INTO migration_history (from_version, to_version, migration_type, status, completed_at)
VALUES (NULL, '2.0.0', 'install', 'completed', NOW());