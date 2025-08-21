-- =============================================================================
-- Upgrade Script: v1.x to v2.0.0
-- =============================================================================
-- This script upgrades an existing TLS Scanner database from v1 to v2
-- It adds authentication tables and version tracking
-- Safe to run multiple times - uses IF NOT EXISTS everywhere

BEGIN;  -- Start transaction

-- =============================================================================
-- STEP 1: Add Version Tracking
-- =============================================================================

CREATE TABLE IF NOT EXISTS schema_version (
    id INTEGER PRIMARY KEY DEFAULT 1,
    version VARCHAR(20) NOT NULL,
    installed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    description TEXT,
    CONSTRAINT single_row CHECK (id = 1)
);

-- Check current version (if table just created, it will be empty)
DO $$
DECLARE
    current_version VARCHAR(20);
BEGIN
    SELECT version INTO current_version FROM schema_version WHERE id = 1;
    
    IF current_version IS NULL THEN
        -- No version recorded, this is v1
        INSERT INTO schema_version (id, version, description)
        VALUES (1, '1.0.0', 'Original schema without authentication');
        
        RAISE NOTICE 'Detected v1 schema, beginning upgrade to v2...';
    ELSIF current_version = '2.0.0' THEN
        RAISE NOTICE 'Already at v2.0.0, skipping upgrade';
        -- Will still create missing tables if any
    ELSE
        RAISE NOTICE 'Current version: %, upgrading to v2.0.0', current_version;
    END IF;
END $$;

-- =============================================================================
-- STEP 2: Add New Columns to Existing Tables
-- =============================================================================

-- Add user tracking to scans table
ALTER TABLE scans 
ADD COLUMN IF NOT EXISTS created_by UUID;

-- Add user tracking to scan_queue table
ALTER TABLE scan_queue 
ADD COLUMN IF NOT EXISTS created_by UUID;

-- Add indexes for new columns
CREATE INDEX IF NOT EXISTS idx_scans_created_by ON scans(created_by);
CREATE INDEX IF NOT EXISTS idx_queue_created_by ON scan_queue(created_by);

-- =============================================================================
-- STEP 3: Create Authentication Tables
-- =============================================================================

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT TRUE,
    is_ldap BOOLEAN DEFAULT FALSE,
    ldap_dn TEXT,
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

-- API keys for programmatic access
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
-- STEP 4: Create Admin Feature Tables
-- =============================================================================

-- Data retention policies
CREATE TABLE IF NOT EXISTS data_retention_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type VARCHAR(50) NOT NULL UNIQUE,
    retention_days INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_run TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- System configuration
CREATE TABLE IF NOT EXISTS system_config (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT,
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- STEP 5: Create All Indexes
-- =============================================================================

-- User table indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);

-- Token indexes
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);

-- Audit log indexes
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource_type ON audit_log(resource_type);

-- API key indexes
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);

-- =============================================================================
-- STEP 6: Add Foreign Key Constraints
-- =============================================================================

ALTER TABLE scans 
    DROP CONSTRAINT IF EXISTS fk_scans_created_by,
    ADD CONSTRAINT fk_scans_created_by 
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE scan_queue 
    DROP CONSTRAINT IF EXISTS fk_scan_queue_created_by,
    ADD CONSTRAINT fk_scan_queue_created_by 
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;

-- =============================================================================
-- STEP 7: Insert Default Data
-- =============================================================================

-- Default retention policies
INSERT INTO data_retention_policies (resource_type, retention_days, is_active) VALUES
    ('scans', 90, true),
    ('audit_log', 365, true),
    ('refresh_tokens', 7, true)
ON CONFLICT (resource_type) DO NOTHING;

-- Default system configuration
INSERT INTO system_config (key, value, description, is_sensitive) VALUES
    ('scan_timeout', '30', 'Maximum time in seconds for a scan to complete', false),
    ('max_concurrent_scans', '10', 'Maximum number of concurrent scans', false),
    ('auth_mode', 'none', 'Authentication mode: none, optional, required', false),
    ('allow_anonymous_scans', 'true', 'Allow scans without authentication when auth_mode=optional', false)
ON CONFLICT (key) DO NOTHING;

-- =============================================================================
-- STEP 8: Create Migration History Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS migration_history (
    id SERIAL PRIMARY KEY,
    from_version VARCHAR(20),
    to_version VARCHAR(20) NOT NULL,
    migration_type VARCHAR(50),
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'in_progress',
    details JSONB,
    error_message TEXT
);

-- =============================================================================
-- STEP 9: Update Version
-- =============================================================================

-- Update schema version
UPDATE schema_version 
SET version = '2.0.0', 
    installed_at = NOW(),
    description = 'Complete schema with authentication tables'
WHERE id = 1;

-- Record the upgrade
INSERT INTO migration_history (from_version, to_version, migration_type, status, completed_at)
VALUES ('1.0.0', '2.0.0', 'upgrade', 'completed', NOW());

COMMIT;  -- Commit transaction

-- =============================================================================
-- POST-UPGRADE SUMMARY
-- =============================================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=====================================================';
    RAISE NOTICE 'Upgrade to v2.0.0 completed successfully!';
    RAISE NOTICE '=====================================================';
    RAISE NOTICE '';
    RAISE NOTICE 'New features available:';
    RAISE NOTICE '  - Authentication tables (users, tokens, audit_log)';
    RAISE NOTICE '  - Admin features (data retention, system config)';
    RAISE NOTICE '  - User tracking in scans';
    RAISE NOTICE '  - Schema version tracking';
    RAISE NOTICE '';
    RAISE NOTICE 'Note: Auth features are only active when AUTH_MODE != none';
    RAISE NOTICE '';
END $$;