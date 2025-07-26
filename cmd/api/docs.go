// Package main TLS Scanner Portal API
//
// High-performance TLS/SSL security scanner API with SSL Labs grading
//
//	Schemes: http, https
//	Host: localhost:8000
//	BasePath: /api/v1
//	Version: 1.0.0
//
//	Consumes:
//	- application/json
//
//	Produces:
//	- application/json
//
// swagger:meta
package main

import (
	_ "github.com/swaggo/files"
	_ "github.com/swaggo/gin-swagger"
)

// swagger:model ScanRequest
type SwaggerScanRequest struct {
	// The target hostname or IP to scan
	// required: true
	// example: example.com
	Target string `json:"target"`
	// Priority level (1-10, higher is more urgent)
	// example: 5
	Priority int `json:"priority,omitempty"`
}

// swagger:model ScanResponse
type SwaggerScanResponse struct {
	// Unique scan identifier
	// example: 550e8400-e29b-41d4-a716-446655440000
	ID string `json:"id"`
	// Current status of the scan
	// example: queued
	Status string `json:"status"`
	// Position in queue (if queued)
	// example: 3
	QueuePos int `json:"queue_position,omitempty"`
	// Status message
	// example: Scan has been queued
	Message string `json:"message"`
	// Creation timestamp
	Created string `json:"created"`
}

// swagger:model ErrorResponse
type SwaggerErrorResponse struct {
	// Error message
	// example: Invalid target
	Error string `json:"error"`
}

// swagger:model HealthResponse
type SwaggerHealthResponse struct {
	// Service status
	// example: healthy
	Status string `json:"status"`
	// Database status (only on error)
	// example: down
	Database string `json:"database,omitempty"`
	// Redis status (only on error)
	// example: down
	Redis string `json:"redis,omitempty"`
}

// swagger:model ScanResult
type SwaggerScanResult struct {
	// Scan ID
	ID string `json:"id"`
	// Scan status
	Status string `json:"status"`
	// SSL Labs grade (A+, A, B, C, D, E, F)
	Grade string `json:"grade,omitempty"`
	// Numeric score (0-100)
	Score int `json:"score,omitempty"`
	// Protocol support score
	ProtocolSupportScore int `json:"protocol_support_score,omitempty"`
	// Key exchange score
	KeyExchangeScore int `json:"key_exchange_score,omitempty"`
	// Cipher strength score
	CipherStrengthScore int `json:"cipher_strength_score,omitempty"`
	// Certificate details
	CertificateExpiresAt string `json:"certificate_expires_at,omitempty"`
	CertificateDaysRemaining int `json:"certificate_days_remaining,omitempty"`
	// Vulnerabilities found
	Vulnerabilities []map[string]interface{} `json:"vulnerabilities,omitempty"`
	// Grade degradations
	GradeDegradations []map[string]interface{} `json:"grade_degradations,omitempty"`
	// Weak protocols
	WeakProtocols []map[string]interface{} `json:"weak_protocols,omitempty"`
	// Weak ciphers
	WeakCiphers []map[string]interface{} `json:"weak_ciphers,omitempty"`
	// Full scan result
	Result interface{} `json:"result,omitempty"`
}

// swagger:parameters createScan
type SwaggerCreateScanParams struct {
	// in: body
	// required: true
	Body SwaggerScanRequest `json:"body"`
}

// swagger:parameters getScan streamScan
type SwaggerGetScanParams struct {
	// Scan ID
	// in: path
	// required: true
	// example: 550e8400-e29b-41d4-a716-446655440000
	ID string `json:"id"`
}

// swagger:response scanResponse
type SwaggerScanResponseWrapper struct {
	// in: body
	Body SwaggerScanResponse
}

// swagger:response scanResult
type SwaggerScanResultWrapper struct {
	// in: body
	Body SwaggerScanResult
}

// swagger:response errorResponse
type SwaggerErrorResponseWrapper struct {
	// in: body
	Body SwaggerErrorResponse
}

// swagger:response healthResponse
type SwaggerHealthResponseWrapper struct {
	// in: body
	Body SwaggerHealthResponse
}

// swagger:route POST /scans scans createScan
//
// Submit a new scan
//
// Submit a target hostname or IP address for TLS/SSL scanning.
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       202: scanResponse
//       400: errorResponse
//       500: errorResponse

// swagger:route GET /scans/{id} scans getScan
//
// Get scan result
//
// Retrieve the result of a specific scan by its ID.
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: scanResult
//       404: errorResponse
//       500: errorResponse

// swagger:route GET /scans scans listScans
//
// List all scans
//
// Get a list of all scans with their status and grades.
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: body:map[string]interface{}
//       500: errorResponse

// swagger:route GET /health health healthCheck
//
// Health check
//
// Check if the API and its dependencies are healthy.
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Responses:
//       200: healthResponse
//       503: healthResponse

// swagger:route GET /scans/{id}/stream websocket streamScan
//
// WebSocket stream
//
// Connect to WebSocket for real-time scan updates.
//
//     Schemes: ws, wss
//
//     Responses:
//       101: body:string