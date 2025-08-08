// @title TLS Scanner Portal API
// @version 1.0.0
// @description High-performance TLS/SSL security scanner API with SSL Labs grading
// @host localhost:8000
// @BasePath /api/v1
// @schemes http https
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/jphoke/tlsscanner-portal/pkg/scanner"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	_ "github.com/jphoke/tlsscanner-portal/docs/swagger" // swagger docs
)

type Server struct {
	db      *sql.DB
	redis   *redis.Client
	scanner *scanner.Scanner
}

// ScanRequest represents a new scan submission
// @Description Request body for submitting a new TLS/SSL scan
type ScanRequest struct {
	// Target hostname or IP address to scan (required)
	// @example example.com or 192.168.1.1:8443
	Target     string `json:"target" binding:"required" example:"example.com"`
	// Scan priority (1-10, higher = more priority)
	// @example 5
	Priority   int    `json:"priority" example:"5"`
	// Optional comments for tracking (max 100 chars)
	// @example "Ticket #12345"
	Comments   string `json:"comments" binding:"omitempty,max=100" example:"Quarterly security audit"`
	// Enable deep scan with SSL v3 detection using raw sockets
	// @example false
	CheckSSLv3 bool   `json:"check_sslv3" example:"false"`
}

type ScanResponse struct {
	ID       string    `json:"id"`
	Status   string    `json:"status"`
	QueuePos int       `json:"queue_position,omitempty"`
	Message  string    `json:"message"`
	Created  time.Time `json:"created"`
}

type ScanResultResponse struct {
	ID                      string                 `json:"id"`
	Status                  string                 `json:"status"`
	ServiceType             string                 `json:"service_type,omitempty"`
	ConnectionType          string                 `json:"connection_type,omitempty"`
	Grade                   string                 `json:"grade,omitempty"`
	Score                   int                    `json:"score,omitempty"`
	ProtocolSupportScore    int                    `json:"protocol_support_score,omitempty"`
	KeyExchangeScore        int                    `json:"key_exchange_score,omitempty"`
	CipherStrengthScore     int                    `json:"cipher_strength_score,omitempty"`
	ProtocolGrade           string                 `json:"protocol_grade,omitempty"`
	ProtocolScore           int                    `json:"protocol_score,omitempty"`
	CertificateGrade        string                 `json:"certificate_grade,omitempty"`
	CertificateScore        int                    `json:"certificate_score,omitempty"`
	CertificateExpiresAt    *time.Time             `json:"certificate_expires_at,omitempty"`
	CertificateDaysRemaining int                   `json:"certificate_days_remaining,omitempty"`
	CertificateIssuer       string                 `json:"certificate_issuer,omitempty"`
	CertificateKeyType      string                 `json:"certificate_key_type,omitempty"`
	CertificateKeySize      int                    `json:"certificate_key_size,omitempty"`
	Comments                string                 `json:"comments,omitempty"`
	Result                  interface{}            `json:"result,omitempty" swaggertype:"object"`
	Vulnerabilities         []map[string]interface{} `json:"vulnerabilities"`
	GradeDegradations       []map[string]interface{} `json:"grade_degradations"`
	WeakProtocols           []map[string]interface{} `json:"weak_protocols"`
	WeakCiphers             []map[string]interface{} `json:"weak_ciphers"`
}

type ScanListItem struct {
	ID         string     `json:"id"`
	Target     string     `json:"target"`
	Status     string     `json:"status"`
	Grade      string     `json:"grade,omitempty"`
	Score      int        `json:"score,omitempty"`
	Comments   string     `json:"comments,omitempty"`
	Created    time.Time  `json:"created"`
}

type ScanListResponse struct {
	Scans []ScanListItem `json:"scans"`
	Total int            `json:"total"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		return true
	},
}

// validateTarget validates and sanitizes the scan target
//
//nolint:err113 // Dynamic errors provide specific validation feedback to users
func validateTarget(target string) (string, int, error) {
	// Remove leading/trailing whitespace
	target = strings.TrimSpace(target)
	
	// Check if empty
	if target == "" {
		return "", 0, fmt.Errorf("target cannot be empty")
	}
	
	// Remove common URL prefixes and trailing slashes
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "ssl://")
	target = strings.TrimPrefix(target, "tls://")
	target = strings.TrimSuffix(target, "/")
	
	// Check for URL path (not allowed)
	if strings.Contains(target, "/") {
		return "", 0, fmt.Errorf("target cannot contain URL paths")
	}
	
	// Split host and port
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		// No port specified, use default
		host = target
		portStr = "443"
	}
	
	// Validate port
	var port int
	if portStr != "" {
		_, err := fmt.Sscanf(portStr, "%d", &port)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid port number")
		}
	} else {
		port = 443
	}
	
	// Validate hostname/IP
	if !isValidHostname(host) && !isValidIP(host) {
		return "", 0, fmt.Errorf("invalid hostname or IP address")
	}
	
	// Return cleaned target with port
	if port != 443 {
		return fmt.Sprintf("%s:%d", host, port), port, nil
	}
	return host, port, nil
}

// isValidHostname checks if the string is a valid hostname
func isValidHostname(hostname string) bool {
	if len(hostname) > 253 {
		return false
	}
	
	// Valid hostname regex
	hostnameRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
	return hostnameRegex.MatchString(hostname)
}

// isValidIP checks if the string is a valid IP address
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// validateComments validates the comments field
//
//nolint:err113 // Dynamic errors provide specific validation feedback to users
func validateComments(comments string) (string, error) {
	// Trim whitespace
	comments = strings.TrimSpace(comments)
	
	// Check length
	if len(comments) > 100 {
		return "", fmt.Errorf("comments cannot exceed 100 characters")
	}
	
	// Remove any control characters
	comments = regexp.MustCompile(`[\x00-\x1F\x7F]`).ReplaceAllString(comments, "")
	
	return comments, nil
}

func main() {
	// Database connection
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:password@localhost/tlsscanner?sslmode=disable"
	}
	
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database connection: %v", err)
		}
	}()
	
	// Redis connection
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}
	
	rdb := redis.NewClient(&redis.Options{
		Addr: redisURL,
	})
	
	// Scanner instance
	scannerConfig := scanner.Config{
		Timeout:        10 * time.Second,
		MaxConcurrency: 10,
		CustomCAPath:   os.Getenv("CUSTOM_CA_PATH"),
		Verbose:        os.Getenv("SCANNER_VERBOSE") == "true",
	}
	s := scanner.New(scannerConfig)
	
	server := &Server{
		db:      db,
		redis:   rdb,
		scanner: s,
	}
	
	// Gin router
	r := gin.Default()
	
	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	})
	
	// Swagger documentation
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Routes
	api := r.Group("/api/v1")
	{
		api.POST("/scans", server.createScan)
		api.GET("/scans/:id", server.getScan)
		api.GET("/scans", server.listScans)
		api.GET("/scans/:id/stream", server.streamScan)
		api.GET("/stats", server.getStats)
		api.GET("/health", server.healthCheck)
	}
	
	// Start workers
	go server.startWorkers(5)
	
	port := "8080"
	
	log.Printf("Starting API server on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// createScan godoc
// @Summary Submit a new scan or batch of scans
// @Description Submit a single target or multiple targets for TLS/SSL scanning
// @Tags scans
// @Accept json
// @Produce json
// @Param scan body ScanRequest false "Single scan target"
// @Param batch body []ScanRequest false "Batch of scan targets (up to 100)"
// @Success 202 {object} ScanResponse "Single scan response"
// @Success 202 {object} map[string]interface{} "Batch scan response"
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /scans [post]
func (s *Server) createScan(c *gin.Context) {
	ctx := c.Request.Context()
	
	// Try to parse as array first (batch request)
	var batchReq []ScanRequest
	if err := c.ShouldBindJSON(&batchReq); err == nil {
		// It's a batch request
		s.handleBatchScan(c, batchReq)
		return
	}
	
	// Not an array, try single request
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request format"})
		return
	}
	
	// Validate and sanitize target
	cleanedTarget, port, err := validateTarget(req.Target)
	if err != nil {
		c.JSON(400, gin.H{"error": fmt.Sprintf("Invalid target: %s", err.Error())})
		return
	}
	
	// Validate and sanitize comments
	cleanedComments, err := validateComments(req.Comments)
	if err != nil {
		c.JSON(400, gin.H{"error": fmt.Sprintf("Invalid comments: %s", err.Error())})
		return
	}
	
	// Create scan record
	var scanID string
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO scans (target, port, status, comments, check_sslv3)
		VALUES ($1, $2, 'queued', $3, $4)
		RETURNING id
	`, cleanedTarget, fmt.Sprintf("%d", port), cleanedComments, req.CheckSSLv3).Scan(&scanID)
	
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create scan"})
		return
	}
	
	// Add to queue
	priority := req.Priority
	if priority == 0 {
		priority = 5
	}
	
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO scan_queue (target, priority, scan_id, check_sslv3)
		VALUES ($1, $2, $3, $4)
	`, cleanedTarget, priority, scanID, req.CheckSSLv3)
	
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to queue scan"})
		return
	}
	
	// Publish to Redis for workers
	s.redis.Publish(ctx, "scan_queue", scanID)
	
	c.JSON(202, ScanResponse{
		ID:      scanID,
		Status:  "queued",
		Message: "Scan has been queued",
		Created: time.Now(),
	})
}

// handleBatchScan processes batch scan requests
func (s *Server) handleBatchScan(c *gin.Context, requests []ScanRequest) {
	ctx := c.Request.Context()
	
	// Limit batch size
	const maxBatchSize = 100
	if len(requests) > maxBatchSize {
		c.JSON(400, gin.H{"error": fmt.Sprintf("Batch size exceeds maximum of %d", maxBatchSize)})
		return
	}
	
	if len(requests) == 0 {
		c.JSON(400, gin.H{"error": "Empty batch request"})
		return
	}
	
	// Process each scan request
	var results []gin.H
	successCount := 0
	failedCount := 0
	
	for _, req := range requests {
		// Validate and sanitize target
		cleanedTarget, port, err := validateTarget(req.Target)
		if err != nil {
			results = append(results, gin.H{
				"target": req.Target,
				"error":  fmt.Sprintf("Invalid target: %s", err.Error()),
			})
			failedCount++
			continue
		}
		
		// Validate and sanitize comments
		cleanedComments, err := validateComments(req.Comments)
		if err != nil {
			results = append(results, gin.H{
				"target": req.Target,
				"error":  fmt.Sprintf("Invalid comments: %s", err.Error()),
			})
			failedCount++
			continue
		}
		
		// Create scan record
		var scanID string
		err = s.db.QueryRowContext(ctx, `
			INSERT INTO scans (target, port, status, comments, check_sslv3)
			VALUES ($1, $2, 'queued', $3, $4)
			RETURNING id
		`, cleanedTarget, fmt.Sprintf("%d", port), cleanedComments, req.CheckSSLv3).Scan(&scanID)
		
		if err != nil {
			results = append(results, gin.H{
				"target": req.Target,
				"error":  "Failed to create scan",
			})
			failedCount++
			continue
		}
		
		// Add to queue
		priority := req.Priority
		if priority == 0 {
			priority = 5
		}
		
		_, err = s.db.ExecContext(ctx, `
			INSERT INTO scan_queue (target, priority, scan_id, check_sslv3)
			VALUES ($1, $2, $3, $4)
		`, cleanedTarget, priority, scanID, req.CheckSSLv3)
		
		if err != nil {
			results = append(results, gin.H{
				"target": req.Target,
				"error":  "Failed to queue scan",
				"id":     scanID,
			})
			failedCount++
			continue
		}
		
		// Publish to Redis
		s.redis.Publish(ctx, "scan_queue", scanID)
		
		results = append(results, gin.H{
			"target": req.Target,
			"id":     scanID,
			"status": "queued",
		})
		successCount++
	}
	
	// Return batch response
	c.JSON(202, gin.H{
		"total":   len(requests),
		"success": successCount,
		"failed":  failedCount,
		"scans":   results,
		"message": fmt.Sprintf("Batch scan initiated: %d queued, %d failed", successCount, failedCount),
	})
}

// getScan godoc
// @Summary Get scan result
// @Description Retrieve the result of a specific scan by its ID
// @Tags scans
// @Accept json
// @Produce json
// @Param id path string true "Scan ID"
// @Success 200 {object} ScanResultResponse
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /scans/{id} [get]
func (s *Server) getScan(c *gin.Context) {
	ctx := c.Request.Context()
	scanID := c.Param("id")
	
	var result json.RawMessage
	var status string
	var serviceType, connectionType sql.NullString
	var grade, protocolGrade, certificateGrade sql.NullString
	var score, protocolScore, certificateScore sql.NullInt64
	var protocolSupportScore, keyExchangeScore, cipherStrengthScore sql.NullInt64
	var certExpiresAt sql.NullTime
	var certDaysRemaining sql.NullInt64
	var certIssuer, certKeyType sql.NullString
	var certKeySize sql.NullInt64
	var comments sql.NullString
	
	err := s.db.QueryRowContext(ctx, `
		SELECT status, service_type, connection_type, grade, score, 
		       protocol_support_score, key_exchange_score, cipher_strength_score,
		       protocol_grade, protocol_score, 
		       certificate_grade, certificate_score,
		       certificate_expires_at, certificate_days_remaining,
		       certificate_issuer, certificate_key_type, certificate_key_size,
		       comments, result
		FROM scans
		WHERE id = $1
	`, scanID).Scan(&status, &serviceType, &connectionType, &grade, &score, 
		&protocolSupportScore, &keyExchangeScore, &cipherStrengthScore,
		&protocolGrade, &protocolScore,
		&certificateGrade, &certificateScore,
		&certExpiresAt, &certDaysRemaining,
		&certIssuer, &certKeyType, &certKeySize, &comments, &result)
	
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(404, gin.H{"error": "Scan not found"})
		return
	}
	
	if err != nil {
		c.JSON(500, gin.H{"error": "Database error"})
		return
	}
	
	response := gin.H{
		"id":     scanID,
		"status": status,
	}
	
	if serviceType.Valid {
		response["service_type"] = serviceType.String
	}
	
	if connectionType.Valid {
		response["connection_type"] = connectionType.String
	}
	
	if grade.Valid {
		response["grade"] = grade.String
	}
	
	if score.Valid {
		response["score"] = score.Int64
	}
	
	if protocolSupportScore.Valid {
		response["protocol_support_score"] = protocolSupportScore.Int64
	}
	
	if keyExchangeScore.Valid {
		response["key_exchange_score"] = keyExchangeScore.Int64
	}
	
	if cipherStrengthScore.Valid {
		response["cipher_strength_score"] = cipherStrengthScore.Int64
	}
	
	if protocolGrade.Valid {
		response["protocol_grade"] = protocolGrade.String
	}
	
	if protocolScore.Valid {
		response["protocol_score"] = protocolScore.Int64
	}
	
	if certificateGrade.Valid {
		response["certificate_grade"] = certificateGrade.String
	}
	
	if certificateScore.Valid {
		response["certificate_score"] = certificateScore.Int64
	}
	
	// Add certificate details
	if certExpiresAt.Valid {
		response["certificate_expires_at"] = certExpiresAt.Time
	}
	if certDaysRemaining.Valid {
		response["certificate_days_remaining"] = certDaysRemaining.Int64
	}
	if certIssuer.Valid {
		response["certificate_issuer"] = certIssuer.String
	}
	if certKeyType.Valid {
		response["certificate_key_type"] = certKeyType.String
	}
	if certKeySize.Valid {
		response["certificate_key_size"] = certKeySize.Int64
	}
	
	if comments.Valid && comments.String != "" {
		response["comments"] = comments.String
	}
	
	if result != nil {
		response["result"] = result
	}
	
	// Get vulnerabilities
	vulnerabilities := []gin.H{}
	vulnRows, err := s.db.QueryContext(ctx, `
		SELECT vulnerability_name, severity, description, affected, 
		       COALESCE(cve_data, '[]'::jsonb) as cve_data
		FROM scan_vulnerabilities
		WHERE scan_id = $1
		ORDER BY severity
	`, scanID)
	if err == nil {
		defer func() {
			if err := vulnRows.Close(); err != nil {
				log.Printf("Error closing vulnerability rows: %v", err)
			}
		}()
		for vulnRows.Next() {
			var name, severity, description string
			var affected bool
			var cveDataJSON []byte
			if err := vulnRows.Scan(&name, &severity, &description, &affected, &cveDataJSON); err == nil {
				vuln := gin.H{
					"name":        name,
					"severity":    severity,
					"description": description,
					"affected":    affected,
				}
				
				// Parse CVE data
				var cves []interface{}
				if err := json.Unmarshal(cveDataJSON, &cves); err == nil && len(cves) > 0 {
					vuln["cves"] = cves
				}
				
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}
	response["vulnerabilities"] = vulnerabilities
	
	// Get grade degradations
	degradations := []gin.H{}
	degRows, err := s.db.QueryContext(ctx, `
		SELECT category, issue, details, impact, remediation
		FROM scan_grade_degradations
		WHERE scan_id = $1
		ORDER BY category
	`, scanID)
	if err == nil {
		defer func() {
			if err := degRows.Close(); err != nil {
				log.Printf("Error closing degradation rows: %v", err)
			}
		}()
		for degRows.Next() {
			var category, issue, details, impact, remediation string
			if err := degRows.Scan(&category, &issue, &details, &impact, &remediation); err == nil {
				degradations = append(degradations, gin.H{
					"category":    category,
					"issue":       issue,
					"details":     details,
					"impact":      impact,
					"remediation": remediation,
				})
			}
		}
	}
	response["grade_degradations"] = degradations
	
	// Get weak protocols
	weakProtocols := []gin.H{}
	protoRows, err := s.db.QueryContext(ctx, `
		SELECT protocol_name, protocol_version
		FROM scan_weak_protocols
		WHERE scan_id = $1
		ORDER BY protocol_version
	`, scanID)
	if err == nil {
		defer func() {
			if err := protoRows.Close(); err != nil {
				log.Printf("Error closing protocol rows: %v", err)
			}
		}()
		for protoRows.Next() {
			var name string
			var version int
			if err := protoRows.Scan(&name, &version); err == nil {
				weakProtocols = append(weakProtocols, gin.H{
					"name":    name,
					"version": version,
				})
			}
		}
	}
	response["weak_protocols"] = weakProtocols
	
	// Get weak ciphers
	weakCiphers := []gin.H{}
	cipherRows, err := s.db.QueryContext(ctx, `
		SELECT cipher_id, cipher_name, has_forward_secrecy, strength, protocol
		FROM scan_weak_ciphers
		WHERE scan_id = $1
		ORDER BY strength, cipher_name
	`, scanID)
	if err == nil {
		defer func() {
			if err := cipherRows.Close(); err != nil {
				log.Printf("Error closing cipher rows: %v", err)
			}
		}()
		for cipherRows.Next() {
			var id int
			var name, strength, protocol string
			var hasFS bool
			if err := cipherRows.Scan(&id, &name, &hasFS, &strength, &protocol); err == nil {
				weakCiphers = append(weakCiphers, gin.H{
					"id":                 id,
					"name":               name,
					"forward_secrecy":    hasFS,
					"strength":           strength,
					"protocol":           protocol,
				})
			}
		}
	}
	response["weak_ciphers"] = weakCiphers
	
	c.JSON(200, response)
}

// listScans godoc
// @Summary List all scans
// @Description Get a list of all scans with their status and grades
// @Tags scans
// @Accept json
// @Produce json
// @Success 200 {object} ScanListResponse
// @Failure 500 {object} map[string]string
// @Router /scans [get]
func (s *Server) listScans(c *gin.Context) {
	ctx := c.Request.Context()
	limit := 50
	offset := 0
	
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target, status, grade, score, comments, created_at
		FROM scans
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	
	if err != nil {
		c.JSON(500, gin.H{"error": "Database error"})
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("Error closing scan list rows: %v", err)
		}
	}()
	
	var scans []gin.H
	for rows.Next() {
		var id, target, status string
		var grade sql.NullString
		var score sql.NullInt64
		var comments sql.NullString
		var created time.Time
		
		err := rows.Scan(&id, &target, &status, &grade, &score, &comments, &created)
		if err != nil {
			continue
		}
		
		scan := gin.H{
			"id":      id,
			"target":  target,
			"status":  status,
			"created": created,
		}
		
		if grade.Valid {
			scan["grade"] = grade.String
		}
		if score.Valid {
			scan["score"] = score.Int64
		}
		if comments.Valid && comments.String != "" {
			scan["comments"] = comments.String
		}
		
		scans = append(scans, scan)
	}
	
	c.JSON(200, gin.H{
		"scans": scans,
		"total": len(scans),
	})
}

func (s *Server) streamScan(c *gin.Context) {
	ctx := c.Request.Context()
	scanID := c.Param("id")
	
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("Error closing WebSocket connection: %v", err)
		}
	}()
	
	// Send updates until scan completes
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		var status string
		err := s.db.QueryRowContext(ctx, "SELECT status FROM scans WHERE id = $1", scanID).Scan(&status)
		if err != nil {
			return
		}
		
		update := gin.H{
			"id":     scanID,
			"status": status,
		}
		
		if err := conn.WriteJSON(update); err != nil {
			return
		}
		
		if status == "completed" || status == "failed" {
			return
		}
	}
}

// getStats godoc
// @Summary Get statistics
// @Description Get scan statistics including total scans, queue length, etc.
// @Tags stats
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /stats [get]
func (s *Server) getStats(c *gin.Context) {
	ctx := c.Request.Context()
	var stats struct {
		TotalScans     int
		ScansToday     int
		AverageGrade   string
		QueueLength    int
		ActiveWorkers  int
	}
	
	// Get total scans
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scans").Scan(&stats.TotalScans); err != nil {
		log.Printf("Error getting total scans count: %v", err)
	}
	
	// Get scans today
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM scans 
		WHERE created_at >= CURRENT_DATE
	`).Scan(&stats.ScansToday); err != nil {
		log.Printf("Error getting today's scan count: %v", err)
	}
	
	// Get queue length
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM scan_queue 
		WHERE status = 'pending'
	`).Scan(&stats.QueueLength); err != nil {
		log.Printf("Error getting queue length: %v", err)
	}
	
	// Calculate average grade
	var validGrades []string
	rows, err := s.db.QueryContext(ctx, `
		SELECT grade FROM scans 
		WHERE status = 'completed' 
		AND grade IS NOT NULL 
		AND grade NOT IN ('', '-', 'N/A')
	`)
	if err == nil {
		defer func() {
			if err := rows.Close(); err != nil {
				log.Printf("Error closing stats rows: %v", err)
			}
		}()
		for rows.Next() {
			var grade string
			if err := rows.Scan(&grade); err == nil {
				validGrades = append(validGrades, grade)
			}
		}
	}
	
	if len(validGrades) > 0 {
		// Calculate average by converting grades to scores and back
		totalScore := 0
		for _, grade := range validGrades {
			switch grade {
			case "A+":
				totalScore += 95
			case "A":
				totalScore += 85
			case "B":
				totalScore += 75
			case "C":
				totalScore += 65
			case "D":
				totalScore += 55
			case "E":
				totalScore += 45
			case "F":
				totalScore += 35
			case "M":
				totalScore += 30  // Mismatch gets low score
			}
		}
		
		avgScore := totalScore / len(validGrades)
		
		// Convert average score back to grade
		switch {
		case avgScore >= 90:
			stats.AverageGrade = "A+"
		case avgScore >= 80:
			stats.AverageGrade = "A"
		case avgScore >= 70:
			stats.AverageGrade = "B"
		case avgScore >= 60:
			stats.AverageGrade = "C"
		case avgScore >= 50:
			stats.AverageGrade = "D"
		case avgScore >= 40:
			stats.AverageGrade = "E"
		default:
			stats.AverageGrade = "F"
		}
	} else {
		stats.AverageGrade = "N/A"
	}
	
	c.JSON(200, stats)
}

// healthCheck godoc
// @Summary Health check
// @Description Check if the API and its dependencies are healthy
// @Tags health
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 503 {object} map[string]string
// @Router /health [get]
func (s *Server) healthCheck(c *gin.Context) {
	ctx := c.Request.Context()
	
	// Check database
	if err := s.db.PingContext(ctx); err != nil {
		c.JSON(503, gin.H{"status": "unhealthy", "database": "down"})
		return
	}
	
	// Check Redis
	if err := s.redis.Ping(ctx).Err(); err != nil {
		c.JSON(503, gin.H{"status": "unhealthy", "redis": "down"})
		return
	}
	
	// Include custom CA status
	customCAPath := os.Getenv("CUSTOM_CA_PATH")
	hasCustomCA := customCAPath != ""
	
	response := gin.H{
		"status": "healthy",
		"custom_ca_enabled": hasCustomCA,
	}
	
	if hasCustomCA {
		response["custom_ca_path"] = customCAPath
	}
	
	c.JSON(200, response)
}

func (s *Server) startWorkers(count int) {
	for i := 0; i < count; i++ {
		go s.worker(i)
	}
}

func (s *Server) worker(id int) {
	log.Printf("Worker %d started", id)
	
	for {
		// Create context with timeout for each scan operation
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		
		// Get next scan from queue
		var scanID, target string
		var checkSSLv3 bool
		err := s.db.QueryRowContext(ctx, `
			UPDATE scan_queue
			SET status = 'processing', started_at = NOW()
			WHERE id = (
				SELECT id FROM scan_queue
				WHERE status = 'pending'
				ORDER BY priority DESC, created_at
				FOR UPDATE SKIP LOCKED
				LIMIT 1
			)
			RETURNING scan_id, target, check_sslv3
		`).Scan(&scanID, &target, &checkSSLv3)
		
		if errors.Is(err, sql.ErrNoRows) {
			// No work available
			cancel()
			time.Sleep(1 * time.Second)
			continue
		}
		
		if err != nil {
			log.Printf("Worker %d: Failed to get work: %v", id, err)
			cancel()
			time.Sleep(1 * time.Second)
			continue
		}
		
		// Update scan status
		if _, err := s.db.ExecContext(ctx, "UPDATE scans SET status = 'scanning' WHERE id = $1", scanID); err != nil {
			log.Printf("Worker %d: Error updating scan status to 'scanning': %v", id, err)
		}
		
		// Create scanner config for this specific scan
		scannerConfig := scanner.Config{
			Timeout:        10 * time.Second,
			MaxConcurrency: 10,
			CustomCAPath:   os.Getenv("CUSTOM_CA_PATH"),
			Verbose:        os.Getenv("SCANNER_VERBOSE") == "true",
			CheckSSLv3:     checkSSLv3,
		}
		scannerInstance := scanner.New(scannerConfig)
		
		// Perform scan
		log.Printf("Worker %d: Scanning %s (SSL v3 check: %v)", id, target, checkSSLv3)
		result, err := scannerInstance.ScanTarget(target)
		
		if err != nil {
			// Mark as failed
			if _, dbErr := s.db.ExecContext(ctx, `
				UPDATE scans 
				SET status = 'failed', error_message = $2, updated_at = NOW()
				WHERE id = $1
			`, scanID, err.Error()); dbErr != nil {
				log.Printf("Worker %d: Error updating failed scan status: %v", id, dbErr)
			}
		} else {
			// Save results
			resultJSON, _ := json.Marshal(result)
			
			// Calculate certificate days remaining
			var certExpiresAt *time.Time
			var certDaysRemaining *int
			var certIssuer, certKeyType *string
			var certKeySize *int
			
			if result.Certificate != nil {
				certExpiresAt = &result.Certificate.NotAfter
				days := int(time.Until(result.Certificate.NotAfter).Hours() / 24)
				certDaysRemaining = &days
				certIssuer = &result.Certificate.Issuer
				certKeyType = &result.Certificate.KeyType
				certKeySize = &result.Certificate.KeySize
			}
			
			// Update main scan record
			if _, err := s.db.ExecContext(ctx, `
				UPDATE scans 
				SET status = 'completed', 
				    service_type = $2,
				    connection_type = $3,
				    grade = $4, 
				    score = $5,
				    protocol_support_score = $6,
				    key_exchange_score = $7,
				    cipher_strength_score = $8,
				    protocol_grade = $9,
				    protocol_score = $10,
				    certificate_grade = $11,
				    certificate_score = $12,
				    result = $13,
				    duration_ms = $14,
				    ip = $15,
				    certificate_expires_at = $16,
				    certificate_days_remaining = $17,
				    certificate_issuer = $18,
				    certificate_key_type = $19,
				    certificate_key_size = $20,
				    updated_at = NOW()
				WHERE id = $1
			`, scanID, result.ServiceType, result.ConnectionType,
			   result.Grade, result.Score, 
			   result.ProtocolSupportScore, result.KeyExchangeScore, result.CipherStrengthScore,
			   result.ProtocolGrade, result.ProtocolScore,
			   result.CertificateGrade, result.CertificateScore,
			   resultJSON, int(result.Duration.Milliseconds()), result.IP,
			   certExpiresAt, certDaysRemaining, certIssuer, certKeyType, certKeySize); err != nil {
				log.Printf("Worker %d: CRITICAL ERROR - Failed to save scan results: %v", id, err)
				// Try to at least mark it as failed
				if _, dbErr := s.db.ExecContext(ctx, `UPDATE scans SET status = 'failed', error_message = $2 WHERE id = $1`, 
					scanID, fmt.Sprintf("Failed to save results: %v", err)); dbErr != nil {
					log.Printf("Worker %d: CRITICAL - Failed to update status after save failure: %v", id, dbErr)
				}
			}
			
			// Save vulnerabilities
			for _, vuln := range result.Vulnerabilities {
				// Convert CVEs to JSON
				cveJSON, _ := json.Marshal(vuln.CVEs)
				
				if _, err := s.db.ExecContext(ctx, `
					INSERT INTO scan_vulnerabilities (scan_id, vulnerability_name, severity, description, affected, cve_data)
					VALUES ($1, $2, $3, $4, $5, $6)
				`, scanID, vuln.Name, vuln.Severity, vuln.Description, vuln.Affected, cveJSON); err != nil {
					log.Printf("Worker %d: Error saving vulnerability %s: %v", id, vuln.Name, err)
				}
			}
			
			// Save grade degradations
			for _, deg := range result.GradeDegradations {
				if _, err := s.db.ExecContext(ctx, `
					INSERT INTO scan_grade_degradations (scan_id, category, issue, details, impact, remediation)
					VALUES ($1, $2, $3, $4, $5, $6)
				`, scanID, deg.Category, deg.Issue, deg.Details, deg.Impact, deg.Remediation); err != nil {
					log.Printf("Worker %d: Error saving grade degradation: %v", id, err)
				}
			}
			
			// Save weak protocols
			for _, proto := range result.SupportedProtocols {
				if proto.Name == "TLS 1.0" || proto.Name == "TLS 1.1" || proto.Name == "SSL 3.0" || proto.Name == "SSL 2.0" {
					if _, err := s.db.ExecContext(ctx, `
						INSERT INTO scan_weak_protocols (scan_id, protocol_name, protocol_version)
						VALUES ($1, $2, $3)
					`, scanID, proto.Name, proto.Version); err != nil {
						log.Printf("Worker %d: Error saving weak protocol %s: %v", id, proto.Name, err)
					}
				}
			}
			
			// Save weak cipher suites
			for _, cipher := range result.CipherSuites {
				// Mark as weak if: WEAK strength, MEDIUM strength, or (not TLS 1.3 and no forward secrecy)
				isWeak := cipher.Strength == "WEAK" || cipher.Strength == "MEDIUM"
				isMissingPFS := !cipher.Forward && cipher.Protocol != "TLS 1.3"
				
				if isWeak || isMissingPFS {
					if _, err := s.db.ExecContext(ctx, `
						INSERT INTO scan_weak_ciphers (scan_id, cipher_id, cipher_name, has_forward_secrecy, strength, protocol)
						VALUES ($1, $2, $3, $4, $5, $6)
					`, scanID, cipher.ID, cipher.Name, cipher.Forward, cipher.Strength, cipher.Protocol); err != nil {
						log.Printf("Worker %d: Error saving weak cipher %s: %v", id, cipher.Name, err)
					}
				}
			}
		}
		
		// Remove from queue
		if _, err := s.db.ExecContext(ctx, "DELETE FROM scan_queue WHERE scan_id = $1", scanID); err != nil {
			log.Printf("Worker %d: Error removing scan from queue: %v", id, err)
		}
		
		log.Printf("Worker %d: Completed scan %s", id, scanID)
		
		// Clean up context
		cancel()
	}
}