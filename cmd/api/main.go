// @title TLS Scanner Portal API
// @version 1.0.0
// @description High-performance TLS/SSL security scanner API with SSL Labs grading
// @host localhost:8000
// @BasePath /api/v1
// @schemes http https
package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
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

type ScanRequest struct {
	Target   string `json:"target" binding:"required"`
	Priority int    `json:"priority"`
	Comments string `json:"comments" binding:"omitempty,max=100"`
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
	defer db.Close()
	
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
	r.Run(":" + port)
}

// createScan godoc
// @Summary Submit a new scan
// @Description Submit a target hostname or IP address for TLS/SSL scanning
// @Tags scans
// @Accept json
// @Produce json
// @Param scan body ScanRequest true "Scan target"
// @Success 202 {object} ScanResponse
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /scans [post]
func (s *Server) createScan(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	// Create scan record
	var scanID string
	err := s.db.QueryRow(`
		INSERT INTO scans (target, port, status, comments)
		VALUES ($1, $2, 'queued', $3)
		RETURNING id
	`, req.Target, "443", req.Comments).Scan(&scanID)
	
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create scan"})
		return
	}
	
	// Add to queue
	priority := req.Priority
	if priority == 0 {
		priority = 5
	}
	
	_, err = s.db.Exec(`
		INSERT INTO scan_queue (target, priority, scan_id)
		VALUES ($1, $2, $3)
	`, req.Target, priority, scanID)
	
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to queue scan"})
		return
	}
	
	// Publish to Redis for workers
	ctx := c.Request.Context()
	s.redis.Publish(ctx, "scan_queue", scanID)
	
	c.JSON(202, ScanResponse{
		ID:      scanID,
		Status:  "queued",
		Message: "Scan has been queued",
		Created: time.Now(),
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
	
	err := s.db.QueryRow(`
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
	
	if err == sql.ErrNoRows {
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
	vulnRows, err := s.db.Query(`
		SELECT vulnerability_name, severity, description, affected
		FROM scan_vulnerabilities
		WHERE scan_id = $1
		ORDER BY severity
	`, scanID)
	if err == nil {
		defer vulnRows.Close()
		for vulnRows.Next() {
			var name, severity, description string
			var affected bool
			if err := vulnRows.Scan(&name, &severity, &description, &affected); err == nil {
				vulnerabilities = append(vulnerabilities, gin.H{
					"name":        name,
					"severity":    severity,
					"description": description,
					"affected":    affected,
				})
			}
		}
	}
	response["vulnerabilities"] = vulnerabilities
	
	// Get grade degradations
	degradations := []gin.H{}
	degRows, err := s.db.Query(`
		SELECT category, issue, details, impact, remediation
		FROM scan_grade_degradations
		WHERE scan_id = $1
		ORDER BY category
	`, scanID)
	if err == nil {
		defer degRows.Close()
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
	protoRows, err := s.db.Query(`
		SELECT protocol_name, protocol_version
		FROM scan_weak_protocols
		WHERE scan_id = $1
		ORDER BY protocol_version
	`, scanID)
	if err == nil {
		defer protoRows.Close()
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
	cipherRows, err := s.db.Query(`
		SELECT cipher_id, cipher_name, has_forward_secrecy, strength, protocol
		FROM scan_weak_ciphers
		WHERE scan_id = $1
		ORDER BY strength, cipher_name
	`, scanID)
	if err == nil {
		defer cipherRows.Close()
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
	limit := 50
	offset := 0
	
	rows, err := s.db.Query(`
		SELECT id, target, status, grade, score, comments, created_at
		FROM scans
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	
	if err != nil {
		c.JSON(500, gin.H{"error": "Database error"})
		return
	}
	defer rows.Close()
	
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
	scanID := c.Param("id")
	
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()
	
	// Send updates until scan completes
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		var status string
		err := s.db.QueryRow("SELECT status FROM scans WHERE id = $1", scanID).Scan(&status)
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
	var stats struct {
		TotalScans     int
		ScansToday     int
		AverageGrade   string
		QueueLength    int
		ActiveWorkers  int
	}
	
	// Get total scans
	s.db.QueryRow("SELECT COUNT(*) FROM scans").Scan(&stats.TotalScans)
	
	// Get scans today
	s.db.QueryRow(`
		SELECT COUNT(*) FROM scans 
		WHERE created_at >= CURRENT_DATE
	`).Scan(&stats.ScansToday)
	
	// Get queue length
	s.db.QueryRow(`
		SELECT COUNT(*) FROM scan_queue 
		WHERE status = 'pending'
	`).Scan(&stats.QueueLength)
	
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
	// Check database
	if err := s.db.Ping(); err != nil {
		c.JSON(503, gin.H{"status": "unhealthy", "database": "down"})
		return
	}
	
	// Check Redis
	ctx := c.Request.Context()
	if err := s.redis.Ping(ctx).Err(); err != nil {
		c.JSON(503, gin.H{"status": "unhealthy", "redis": "down"})
		return
	}
	
	c.JSON(200, gin.H{"status": "healthy"})
}

func (s *Server) startWorkers(count int) {
	for i := 0; i < count; i++ {
		go s.worker(i)
	}
}

func (s *Server) worker(id int) {
	log.Printf("Worker %d started", id)
	
	for {
		// Get next scan from queue
		var scanID, target string
		err := s.db.QueryRow(`
			UPDATE scan_queue
			SET status = 'processing', started_at = NOW()
			WHERE id = (
				SELECT id FROM scan_queue
				WHERE status = 'pending'
				ORDER BY priority DESC, created_at
				FOR UPDATE SKIP LOCKED
				LIMIT 1
			)
			RETURNING scan_id, target
		`).Scan(&scanID, &target)
		
		if err == sql.ErrNoRows {
			// No work available
			time.Sleep(1 * time.Second)
			continue
		}
		
		if err != nil {
			log.Printf("Worker %d: Failed to get work: %v", id, err)
			time.Sleep(1 * time.Second)
			continue
		}
		
		// Update scan status
		s.db.Exec("UPDATE scans SET status = 'scanning' WHERE id = $1", scanID)
		
		// Perform scan
		log.Printf("Worker %d: Scanning %s", id, target)
		result, err := s.scanner.ScanTarget(target)
		
		if err != nil {
			// Mark as failed
			s.db.Exec(`
				UPDATE scans 
				SET status = 'failed', error_message = $2, updated_at = NOW()
				WHERE id = $1
			`, scanID, err.Error())
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
			s.db.Exec(`
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
			   certExpiresAt, certDaysRemaining, certIssuer, certKeyType, certKeySize)
			
			// Save vulnerabilities
			for _, vuln := range result.Vulnerabilities {
				s.db.Exec(`
					INSERT INTO scan_vulnerabilities (scan_id, vulnerability_name, severity, description, affected)
					VALUES ($1, $2, $3, $4, $5)
				`, scanID, vuln.Name, vuln.Severity, vuln.Description, vuln.Affected)
			}
			
			// Save grade degradations
			for _, deg := range result.GradeDegradations {
				s.db.Exec(`
					INSERT INTO scan_grade_degradations (scan_id, category, issue, details, impact, remediation)
					VALUES ($1, $2, $3, $4, $5, $6)
				`, scanID, deg.Category, deg.Issue, deg.Details, deg.Impact, deg.Remediation)
			}
			
			// Save weak protocols
			for _, proto := range result.SupportedProtocols {
				if proto.Name == "TLS 1.0" || proto.Name == "TLS 1.1" || proto.Name == "SSL 3.0" || proto.Name == "SSL 2.0" {
					s.db.Exec(`
						INSERT INTO scan_weak_protocols (scan_id, protocol_name, protocol_version)
						VALUES ($1, $2, $3)
					`, scanID, proto.Name, proto.Version)
				}
			}
			
			// Save weak cipher suites
			for _, cipher := range result.CipherSuites {
				// Mark as weak if: WEAK strength, MEDIUM strength, or (not TLS 1.3 and no forward secrecy)
				isWeak := cipher.Strength == "WEAK" || cipher.Strength == "MEDIUM"
				isMissingPFS := !cipher.Forward && cipher.Protocol != "TLS 1.3"
				
				if isWeak || isMissingPFS {
					s.db.Exec(`
						INSERT INTO scan_weak_ciphers (scan_id, cipher_id, cipher_name, has_forward_secrecy, strength, protocol)
						VALUES ($1, $2, $3, $4, $5, $6)
					`, scanID, cipher.ID, cipher.Name, cipher.Forward, cipher.Strength, cipher.Protocol)
				}
			}
		}
		
		// Remove from queue
		s.db.Exec("DELETE FROM scan_queue WHERE scan_id = $1", scanID)
		
		log.Printf("Worker %d: Completed scan %s", id, scanID)
	}
}