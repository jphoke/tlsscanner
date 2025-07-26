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
)

type Server struct {
	db      *sql.DB
	redis   *redis.Client
	scanner *scanner.Scanner
}

type ScanRequest struct {
	Target   string `json:"target" binding:"required"`
	Priority int    `json:"priority"`
}

type ScanResponse struct {
	ID       string    `json:"id"`
	Status   string    `json:"status"`
	QueuePos int       `json:"queue_position,omitempty"`
	Message  string    `json:"message"`
	Created  time.Time `json:"created"`
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
	
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	log.Printf("Starting API server on port %s", port)
	r.Run(":" + port)
}

func (s *Server) createScan(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	// Create scan record
	var scanID string
	err := s.db.QueryRow(`
		INSERT INTO scans (target, port, status)
		VALUES ($1, $2, 'queued')
		RETURNING id
	`, req.Target, "443").Scan(&scanID)
	
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

func (s *Server) getScan(c *gin.Context) {
	scanID := c.Param("id")
	
	var result json.RawMessage
	var status string
	var grade, protocolGrade, certificateGrade sql.NullString
	var score, protocolScore, certificateScore sql.NullInt64
	var protocolSupportScore, keyExchangeScore, cipherStrengthScore sql.NullInt64
	var certExpiresAt sql.NullTime
	var certDaysRemaining sql.NullInt64
	var certIssuer, certKeyType sql.NullString
	var certKeySize sql.NullInt64
	
	err := s.db.QueryRow(`
		SELECT status, grade, score, 
		       protocol_support_score, key_exchange_score, cipher_strength_score,
		       protocol_grade, protocol_score, 
		       certificate_grade, certificate_score,
		       certificate_expires_at, certificate_days_remaining,
		       certificate_issuer, certificate_key_type, certificate_key_size,
		       result
		FROM scans
		WHERE id = $1
	`, scanID).Scan(&status, &grade, &score, 
		&protocolSupportScore, &keyExchangeScore, &cipherStrengthScore,
		&protocolGrade, &protocolScore,
		&certificateGrade, &certificateScore,
		&certExpiresAt, &certDaysRemaining,
		&certIssuer, &certKeyType, &certKeySize, &result)
	
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

func (s *Server) listScans(c *gin.Context) {
	limit := 50
	offset := 0
	
	rows, err := s.db.Query(`
		SELECT id, target, status, grade, score, created_at
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
		var created time.Time
		
		err := rows.Scan(&id, &target, &status, &grade, &score, &created)
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
	
	for {
		select {
		case <-ticker.C:
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
}

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
				    grade = $2, 
				    score = $3,
				    protocol_support_score = $4,
				    key_exchange_score = $5,
				    cipher_strength_score = $6,
				    protocol_grade = $7,
				    protocol_score = $8,
				    certificate_grade = $9,
				    certificate_score = $10,
				    result = $11,
				    duration_ms = $12,
				    ip = $13,
				    certificate_expires_at = $14,
				    certificate_days_remaining = $15,
				    certificate_issuer = $16,
				    certificate_key_type = $17,
				    certificate_key_size = $18,
				    updated_at = NOW()
				WHERE id = $1
			`, scanID, result.Grade, result.Score, 
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