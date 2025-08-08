package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jphoke/tlsscanner-portal/pkg/scanner"
)

func main() {
	var (
		target     = flag.String("target", "", "Target host:port to scan")
		batch      = flag.String("batch", "", "CSV file with targets for batch scanning")
		batchShort = flag.String("b", "", "Short form of -batch")
		timeout    = flag.Duration("timeout", 10*time.Second, "Connection timeout")
		jsonOutput = flag.Bool("json", false, "Output as JSON")
		verbose    = flag.Bool("v", false, "Verbose output")
		caPath     = flag.String("ca-path", "", "Path to directory containing custom CA certificates")
		checkSSLv3 = flag.Bool("check-sslv3", false, "Enable SSL v3 detection (uses raw sockets)")
		summary    = flag.Bool("summary", false, "Show summary only for batch scans")
	)
	
	flag.Parse()
	
	// Handle short form of batch
	batchFile := *batch
	if batchFile == "" && *batchShort != "" {
		batchFile = *batchShort
	}
	
	// Validate inputs
	if *target == "" && batchFile == "" {
		fmt.Fprintf(os.Stderr, "Error: either -target or -batch is required\n")
		flag.Usage()
		os.Exit(1)
	}
	
	if *target != "" && batchFile != "" {
		fmt.Fprintf(os.Stderr, "Error: cannot use both -target and -batch\n")
		flag.Usage()
		os.Exit(1)
	}
	
	config := scanner.Config{
		Timeout:      *timeout,
		Verbose:      *verbose,
		CustomCAPath: *caPath,
		CheckSSLv3:   *checkSSLv3,
	}
	
	s := scanner.New(config)
	
	// Single target mode
	if *target != "" {
		fmt.Fprintf(os.Stderr, "Scanning %s...\n", *target)
		result, err := s.ScanTarget(*target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
			os.Exit(1)
		}
		
		if *jsonOutput {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(result); err != nil {
				log.Fatalf("Error encoding JSON output: %v", err)
			}
		} else {
			printTextResult(result)
		}
		return
	}
	
	// Batch mode
	if err := runBatchScan(s, batchFile, *jsonOutput, *summary); err != nil {
		fmt.Fprintf(os.Stderr, "Batch scan failed: %v\n", err)
		os.Exit(1)
	}
}

func printTextResult(r *scanner.Result) {
	fmt.Printf("\nTLS Scan Report\n")
	fmt.Printf("===============\n\n")
	
	fmt.Printf("Target: %s\n", r.Target)
	fmt.Printf("IP: %s\n", r.IP)
	fmt.Printf("Port: %s\n", r.Port)
	fmt.Printf("Scan Time: %s\n", r.ScanTime.Format(time.RFC3339))
	fmt.Printf("Duration: %s\n", r.Duration)
	
	fmt.Printf("\n📊 Overall Grade: %s (Score: %d/100) - SSL Labs Methodology\n", r.Grade, r.Score)
	if r.Grade == "F" && r.Score == 0 {
		fmt.Println("   ⚠️  Automatic F due to certificate issues")
	}
	
	fmt.Printf("\n🔍 SSL Labs Scoring:\n")
	fmt.Printf("   Protocol Support: %d/100 (30%% weight)\n", r.ProtocolSupportScore)
	fmt.Printf("   Key Exchange: %d/100 (30%% weight)\n", r.KeyExchangeScore)
	fmt.Printf("   Cipher Strength: %d/100 (40%% weight)\n", r.CipherStrengthScore)
	
	fmt.Printf("\n📋 Additional Details:\n")
	fmt.Printf("   🔐 Protocol/Cipher Grade: %s (%d/100)\n", r.ProtocolGrade, r.ProtocolScore)
	fmt.Printf("   📜 Certificate Grade: %s (%d/100)\n", r.CertificateGrade, r.CertificateScore)
	
	// Protocols
	fmt.Printf("\n🔐 Supported Protocols:\n")
	for _, proto := range r.SupportedProtocols {
		if proto.Enabled {
			symbol := "✅"
			if proto.Version < 0x0303 { // TLS 1.2
				symbol = "⚠️"
			}
			fmt.Printf("  %s %s\n", symbol, proto.Name)
		}
	}
	
	// Certificate
	if r.Certificate != nil {
		fmt.Printf("\n📜 Certificate:\n")
		fmt.Printf("  Subject: %s\n", r.Certificate.Subject)
		fmt.Printf("  Issuer: %s\n", r.Certificate.Issuer)
		fmt.Printf("  Valid: %s to %s\n", 
			r.Certificate.NotBefore.Format("2006-01-02"),
			r.Certificate.NotAfter.Format("2006-01-02"))
		
		if r.Certificate.IsValid {
			fmt.Printf("  Status: ✅ Valid\n")
			// Show if trusted via custom CA
			for _, note := range r.Certificate.ValidationErrors {
				if strings.Contains(note, "custom CA") {
					fmt.Printf("    - %s\n", note)
				}
			}
		} else {
			fmt.Printf("  Status: ❌ Invalid\n")
			for _, err := range r.Certificate.ValidationErrors {
				fmt.Printf("    - %s\n", err)
			}
		}
	}
	
	// Vulnerabilities
	if len(r.Vulnerabilities) > 0 {
		fmt.Printf("\n⚠️  Vulnerabilities:\n")
		for _, vuln := range r.Vulnerabilities {
			symbol := "🔶"
			if vuln.Severity == "HIGH" {
				symbol = "🔴"
			}
			fmt.Printf("  %s %s (%s)\n", symbol, vuln.Name, vuln.Severity)
			fmt.Printf("     %s\n", vuln.Description)
		}
	}
	
	// Cipher Summary
	fmt.Printf("\n🔑 Cipher Suite Summary:\n")
	cipherCounts := map[string]int{
		"VERY_STRONG": 0,
		"STRONG":      0,
		"MEDIUM":      0,
		"WEAK":        0,
		"INSECURE":    0,
	}
	
	for _, cipher := range r.CipherSuites {
		cipherCounts[cipher.Strength]++
	}
	
	fmt.Printf("  Very Strong: %d\n", cipherCounts["VERY_STRONG"])
	fmt.Printf("  Strong: %d\n", cipherCounts["STRONG"])
	fmt.Printf("  Medium: %d\n", cipherCounts["MEDIUM"])
	fmt.Printf("  Weak: %d\n", cipherCounts["WEAK"])
	fmt.Printf("  Insecure: %d\n", cipherCounts["INSECURE"])
	
	// Grade Degradations
	if len(r.GradeDegradations) > 0 {
		fmt.Printf("\n⚠️  Issues Impacting Grade:\n")
		for _, deg := range r.GradeDegradations {
			fmt.Printf("\n  🔸 %s\n", deg.Issue)
			fmt.Printf("     Details: %s\n", deg.Details)
			fmt.Printf("     Impact: %s\n", deg.Impact)
			fmt.Printf("     Fix: %s\n", deg.Remediation)
		}
	}
	
	if len(r.Errors) > 0 {
		fmt.Printf("\n❌ Errors:\n")
		for _, err := range r.Errors {
			fmt.Printf("  - %s\n", err)
		}
	}
	
	fmt.Println()
}

// BatchTarget represents a target from the CSV file
type BatchTarget struct {
	Target     string
	CheckSSLv3 bool
	Comments   string
}

// runBatchScan processes a CSV file with multiple targets
func runBatchScan(s *scanner.Scanner, filename string, jsonOutput, summaryOnly bool) error {
	file, err := os.Open(filename) // #nosec G304 - CLI tool, user-provided filename is expected
	if err != nil {
		return fmt.Errorf("cannot open batch file: %w", err)
	}
	defer file.Close()

	targets, err := parseBatchFile(file)
	if err != nil {
		return fmt.Errorf("cannot parse batch file: %w", err)
	}

	if len(targets) == 0 {
		return fmt.Errorf("no targets found in batch file")
	}

	fmt.Fprintf(os.Stderr, "Starting batch scan of %d targets...\n", len(targets))

	results := make([]*scanner.Result, 0, len(targets))
	successCount := 0
	failCount := 0

	for i, target := range targets {
		fmt.Fprintf(os.Stderr, "[%d/%d] Scanning %s...", i+1, len(targets), target.Target)
		
		// Update scanner config for this specific target
		config := s.GetConfig()
		config.CheckSSLv3 = target.CheckSSLv3
		s.UpdateConfig(config)
		
		result, err := s.ScanTarget(target.Target)
		if err != nil {
			fmt.Fprintf(os.Stderr, " FAILED: %v\n", err)
			failCount++
			// Create a failed result entry
			result = &scanner.Result{
				Target: target.Target,
				Grade:  "-",
				Errors: []string{err.Error()},
			}
		} else {
			fmt.Fprintf(os.Stderr, " Grade: %s\n", result.Grade)
			successCount++
		}
		
		results = append(results, result)
	}

	// Output results
	if summaryOnly {
		printBatchSummary(results, successCount, failCount)
	} else if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		batchResult := map[string]interface{}{
			"scan_count": len(targets),
			"success":    successCount,
			"failed":     failCount,
			"results":    results,
		}
		if err := encoder.Encode(batchResult); err != nil {
			return fmt.Errorf("error encoding JSON output: %w", err)
		}
	} else {
		// Print full text results for each scan
		for _, result := range results {
			printTextResult(result)
			fmt.Println(strings.Repeat("-", 80))
		}
		printBatchSummary(results, successCount, failCount)
	}

	return nil
}

// parseBatchFile reads and parses the CSV file
func parseBatchFile(file *os.File) ([]BatchTarget, error) {
	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true
	
	// Read all records
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("empty CSV file")
	}

	var targets []BatchTarget
	hasHeader := false
	
	// Check if first row looks like a header
	if len(records[0]) > 0 && strings.ToLower(records[0][0]) == "target" {
		hasHeader = true
	}

	startIdx := 0
	if hasHeader {
		startIdx = 1
	}

	for i := startIdx; i < len(records); i++ {
		record := records[i]
		if len(record) == 0 || (len(record) == 1 && record[0] == "") {
			continue // Skip empty lines
		}

		target := BatchTarget{
			Target: record[0],
		}

		// Parse check_sslv3 flag if present
		if len(record) > 1 && record[1] != "" {
			checkSSLv3 := strings.ToLower(strings.TrimSpace(record[1]))
			target.CheckSSLv3 = checkSSLv3 == "y" || checkSSLv3 == "yes" || checkSSLv3 == "true" || checkSSLv3 == "1"
		}

		// Parse comments if present
		if len(record) > 2 {
			target.Comments = record[2]
		}

		targets = append(targets, target)
	}

	return targets, nil
}

// printBatchSummary prints a summary of the batch scan results
func printBatchSummary(results []*scanner.Result, successCount, failCount int) {
	fmt.Printf("\n📊 Batch Scan Summary\n")
	fmt.Printf("====================\n")
	fmt.Printf("Total Scans: %d\n", len(results))
	fmt.Printf("✅ Successful: %d\n", successCount)
	fmt.Printf("❌ Failed: %d\n", failCount)

	// Grade distribution
	gradeCount := make(map[string]int)
	for _, result := range results {
		if result.Grade != "-" {
			gradeCount[result.Grade]++
		}
	}

	if len(gradeCount) > 0 {
		fmt.Printf("\n📈 Grade Distribution:\n")
		for _, grade := range []string{"A+", "A", "A-", "B", "C", "D", "E", "F", "M"} {
			if count, ok := gradeCount[grade]; ok {
				fmt.Printf("  %s: %d\n", grade, count)
			}
		}
	}

	// List of failed scans
	if failCount > 0 {
		fmt.Printf("\n❌ Failed Scans:\n")
		for _, result := range results {
			if len(result.Errors) > 0 {
				fmt.Printf("  - %s: %s\n", result.Target, result.Errors[0])
			}
		}
	}
}