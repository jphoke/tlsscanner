package main

import (
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
		timeout    = flag.Duration("timeout", 10*time.Second, "Connection timeout")
		jsonOutput = flag.Bool("json", false, "Output as JSON")
		verbose    = flag.Bool("v", false, "Verbose output")
		caPath     = flag.String("ca-path", "", "Path to directory containing custom CA certificates")
		checkSSLv3 = flag.Bool("check-sslv3", false, "Enable SSL v3 detection (uses raw sockets)")
	)
	
	flag.Parse()
	
	if *target == "" {
		fmt.Fprintf(os.Stderr, "Error: -target is required\n")
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