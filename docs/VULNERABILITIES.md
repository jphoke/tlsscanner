# TLS Vulnerability Detection Guide

This document explains how the TLS Scanner Portal detects and reports various TLS/SSL vulnerabilities. Understanding these detection methods helps interpret scan results and remediation priorities.

## Table of Contents

- [Detection Philosophy](#detection-philosophy)
- [Vulnerability Checks](#vulnerability-checks)
  - [BEAST Attack](#beast-attack)
  - [SWEET32](#sweet32)
  - [FREAK Attack](#freak-attack)
  - [RC4 Weaknesses](#rc4-weaknesses)
  - [Anonymous Ciphers](#anonymous-ciphers)
  - [Weak DH Parameters](#weak-dh-parameters)
  - [Heartbleed](#heartbleed)
- [Severity Levels](#severity-levels)
- [Grade Impact](#grade-impact)
- [Future Detections](#future-detections)

## Detection Philosophy

The scanner uses **passive detection methods** exclusively. We do not:
- Attempt to exploit vulnerabilities
- Send malicious payloads
- Perform denial-of-service tests
- Try to extract sensitive data

All detections are based on:
- Protocol version analysis
- Cipher suite enumeration
- Certificate examination
- Configuration pattern matching

## Vulnerability Checks

### BEAST Attack
**CVE-2011-3389 | CVSS 5.9 | Severity: HIGH**

#### Detection Method
The scanner checks for the combination of:
1. TLS 1.0 protocol support
2. CBC mode cipher suites

#### Detection Logic
```
IF (TLS 1.0 is enabled) AND (CBC ciphers are supported) THEN
    Mark as vulnerable to BEAST
```

#### Why This Matters
BEAST exploits a weakness in TLS 1.0's CBC mode implementation, allowing attackers to decrypt HTTPS cookies and hijack sessions.

#### Example Vulnerable Configuration
- Server supports TLS 1.0
- Offers ciphers like `TLS_RSA_WITH_AES_128_CBC_SHA`

---

### SWEET32
**CVE-2016-2183, CVE-2016-6329 | CVSS 5.9 | Severity: HIGH**

#### Detection Method
The scanner identifies any 3DES cipher suites in the supported cipher list.

#### Detection Logic
```
IF (any cipher contains "3DES" or "DES_EDE") THEN
    Mark as vulnerable to SWEET32
```

#### Why This Matters
3DES uses 64-bit blocks, making it vulnerable to birthday attacks when large amounts of data are encrypted (>32GB).

#### Example Vulnerable Ciphers
- `TLS_RSA_WITH_3DES_EDE_CBC_SHA`
- `TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA`

---

### FREAK Attack
**CVE-2015-0204 | CVSS 7.5 | Severity: HIGH**

#### Detection Method
The scanner looks for export-grade cipher suites (deliberately weakened encryption from the 1990s).

#### Detection Logic
```
IF (any cipher contains "EXPORT" or has ≤512-bit RSA) THEN
    Mark as vulnerable to FREAK
```

#### Why This Matters
Export ciphers use intentionally weak keys (512-bit RSA) that can be broken in hours, allowing man-in-the-middle attacks.

#### Example Vulnerable Ciphers
- `TLS_RSA_EXPORT_WITH_RC4_40_MD5`
- `TLS_RSA_EXPORT_WITH_DES40_CBC_SHA`

---

### RC4 Weaknesses
**CVE-2013-2566, CVE-2015-2808 | CVSS 5.9 | Severity: MEDIUM**

#### Detection Method
The scanner identifies any RC4-based cipher suites.

#### Detection Logic
```
IF (any cipher contains "RC4") THEN
    Mark as having RC4 weaknesses
```

#### Why This Matters
RC4 has statistical biases that allow plaintext recovery, especially problematic for frequently transmitted data like HTTP cookies.

#### Example Vulnerable Ciphers
- `TLS_RSA_WITH_RC4_128_SHA`
- `TLS_ECDHE_RSA_WITH_RC4_128_SHA`

---

### Anonymous Ciphers
**No specific CVE | Severity: CRITICAL**

#### Detection Method
The scanner checks for cipher suites that don't provide authentication.

#### Detection Logic
```
IF (cipher name contains "anon" or "NULL") THEN
    Mark as supporting anonymous ciphers
```

#### Why This Matters
Anonymous ciphers provide no authentication, making man-in-the-middle attacks trivial.

#### Example Vulnerable Ciphers
- `TLS_DH_anon_WITH_AES_128_CBC_SHA`
- `TLS_ECDH_anon_WITH_AES_128_CBC_SHA`

---

### Weak DH Parameters
**Related to CVE-2015-4000 (Logjam) | Severity: LOW**

#### Detection Method
The scanner checks for DH cipher suites without ECDH variants.

#### Detection Logic
```
IF (DH ciphers exist) AND (no ECDH ciphers) THEN
    Warn about potential weak DH parameters
```

#### Why This Matters
Many servers use weak (≤1024-bit) DH parameters, though we can't determine the exact size without active testing.

---

### Heartbleed
**CVE-2014-0160 | CVSS 7.5 | Severity: CRITICAL/HIGH**

#### Detection Method
The scanner uses **heuristic analysis** with confidence scoring. This is NOT active exploitation.

#### Detection Logic
```
Confidence Score Calculation:
- Supports TLS 1.0-1.2: +40 points
- Only legacy ciphers: +30 points  
- Has legacy ciphers: +15 points
- Certificate issued before April 2014: +20 points
- Cipher ordering matches emergency patches: +10 points

IF (confidence ≥ 60%) THEN
    Report as potentially vulnerable
```

#### Confidence Levels
- **80-100%**: CRITICAL - Strong indicators of vulnerability
- **60-79%**: HIGH - Likely vulnerable, verify with dedicated tools
- **<60%**: Not flagged

#### Why This Approach
Since we don't perform active exploitation, we analyze patterns common in vulnerable servers:
1. **TLS Version**: Heartbleed only affects TLS 1.0-1.2
2. **Certificate Age**: Pre-Heartbleed certificates suggest unpatched systems
3. **Cipher Patterns**: Emergency patches often had specific cipher preferences
4. **Legacy Support**: Unpatched servers typically support older ciphers

#### Example Detection
```
Server: old-server.example.com
- TLS versions: 1.0, 1.1, 1.2 (no 1.3) → +40
- Certificate issued: 2009 → +20  
- First cipher: ECDHE_RSA_WITH_AES_128_CBC_SHA → +10
- Supports RC4 and 3DES → +15
Total: 85% confidence → Flagged as CRITICAL
```

## Severity Levels

Vulnerabilities are classified as:

- **CRITICAL**: Immediate action required (e.g., Heartbleed, anonymous ciphers)
- **HIGH**: Serious vulnerabilities requiring prompt remediation
- **MEDIUM**: Moderate risk, should be addressed in maintenance windows
- **LOW**: Lower priority but should be fixed for best security

## Grade Impact

Vulnerabilities affect the final grade:

| Vulnerability | Grade Cap | Reason |
|--------------|-----------|---------|
| BEAST | C | TLS 1.0 protocols |
| SWEET32 | B | Weak ciphers |
| FREAK | F | Export ciphers |
| RC4 | F | Broken cipher |
| Anonymous | F | No authentication |
| Heartbleed | F* | Critical vulnerability |

*Heartbleed doesn't cap the grade directly but is reported as a critical finding.

## Future Detections

Planned vulnerability detections include:

### POODLE (CVE-2014-3566)
- Check for SSL 3.0 support
- Identify CBC mode ciphers in SSL 3.0

### CRIME/BREACH
- Detect TLS compression support
- Analyze HTTP compression headers

### ROBOT (CVE-2017-13099)
- Identify RSA key exchange ciphers
- Check for specific Oracle patterns

### Full Logjam Detection
- Extract DH parameter sizes
- Flag parameters ≤1024 bits

### SSL v2/v3 Detection
- Requires external tool integration
- Cannot be detected with Go's crypto/tls

## Important Notes

1. **False Positives**: Heuristic detection may flag patched servers. Always verify with specialized tools.

2. **Evolving Threats**: New vulnerabilities emerge regularly. Keep the scanner updated.

3. **Compliance**: Some vulnerabilities (like BEAST) may be acceptable risks in certain environments but fail compliance audits.

4. **Remediation Priority**: Focus on CRITICAL and HIGH severity issues first, especially those that result in an F grade.

5. **Defense in Depth**: Vulnerability scanning is one layer of security. Combine with:
   - Regular patching
   - Security monitoring
   - Access controls
   - Network segmentation

For questions or to report detection issues, please open a GitHub issue.