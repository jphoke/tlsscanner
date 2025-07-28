# Contributing to TLS Scanner Portal

Thank you for your interest in contributing! This guide will help you get started.

## Code of Conduct

Be respectful and constructive. We're all here to improve security tooling.

## How to Contribute

### Reporting Issues

1. **Check existing issues** first to avoid duplicates
2. **Use issue templates** when available
3. **Include details**:
   - How you built/installed the scanner
   - Target that causes the issue
   - Expected vs actual behavior
   - Error messages or logs

### Suggesting Features

1. **Open a discussion** first for major features
2. **Explain the use case** - why is this needed?
3. **Consider compatibility** with existing features

### Submitting Code

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature`
3. **Make focused commits** with clear messages
4. **Add tests** for new functionality
5. **Update documentation** as needed
6. **Submit a pull request**

## Development Setup

### Prerequisites

- Go 1.23+
- Docker and Docker Compose
- Git
- Make (optional but helpful)

### Getting Started

```bash
# Fork and clone
git clone https://github.com/YOUR-USERNAME/tlsscanner
cd tlsscanner/tlsscanner-portal

# Install dependencies
go mod download

# Run tests
go test ./...

# Build locally
go build -o tlsscanner ./cmd/scanner

# Run with Docker
docker compose up -d
```

### Project Structure

```
tlsscanner-portal/
├── cmd/
│   ├── api/          # REST API server
│   └── scanner/      # CLI scanner
├── pkg/
│   └── scanner/      # Core scanner library
├── internal/         # Internal packages
├── web/              # Frontend files
└── scripts/          # Utility scripts
```

## Coding Standards

### Go Code

- Follow standard Go formatting (`go fmt`)
- Use meaningful variable names
- Add comments for exported functions
- Keep functions focused and small
- Handle errors explicitly

### Example

```go
// ScanTarget performs a comprehensive TLS scan of the specified target.
// Returns a Result containing the security assessment or an error.
func ScanTarget(target string, config *Config) (*Result, error) {
    // Validate input
    if target == "" {
        return nil, errors.New("target cannot be empty")
    }
    
    // Implementation...
}
```

### Commit Messages

Follow conventional commits:

```
feat: add LDAP STARTTLS support
fix: correct TLS 1.3 cipher detection
docs: update API examples
test: add scanner edge cases
refactor: simplify grade calculation
```

## Testing

### Running Tests

```bash
# All tests
go test ./...

# With coverage
go test -cover ./...

# Specific package
go test ./pkg/scanner

# Verbose output
go test -v ./...
```

### Writing Tests

```go
func TestScannerGrading(t *testing.T) {
    tests := []struct {
        name     string
        target   string
        expected string
    }{
        {"Modern server", "example.com", "A"},
        {"Weak protocols", "weak.example.com", "C"},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := ScanTarget(tt.target, nil)
            if err != nil {
                t.Fatalf("scan failed: %v", err)
            }
            if result.Grade != tt.expected {
                t.Errorf("got grade %s, want %s", result.Grade, tt.expected)
            }
        })
    }
}
```

## Developer Certificate of Origin

By contributing to this project, you agree to the Developer Certificate of Origin (DCO). This document was created by the Linux Kernel community and is a simple statement that you, as a contributor, have the legal right to make the contribution.

All commits must be signed off:

```bash
git commit -s -m "your commit message"
```

This adds a `Signed-off-by` line to your commit message.

## Pull Request Process

1. **Update your fork**: `git pull upstream main`
2. **Run tests**: `go test ./...`
3. **Check formatting**: `go fmt ./...`
4. **Update docs** if needed
5. **Create PR** with clear description
6. **Respond to feedback** promptly
7. **Ensure commits are signed** with DCO

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows project style
- [ ] Documentation updated
- [ ] Commit messages are clear
- [ ] PR description explains changes
- [ ] All commits are signed-off (DCO)

## Areas for Contribution

### Good First Issues

- Add more vulnerability detections
- Improve error messages
- Add CLI output formats
- Enhance documentation
- Add unit tests

### Advanced Contributions

- New STARTTLS protocols (PostgreSQL, MySQL)
- Performance optimizations
- Additional cipher suite analysis
- Web UI enhancements
- API client libraries

## Release Process

1. Maintainers update version in code
2. Update CHANGELOG.md
3. Create release tag
4. Publish release with notes

## Getting Help

- **Issues**: Use "question" label
- **Discussions**: Use GitHub Discussions for questions
- **Email**: maintainers@tlsscanner.dev

## Recognition

Contributors are recognized in:
- CHANGELOG.md for significant features
- GitHub contributors page
- Release notes

Thank you for helping make TLS Scanner Portal better!