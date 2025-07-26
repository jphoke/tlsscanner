.PHONY: help build up down logs clean test scanner-build

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

build: ## Build all Docker images
	docker compose build

up: ## Start all services (Web UI: http://localhost:3000, API: http://localhost:8000)
	docker compose up -d

down: ## Stop all services
	docker compose down

logs: ## View logs
	docker compose logs -f

clean: ## Stop services and remove volumes
	docker compose down -v

test: ## Run tests
	go test ./...

scanner-build: ## Build scanner CLI
	go build -o scanner ./cmd/scanner

scan: scanner-build ## Run a test scan
	./scanner -target $(target)

db-shell: ## Connect to PostgreSQL
	docker compose exec postgres psql -U postgres tlsscanner

redis-cli: ## Connect to Redis
	docker compose exec redis redis-cli

api-logs: ## View API logs
	docker compose logs -f api

restart: ## Restart all services
	docker compose restart

cleanup-7: ## Clean up scans older than 7 days
	@docker compose exec -T postgres psql -U postgres -d tlsscanner -c "DELETE FROM scan_queue WHERE created_at < NOW() - INTERVAL '7 days';"
	@docker compose exec -T postgres psql -U postgres -d tlsscanner -c "DELETE FROM scans WHERE created_at < NOW() - INTERVAL '7 days';"
	@docker compose exec -T postgres psql -U postgres -d tlsscanner -c "VACUUM ANALYZE;"
	@echo "Cleaned up scans older than 7 days"

cleanup-30: ## Clean up scans older than 30 days
	@docker compose exec -T postgres psql -U postgres -d tlsscanner -c "DELETE FROM scan_queue WHERE created_at < NOW() - INTERVAL '30 days';"
	@docker compose exec -T postgres psql -U postgres -d tlsscanner -c "DELETE FROM scans WHERE created_at < NOW() - INTERVAL '30 days';"
	@docker compose exec -T postgres psql -U postgres -d tlsscanner -c "VACUUM ANALYZE;"
	@echo "Cleaned up scans older than 30 days"

cleanup-90: ## Clean up scans older than 90 days
	@docker compose exec -T postgres psql -U postgres -d tlsscanner -c "DELETE FROM scan_queue WHERE created_at < NOW() - INTERVAL '90 days';"
	@docker compose exec -T postgres psql -U postgres -d tlsscanner -c "DELETE FROM scans WHERE created_at < NOW() - INTERVAL '90 days';"
	@docker compose exec -T postgres psql -U postgres -d tlsscanner -c "VACUUM ANALYZE;"
	@echo "Cleaned up scans older than 90 days"

cleanup-all: ## Delete ALL scans (WARNING!)
	@echo "WARNING: This will delete ALL scans from the database!"
	@echo "Press Ctrl+C to cancel, or Enter to continue..."
	@read confirm
	@docker compose exec -T postgres psql -U postgres -d tlsscanner -c "TRUNCATE scan_queue, scans CASCADE;"
	@docker compose exec -T postgres psql -U postgres -d tlsscanner -c "VACUUM ANALYZE;"
	@echo "All scans deleted"