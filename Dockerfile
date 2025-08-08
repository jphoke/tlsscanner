# Build stage
FROM golang:1.24-alpine AS builder

# Accept build argument for swagger host
ARG SWAGGER_HOST=localhost:8000

WORKDIR /build

# Install dependencies
RUN apk add --no-cache git bash

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Generate swagger docs with configured host
RUN chmod +x scripts/generate-swagger.sh && \
    SWAGGER_HOST=${SWAGGER_HOST} ./scripts/generate-swagger.sh

# Build the API server
RUN CGO_ENABLED=0 GOOS=linux go build -o api ./cmd/api

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/api .

# Copy static files
COPY web/static ./static

# Copy scripts for maintenance
COPY scripts ./scripts

# Copy generated swagger docs
COPY --from=builder /build/docs/swagger ./docs/swagger

EXPOSE 8080

CMD ["./api"]