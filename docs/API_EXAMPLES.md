# API Examples

## Basic Scan

Submit a basic TLS scan:

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "comments": "Regular security check"
  }'
```

## Deep Scan with SSL v3 Detection

Submit a scan with SSL v3 detection enabled:

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "legacy-server.internal:443",
    "comments": "Checking for SSL v3",
    "check_sslv3": true
  }'
```

## High Priority Scan

Submit a high-priority scan:

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "critical-app.company.com",
    "priority": 10,
    "comments": "Urgent security audit",
    "check_sslv3": true
  }'
```

## Response Format

All scan submissions return a response like:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "queue_position": 3,
  "message": "Scan queued successfully",
  "created": "2025-08-01T15:30:00Z"
}
```

## Checking Scan Results

Poll for results using the scan ID:

```bash
curl http://localhost:8000/api/v1/scans/550e8400-e29b-41d4-a716-446655440000
```

## WebSocket Updates

For real-time updates, connect to the WebSocket endpoint:

```javascript
const ws = new WebSocket('ws://localhost:8000/api/v1/ws');

ws.onmessage = (event) => {
  const update = JSON.parse(event.data);
  console.log('Scan update:', update);
};
```

## Notes

- The `check_sslv3` parameter adds a small overhead (1-2 seconds) to scan time
- SSL v3 detection uses raw sockets to bypass Go/zcrypto limitations
- Any server supporting SSL v3 will receive an automatic F grade
- Use `check_sslv3` only when specifically needed to check for legacy protocols