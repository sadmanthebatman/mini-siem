#!/usr/bin/env bash
# Load pipeline output into OpenSearch and create index patterns.
set -euo pipefail
HOST="${OPENSEARCH_HOST:-http://localhost:9200}"
BULK="${1:-out/opensearch_bulk.ndjson}"

[ -f "$BULK" ] || { echo "No bulk file at $BULK. Run the analyze command first."; exit 1; }

echo "Waiting for OpenSearch at $HOST ..."
until curl -sf "$HOST/_cluster/health" >/dev/null; do sleep 3; done

echo "Applying index template (ECS field mappings) ..."
curl -sf -X PUT "$HOST/_index_template/siem" -H 'Content-Type: application/json' \
  -d @docker/index_template.json > /dev/null

echo "Bulk loading $(wc -l < "$BULK") lines ..."
curl -sf -X POST "$HOST/_bulk" -H 'Content-Type: application/x-ndjson' \
  --data-binary "@$BULK" | python3 -c "import json,sys; d=json.load(sys.stdin); print('errors:', d.get('errors'))"

curl -sf -X POST "$HOST/siem-signals/_refresh" > /dev/null
COUNT=$(curl -sf "$HOST/siem-signals/_count" | python3 -c "import json,sys; print(json.load(sys.stdin)['count'])")
echo "Loaded. siem-signals now holds $COUNT documents."
echo "Open http://localhost:5601 and create index patterns: siem-signals*, siem-events*"
