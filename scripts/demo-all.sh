#!/bin/bash
# Linux/macOS: chay Server + Internal Service nen, Gateway o cua so hien tai.
cd "$(dirname "$0")/.." && bash scripts/build.sh >/dev/null || exit 1
java -cp out nhom06.server.ExternalServer > logs/external.out 2>&1 &
java -cp out nhom06.internal.InternalService > logs/internal.out 2>&1 &
sleep 1
echo "Mo web dashboard: http://127.0.0.1:8088 ; mo Client o terminal khac: ./scripts/4-run-client.sh"
java -cp out nhom06.gateway.GatewayServer config/gateway.properties
kill %1 %2 2>/dev/null
