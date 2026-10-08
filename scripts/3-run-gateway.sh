#!/bin/bash
cd "$(dirname "$0")/.." && java -cp out nhom06.gateway.GatewayServer config/gateway.properties
