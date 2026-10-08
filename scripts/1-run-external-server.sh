#!/bin/bash
cd "$(dirname "$0")/.." && java -cp out nhom06.server.ExternalServer 127.0.0.3 9000 9001
