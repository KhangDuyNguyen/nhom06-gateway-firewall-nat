#!/bin/bash
cd "$(dirname "$0")/.." && bash scripts/build.sh >/dev/null && java -cp out nhom06.test.LoadTest "$@"
