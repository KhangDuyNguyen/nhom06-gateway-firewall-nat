#!/bin/bash
# Bien dich toan bo du an (Linux / macOS)
cd "$(dirname "$0")/.."
mkdir -p out logs
find src -name "*.java" > sources.txt
javac -encoding UTF-8 -d out @sources.txt && echo "Bien dich thanh cong -> thu muc out/"
rm -f sources.txt
