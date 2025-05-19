#!/bin/bash

# Farben für bessere Lesbarkeit
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}QuicSand uTLS Integration Test Runner${NC}"
echo "=========================================="

# Erstelle Build-Verzeichnis
echo -e "${YELLOW}1. Build-Verzeichnis vorbereiten...${NC}"
mkdir -p build
cd build || { echo -e "${RED}Konnte nicht ins Build-Verzeichnis wechseln${NC}"; exit 1; }

# CMake-Konfiguration
echo -e "${YELLOW}2. CMake-Konfiguration generieren...${NC}"
cmake .. || { echo -e "${RED}CMake-Konfiguration fehlgeschlagen${NC}"; exit 1; }

# Kompilieren der Tests
echo -e "${YELLOW}3. Tests kompilieren...${NC}"
make utls_tests || { echo -e "${RED}Kompilieren der Tests fehlgeschlagen${NC}"; exit 1; }

# Tests ausführen
echo -e "${YELLOW}4. Tests ausführen...${NC}"
cd bin || { echo -e "${RED}Konnte nicht ins Bin-Verzeichnis wechseln${NC}"; exit 1; }

echo -e "${YELLOW}Standardtests (ohne Netzwerktests):${NC}"
./utls_tests || { echo -e "${RED}Testausführung fehlgeschlagen${NC}"; exit 1; }

echo ""
echo -e "${GREEN}Alle Tests erfolgreich abgeschlossen!${NC}"
echo "Die uTLS-Integration in QuicSand funktioniert korrekt."
echo ""
echo -e "${YELLOW}Weitere Optionen:${NC}"
echo "1. Führe './utls_tests --gtest_also_run_disabled_tests' aus, um auch die Netzwerktests auszuführen."
echo "2. Führe './utls_tests --gtest_filter=UTLSTests.TestUTLSClientConfigurator' aus, um nur bestimmte Tests auszuführen."
