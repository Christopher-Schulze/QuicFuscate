#!/bin/bash

# Skript zum Zusammenführen der MTU-Manager-Teildateien

# Zieldatei
TARGET_FILE="core/quic_path_mtu_manager.cpp"

# Erstelle die Zieldatei
echo "// Automatisch zusammengeführte Datei aus den Teil-Implementierungen" > $TARGET_FILE
echo "// Erstellt am $(date)" >> $TARGET_FILE
echo "" >> $TARGET_FILE

# Füge Inhalt der Teildateien hinzu
for PART_FILE in core/quic_path_mtu_manager_part*.cpp; do
    echo "// Verarbeite $PART_FILE ..."
    
    # Füge Kommentar für Quelldatei hinzu
    echo "" >> $TARGET_FILE
    echo "// --- Beginn von $PART_FILE ---" >> $TARGET_FILE
    echo "" >> $TARGET_FILE
    
    # Extrahiere Inhalt (ohne Kommentarzeilen, die auf Teildateien hinweisen)
    grep -v "^// Teil [0-9]" $PART_FILE >> $TARGET_FILE
    
    # Füge Kommentar für Ende der Quelldatei hinzu
    echo "" >> $TARGET_FILE
    echo "// --- Ende von $PART_FILE ---" >> $TARGET_FILE
    echo "" >> $TARGET_FILE
    
    echo "Verarbeitet: $PART_FILE"
done

echo "Fertig! Die zusammengeführte Datei wurde erstellt: $TARGET_FILE"
