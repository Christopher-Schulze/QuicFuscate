#!/bin/bash
# Skript zum Korrigieren der doppelten Namespace-Qualifikation
sed -i '' 's/quicsand::quicsand::SessionTicketManager/quicsand::SessionTicketManager/g' utls_client_configurator.cpp
