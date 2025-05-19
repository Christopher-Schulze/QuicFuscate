#!/bin/bash
# Skript zum Korrigieren der Namespace-Probleme im UTLSClientConfigurator
sed -i '' 's/SessionTicketManager::getInstance()/quicsand::SessionTicketManager::getInstance()/g' utls_client_configurator.cpp
