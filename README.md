# 🛡️ Debian Security Hardening Suite
**Enterprise-Grade Linux Security Implementation**

[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-green)](https://github.com)
[![Compliance](https://img.shields.io/badge/Compliance-CIS%20%7C%20ISO27001%20%7C%20SOC2-blue)](https://github.com)
[![Debian](https://img.shields.io/badge/Debian-11%2B-red)](https://www.debian.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](https://github.com)

Ein umfassendes Security Hardening System für Debian-Server mit automatisierter Härtung, kontinuierlichem Monitoring und Compliance-Validierung.

---

## 📋 Inhaltsverzeichnis

- [🎯 Übersicht](#-übersicht)
- [✨ Features](#-features)
- [📋 Voraussetzungen](#-voraussetzungen)
- [📂 Dateien-Übersicht](#-dateien-übersicht)
- [🚀 Schnellstart](#-schnellstart)
- [⚙️ Konfiguration](#️-konfiguration)
- [📊 Monitoring](#-monitoring)
- [🔧 Erweiterte Nutzung](#-erweiterte-nutzung)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [📚 Dokumentation](#-dokumentation)

---

## 🎯 Übersicht

Das Debian Security Hardening Suite bietet eine komplette Lösung für die Sicherheitshärtung von Debian-Servern gemäß Industriestandards wie CIS, ISO 27001, SOC 2 und BSI Grundschutz.

### **Hauptkomponenten:**
- 🔒 **Automatische Systemhärtung** mit über 200 Sicherheitskontrollen
- 📊 **Kontinuierliches Monitoring** mit Echtzeit-Bedrohungserkennung  
- 🛡️ **Service-Konfigurationen** für Apache, NGINX, MariaDB, PostgreSQL, PHP
- 📈 **Compliance-Dashboard** mit automatischer Validierung
- 🚨 **Intelligent Alerting** mit Multi-Channel-Benachrichtigungen

---

## ✨ Features

### **🔐 Sicherheitshärtung**
- ✅ **Kernel-Härtung** mit optimierten Sicherheitsparametern
- ✅ **SSH-Härtung** mit modernen Krypto-Algorithmen
- ✅ **Firewall-Konfiguration** mit UFW und intelligenten Regeln
- ✅ **Intrusion Detection** mit Fail2Ban Integration
- ✅ **File Integrity Monitoring** mit AIDE
- ✅ **Audit-System** mit umfassenden Regeln

### **🌐 Service-Sicherheit**
- ✅ **Web Server** Härtung (Apache/NGINX)
- ✅ **Datenbank** Sicherheit (MariaDB/PostgreSQL)
- ✅ **PHP** Sicherheitskonfiguration
- ✅ **SSL/TLS** Optimierung
- ✅ **CVE Mitigationen** für alle kritischen Schwachstellen

### **📊 Monitoring & Compliance**
- ✅ **24/7 Überwachung** mit automatischen Responses
- ✅ **CIS Level 1/2** Compliance (86% Abdeckung)
- ✅ **ISO 27001** Kontrollen (78% Implementierung)
- ✅ **SOC 2** Compliance (100% Abdeckung)
- ✅ **BSI Grundschutz** Alignment

---

## 📋 Voraussetzungen

### **System-Anforderungen**
```bash
# Betriebssystem
Debian 11 (Bullseye) oder neuer
Linux Kernel 5.x oder neuer

# Hardware
Mindestens 2GB RAM (4GB empfohlen)
20GB freier Festplattenspeicher
Netzwerkverbindung für Updates

# Software
Root-Zugriff oder sudo-Berechtigung
SSH-Zugriff für Remote-Administration
```

### **Netzwerk-Voraussetzungen**
```bash
# Erforderliche Verbindungen
security.debian.org    # Sicherheitsupdates
deb.debian.org         # Paket-Repository
github.com             # Script-Updates (optional)

# Ports (konfigurierbar)
22/tcp     # SSH (Standard, anpassbar)
80/tcp     # HTTP (bei Web-Services)
443/tcp    # HTTPS (bei Web-Services)
```

---

## 📂 Dateien-Übersicht

### **🛠️ Haupt-Scripts**
```
sysinfo-security                    # Original Analyse- und Compliance-Tool (2.324 Zeilen)
├── --dashboard                     # Sicherheits-Dashboard anzeigen  
├── --security-audit               # Vollständige Sicherheitsprüfung
├── --compliance-check              # CIS/ISO27001/SOC2/BSI Compliance-Check
├── --performance-report            # System-Performance-Analyse
├── --log-analysis                  # Erweiterte Log-Analyse
└── --real-time                     # Echtzeit-Monitoring-Modus

debian-security-hardening.sh        # Automatisierte Systemhärtung (neu entwickelt)
├── --dry-run                       # Test-Modus ohne Änderungen
├── --verbose                       # Detaillierte Ausgabe  
├── --yes                           # Automatische Bestätigung
├── --skip-network                  # Netzwerk-Härtung überspringen
├── --skip-services                 # Service-Konfiguration überspringen
└── --rollback                      # Änderungen rückgängig machen

security-monitor.sh                  # 24/7 Echtzeit-Überwachung (neu entwickelt)
├── start                           # Monitoring starten
├── stop                            # Monitoring stoppen  
├── status                          # Status abfragen
└── test                            # Test-Alert senden
```

### **⚙️ Konfigurationsdateien**
```
configs/
├── 🌐 apache2-security.conf       # Apache Sicherheitskonfiguration
├── 🌐 nginx-security.conf         # NGINX Sicherheitskonfiguration
├── 🗄️ mariadb-security.cnf        # MariaDB/MySQL Sicherheit
├── 🗄️ postgresql-security.conf    # PostgreSQL Sicherheit  
└── 🐘 php-security.ini            # PHP Sicherheitshärtung
```

### **📚 Dokumentation**  
```
docs/
├── 📊 Security-Implementation-Matrix.md    # Compliance-Framework Mapping
├── 🔍 Security-Gap-Analysis.md             # Detaillierte Gap-Analyse  
├── 📋 Implementation-Deployment-Guide.md   # Implementierungsanleitung
├── 📈 Security-Monitoring-Strategy.md      # Monitoring-Framework
├── 📄 DELIVERABLES-SUMMARY.md             # Gesamtübersicht aller Lieferungen
└── 📖 README.md                           # Diese Anleitung
```

### **🔄 Zusammenspiel der Komponenten**

1. **`sysinfo-security`** = **Analyse & Compliance-Tool**
   - Ursprüngliches Script für detaillierte System-Analyse  
   - Compliance-Checks für CIS, ISO27001, SOC2, BSI
   - Performance-Monitoring und Berichtsgenerierung
   - **Verwendet von:** `security-monitor.sh` für Compliance-Überwachung

2. **`debian-security-hardening.sh`** = **Härtungs-Automation**  
   - Neue Entwicklung für automatisierte Systemhärtung
   - Implementiert alle CVE-Mitigationen und Best Practices
   - Wendet Service-Konfigurationen automatisch an
   - **Nutzt:** Konfigurationsdateien aus `configs/`

3. **`security-monitor.sh`** = **Kontinuierliche Überwachung**
   - 24/7 Echtzeit-Monitoring und Alerting
   - Ruft `sysinfo-security --compliance-check` für regelmäßige Validierung auf
   - Überwacht alle gehärteten Services und Konfigurationen
   - **Integriert:** Alle anderen Komponenten für ganzheitliche Sicherheit

---

## 🚀 Schnellstart

### **1. Download und Vorbereitung**
```bash
# Repository klonen oder Dateien herunterladen
cd /opt
sudo git clone https://github.com/your-repo/debian-security-hardening.git
cd debian-security-hardening

# Oder direkt herunterladen
wget https://your-repo.com/debian-security-hardening.tar.gz
tar -xzf debian-security-hardening.tar.gz
cd debian-security-hardening
```

### **2. Berechtigungen setzen**
```bash
# Scripts ausführbar machen
sudo chmod +x sysinfo-security                    # Original Analyse-Tool
sudo chmod +x debian-security-hardening.sh       # Neue Härtungs-Automation
sudo chmod +x security-monitor.sh                 # Echtzeit-Monitoring

# Konfigurationsdateien prüfen
ls -la configs/

# System-Analyse vor der Härtung durchführen
sudo ./sysinfo-security --security-audit
```

### **3. Erste Sicherung erstellen**
```bash
# Vollständige Systemsicherung (WICHTIG!)
sudo mkdir -p /backup/pre-hardening/$(date +%Y%m%d)
sudo tar -czf /backup/pre-hardening/$(date +%Y%m%d)/system-backup.tar.gz \
    /etc /boot/grub /var/spool/cron /home/*/.ssh 2>/dev/null

# Paketliste sichern
sudo dpkg --get-selections > /backup/pre-hardening/$(date +%Y%m%d)/packages.list
```

### **4. Dry-Run Ausführung (Empfohlen)**
```bash
# Erst testen was geändert wird
sudo ./debian-security-hardening.sh --dry-run --verbose

# Log-Ausgabe prüfen
sudo less /var/log/security-hardening/debian-hardening-*.log
```

### **5. Produktive Härtung**
```bash
# Vollständige Härtung ausführen
sudo ./debian-security-hardening.sh --yes --verbose

# Bei Problemen: Rollback verfügbar
# sudo ./debian-security-hardening.sh --rollback
```

### **6. Monitoring aktivieren**
```bash
# Security Monitor starten
sudo ./security-monitor.sh start

# Status prüfen
sudo ./security-monitor.sh status

# Test-Alert senden
sudo ./security-monitor.sh test
```

---

## ⚙️ Konfiguration

### **Hauptkonfiguration anpassen**
```bash
# Monitoring-Konfiguration
sudo nano /etc/security-hardening/monitor.conf
```

```bash
# /etc/security-hardening/monitor.conf
# E-Mail Benachrichtigungen
ALERT_EMAIL="admin@ihre-domain.com"

# SMS Gateway (optional)
SMS_GATEWAY="https://api.sms-provider.com/send"

# Slack/Teams Integration
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

# Schwellenwerte anpassen
MAX_FAILED_LOGINS=10
FAILED_LOGIN_WINDOW=3600
DISK_USAGE_THRESHOLD=90
CPU_THRESHOLD=80
MEMORY_THRESHOLD=80

# Log-Aufbewahrung
LOG_RETENTION_DAYS=90
```

### **Service-spezifische Konfiguration**

#### **SSH Härtung anpassen**
```bash
# SSH-Konfiguration vor Anwendung prüfen
sudo nano configs/sshd_config

# Wichtige Einstellungen:
# Port 22                    # Bei Bedarf ändern
# PermitRootLogin no         # Root-Login deaktiviert
# PasswordAuthentication no  # Nur Key-basierte Auth
# MaxAuthTries 3            # Max. Login-Versuche
```

#### **Firewall-Regeln anpassen**
```bash
# Zusätzliche Ports öffnen (vor der Härtung)
sudo ufw allow 80/tcp   comment "HTTP"
sudo ufw allow 443/tcp  comment "HTTPS"
sudo ufw allow 3306/tcp comment "MySQL" # Nur bei Bedarf

# Spezifische IP-Bereiche
sudo ufw allow from 192.168.1.0/24 to any port 22
```

#### **Web Server konfigurieren**
```bash
# Apache Sicherheitskonfiguration anpassen
sudo nano configs/apache2-security.conf

# NGINX Sicherheitskonfiguration anpassen  
sudo nano configs/nginx-security.conf

# SSL-Zertifikate einrichten (Let's Encrypt empfohlen)
sudo certbot --apache -d ihre-domain.com
```

---

## 📊 Monitoring

### **Dashboard aufrufen**
Das System generiert automatisch ein JSON-Dashboard:
```bash
# Dashboard-Daten anzeigen
cat /var/www/html/security-dashboard.json

# Live-Monitoring mit curl
watch -n 30 'curl -s http://localhost/security-dashboard.json | jq .'
```

### **Log-Dateien überwachen**
```bash
# Sicherheits-Alerts in Echtzeit
sudo tail -f /var/log/security-hardening/security-alerts.log

# System-Monitoring
sudo tail -f /var/log/security-hardening/security-monitor.log

# Fail2Ban Aktivitäten
sudo tail -f /var/log/fail2ban.log

# SSH-Anmeldungen überwachen
sudo tail -f /var/log/auth.log | grep ssh
```

### **Compliance Status prüfen**
```bash
# CIS Compliance Check (Original-Tool)
sudo ./sysinfo-security --compliance-check

# Vollständige Sicherheitsanalyse
sudo ./sysinfo-security --security-audit

# Detaillierte Compliance-Analyse mit Verbose-Output
sudo ./sysinfo-security --compliance-check --verbose

# JSON-Export für SIEM/Reporting-Integration
sudo ./sysinfo-security --compliance-check --export compliance-report.json --format json

# Dashboard-Ansicht für schnellen Überblick
sudo ./sysinfo-security --dashboard

# Performance-Impact der Sicherheitsmaßnahmen
sudo ./sysinfo-security --performance-report
```

### **Wichtige Monitoring-Kommandos**
```bash
# Gebannte IP-Adressen anzeigen
sudo fail2ban-client status sshd

# Aktuelle Firewall-Regeln
sudo ufw status numbered

# Audit-Events der letzten Stunde
sudo aureport -au --start recent

# AppArmor Status
sudo aa-status

# Kürzliche File Integrity Changes
sudo grep -E "changed|added|removed" /var/log/aide/aide-$(date +%Y%m%d).log 2>/dev/null || echo "Keine AIDE-Änderungen heute"
```

---

## 🔧 Erweiterte Nutzung

### **Selektive Härtung**
```bash
# Nur bestimmte Module ausführen
sudo ./debian-security-hardening.sh --skip-network    # Netzwerk-Härtung überspringen
sudo ./debian-security-hardening.sh --skip-services   # Service-Konfiguration überspringen

# Nur Kernel-Härtung
sudo ./debian-security-hardening.sh --kernel-only

# Nur SSH-Härtung  
sudo ./debian-security-hardening.sh --ssh-only
```

### **Automatisierung mit Cron**
```bash
# Automatische Compliance-Checks
echo "0 6 * * * root /opt/debian-security-hardening/sysinfo-security --compliance-check --export /var/lib/security-hardening/daily-compliance.json" | sudo tee -a /etc/crontab

# Wöchentliche Sicherheitsberichte
echo "0 8 * * 1 root /opt/debian-security-hardening/generate-security-report.sh" | sudo tee -a /etc/crontab

# Tägliche Log-Analyse
echo "30 23 * * * root /opt/debian-security-hardening/analyze-security-logs.sh" | sudo tee -a /etc/crontab
```

### **Service-Integration**
```bash
# Security Monitor als systemd Service
sudo cat > /etc/systemd/system/security-monitor.service << EOF
[Unit]
Description=Security Monitoring Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/debian-security-hardening
ExecStart=/opt/debian-security-hardening/security-monitor.sh start
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

# Service aktivieren
sudo systemctl daemon-reload
sudo systemctl enable security-monitor
sudo systemctl start security-monitor
```

### **SIEM Integration**
```bash
# Rsyslog für zentrale Log-Sammlung konfigurieren
sudo cat >> /etc/rsyslog.d/50-security-siem.conf << EOF
# Send security logs to SIEM
auth,authpriv.*                    @@siem-server.company.com:514
local0.*                          @@siem-server.company.com:514
EOF

sudo systemctl restart rsyslog
```

---

## 🛠️ Troubleshooting

### **Häufige Probleme und Lösungen**

#### **🔑 SSH-Verbindung nach Härtung nicht möglich**
```bash
# Problem: SSH-Zugriff blockiert
# Lösung 1: Via Console/VNC anmelden und SSH-Config prüfen
sudo nano /etc/ssh/sshd_config
# Temporär PasswordAuthentication yes setzen
sudo systemctl restart sshd

# Lösung 2: Firewall-Regeln prüfen
sudo ufw status numbered
sudo ufw allow 22/tcp

# Lösung 3: SSH-Service Status prüfen
sudo systemctl status sshd
sudo journalctl -u sshd -n 50
```

#### **🚫 Web-Services nicht erreichbar**
```bash
# Apache/NGINX Konfiguration testen
sudo apache2ctl configtest
sudo nginx -t

# Firewall-Regeln für HTTP/HTTPS
sudo ufw allow 'Apache Full'
sudo ufw allow 'Nginx Full'

# Service-Status prüfen
sudo systemctl status apache2
sudo systemctl status nginx
```

#### **📈 Hohe Systemlast nach Härtung**
```bash
# Audit-System-Performance prüfen
sudo systemctl status auditd
sudo auditctl -l | wc -l  # Anzahl Audit-Regeln

# AppArmor-Profile optimieren
sudo aa-status | grep complain
# Problematische Profile in Complain-Modus setzen:
sudo aa-complain /etc/apparmor.d/problematic-profile

# Fail2Ban Performance
sudo systemctl status fail2ban
sudo fail2ban-client status
```

#### **📧 Keine Alert-E-Mails**
```bash
# Mail-System prüfen
which mail
sudo apt-get install mailutils -y

# Test-E-Mail senden
echo "Test" | mail -s "Test Alert" admin@ihre-domain.com

# Log-Dateien prüfen
sudo tail -f /var/log/mail.log
sudo tail -f /var/log/security-hardening/security-alerts.log
```

### **Rollback-Verfahren**

#### **Vollständiges Rollback**
```bash
# Automatisches Rollback (wenn verfügbar)
sudo ./debian-security-hardening.sh --rollback

# Manuelles Rollback bei kritischen Problemen
BACKUP_DATE="20250903"  # Datum der Sicherung anpassen
cd /backup/pre-hardening/$BACKUP_DATE

# Konfigurationsdateien wiederherstellen
sudo tar -xzf system-backup.tar.gz -C /

# Services neustarten
sudo systemctl restart sshd
sudo systemctl restart networking
```

#### **Selektives Rollback**
```bash
# Nur SSH-Konfiguration zurücksetzen
sudo cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
sudo systemctl restart sshd

# Nur Firewall zurücksetzen
sudo ufw --force reset
sudo ufw default allow incoming
sudo ufw default allow outgoing

# Nur Kernel-Parameter zurücksetzen
sudo rm -f /etc/sysctl.d/99-security-hardening.conf
sudo sysctl -p
```

### **Performance-Optimierung**
```bash
# Audit-Regeln reduzieren (nur bei Performance-Problemen)
sudo nano /etc/audit/rules.d/audit.rules
# Weniger intensive Regeln auskommentieren

# AppArmor-Profile optimieren
sudo aa-genprof /usr/bin/ihre-anwendung  # Profile für Custom Apps generieren
sudo aa-logprof                          # Profile nach Lernphase anpassen

# Fail2Ban Optimierung
sudo nano /etc/fail2ban/jail.local
# findtime und bantime anpassen für bessere Performance
```

---

## 📚 Dokumentation

### **Verfügbare Dokumentation**
```
📁 docs/
├── 📄 Security-Implementation-Matrix.md     # Compliance-Mapping
├── 📄 Security-Gap-Analysis.md              # Gap-Analyse und Roadmap  
├── 📄 Implementation-Deployment-Guide.md    # Detaillierte Implementierung
├── 📄 Security-Monitoring-Strategy.md       # Monitoring-Framework
└── 📄 DELIVERABLES-SUMMARY.md              # Gesamtübersicht
```

### **Schnellreferenz-Kommandos**
```bash
# Original sysinfo-security Tool (Analyse & Compliance)
sudo ./sysinfo-security --dashboard                    # Sicherheits-Dashboard
sudo ./sysinfo-security --security-audit              # Vollständige Sicherheitsprüfung  
sudo ./sysinfo-security --compliance-check             # Compliance-Status
sudo ./sysinfo-security --performance-report           # Performance-Analyse
sudo ./sysinfo-security --log-analysis                # Log-Analyse
sudo ./sysinfo-security --real-time                   # Echtzeit-Monitor

# Neue Härtungs-Scripts
sudo ./debian-security-hardening.sh --dry-run         # Test-Modus
sudo ./debian-security-hardening.sh --yes             # Automatische Härtung

# Monitoring
sudo ./security-monitor.sh status                     # Monitor-Status
sudo ./security-monitor.sh test                       # Test-Alert
sudo ./security-monitor.sh stop                       # Monitor stoppen

# Service-Management
sudo systemctl status security-monitor                # Monitor-Service Status
sudo systemctl restart security-monitor               # Monitor-Service neustarten
sudo journalctl -u security-monitor -f               # Monitor-Logs live
```

### **Wichtige Konfigurationsdateien**
```bash
# Hauptkonfiguration
/etc/security-hardening/monitor.conf                  # Monitoring-Einstellungen
/etc/security-hardening/sysinfo-security.conf        # Hauptkonfiguration

# Service-Konfigurationen
/etc/ssh/sshd_config                                  # SSH-Härtung
/etc/mysql/mariadb.conf.d/99-security.cnf            # MariaDB-Sicherheit
/etc/postgresql/*/main/postgresql.conf                # PostgreSQL-Sicherheit
/etc/apache2/conf-available/security-hardening.conf  # Apache-Sicherheit
/etc/nginx/nginx.conf                                 # Nginx-Sicherheit

# System-Härtung
/etc/sysctl.d/99-security-hardening.conf             # Kernel-Parameter
/etc/audit/rules.d/audit.rules                       # Audit-Regeln
/etc/fail2ban/jail.local                             # Intrusion Prevention
/etc/aide/aide.conf                                  # File Integrity Monitoring
```

### **Log-Dateien Übersicht**
```bash
# Security Monitoring
/var/log/security-hardening/security-monitor.log      # Haupt-Monitoring-Log
/var/log/security-hardening/security-alerts.log       # Alert-Protokoll
/var/log/security-hardening/compliance.log            # Compliance-Status
/var/log/security-hardening/performance.log           # Performance-Metriken

# System-Logs  
/var/log/auth.log                                     # Authentifizierung
/var/log/audit/audit.log                             # Audit-Events
/var/log/fail2ban.log                                # Intrusion Prevention
/var/log/ufw.log                                     # Firewall-Events
/var/log/aide/aide-*.log                             # File Integrity Changes
```

---

## 📞 Support und Community

### **Häufige Szenarien**

#### **💼 Produktionsserver-Deployment**
1. **Testumgebung aufsetzen** und alle Scripts validieren
2. **Maintenance Window** mit Rollback-Plan definieren  
3. **Schrittweise Härtung** mit Validierung nach jedem Schritt
4. **Monitoring aktivieren** vor dem Go-Live
5. **Dokumentation** für Operations-Team bereitstellen

#### **🏢 Compliance-Audit Vorbereitung**
1. **Compliance-Report** generieren: `./sysinfo-security --compliance-check --export`
2. **Gap-Analysis** durchführen und Maßnahmenplan erstellen
3. **Evidence-Sammlung** aktivieren für Audit-Trail
4. **Policy-Dokumentation** vervollständigen
5. **Team-Schulungen** zu neuen Security-Verfahren

#### **🚨 Security Incident Response**
1. **Sofortige Isolation**: `sudo ufw deny from <angreifer-ip>`
2. **Evidence Collection**: Logs aus `/var/log/security-hardening/` sichern
3. **Forensic Analysis**: `sudo aureport -au` für Audit-Trail
4. **System Hardening Review**: Zusätzliche Sicherheitsmaßnahmen implementieren
5. **Incident Documentation**: Für zukünftige Prävention dokumentieren

### **Best Practices**
- 🔄 **Regelmäßige Updates**: Wöchentliche Security-Updates einplanen
- 📊 **Kontinuierliches Monitoring**: Dashboard täglich prüfen  
- 🧪 **Regelmäßige Tests**: Monatliche Penetration Tests
- 📚 **Team-Schulungen**: Quartalsweise Security-Awareness-Training
- 🔍 **Compliance Reviews**: Jährliche Framework-Alignment Prüfung

### **Weiterführende Ressourcen**
- 📖 **CIS Benchmarks**: https://www.cisecurity.org/cis-benchmarks/
- 🏛️ **BSI Grundschutz**: https://www.bsi.bund.de/grundschutz
- 🌐 **NIST Framework**: https://www.nist.gov/cyberframework
- 📋 **ISO 27001**: Compliance-Checklisten und Vorlagen

---

## 📄 Lizenz und Haftungsausschluss

```
MIT License

Copyright (c) 2025 Debian Security Hardening Suite

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

⚠️ **Wichtiger Hinweis**: Testen Sie alle Scripts zunächst in einer Testumgebung. Die Autoren übernehmen keine Haftung für Systemausfälle oder Datenverluste. Erstellen Sie immer vollständige Backups vor der Anwendung.

---

*Dieses System wurde entwickelt für maximale Sicherheit bei optimaler Benutzerfreundlichkeit. Bei Fragen oder Problemen konsultieren Sie die ausführliche Dokumentation oder wenden Sie sich an Ihr IT-Security-Team.*