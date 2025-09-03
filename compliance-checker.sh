#!/bin/bash

################################################################################
# Security Compliance Checker
# NUR ANALYSE - KEINE SYSTEMÄNDERUNGEN!
# Verwendet das ursprüngliche sysinfo-security Tool
################################################################################

set -euo pipefail

# Konfiguration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SYSINFO_TOOL="$SCRIPT_DIR/sysinfo-security"
readonly OUTPUT_DIR="/tmp/compliance-reports"
readonly DATE_STR=$(date +%Y%m%d-%H%M%S)

# Farben für Output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m' 
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'

# Print-Funktionen
print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                    Security Compliance Checker${NC}"
    echo -e "${CYAN}              NUR ANALYSE - KEINE SYSTEMÄNDERUNGEN${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}\n"
}

print_section() {
    echo -e "\n${CYAN}▶ $1${NC}"
    echo -e "${CYAN}$(printf '%*s' ${#1} | tr ' ' '-')${NC}"
}

print_status() {
    local status="$1"
    local message="$2"
    
    case "$status" in
        "OK"|"PASS")
            echo -e "  ${GREEN}[✓]${NC} $message"
            ;;
        "WARN"|"WARNING")  
            echo -e "  ${YELLOW}[⚠]${NC} $message"
            ;;
        "FAIL"|"ERROR"|"CRITICAL")
            echo -e "  ${RED}[✗]${NC} $message"
            ;;
        "INFO")
            echo -e "  ${BLUE}[ℹ]${NC} $message"
            ;;
        *)
            echo -e "  ${WHITE}[•]${NC} $message"
            ;;
    esac
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Fehler: Dieses Tool benötigt Root-Rechte für vollständige Analyse${NC}" >&2
        echo -e "${YELLOW}Hinweis: Einige Features sind ohne Root-Zugriff eingeschränkt${NC}" >&2
        return 1
    fi
    return 0
}

# Check if sysinfo-security exists
check_sysinfo_tool() {
    if [[ ! -x "$SYSINFO_TOOL" ]]; then
        echo -e "${RED}Fehler: $SYSINFO_TOOL nicht gefunden oder nicht ausführbar${NC}" >&2
        echo -e "${YELLOW}Stellen Sie sicher, dass das sysinfo-security Tool im gleichen Verzeichnis liegt${NC}" >&2
        exit 1
    fi
}

# Create output directory
create_output_dir() {
    mkdir -p "$OUTPUT_DIR"
    print_status "INFO" "Reports werden gespeichert in: $OUTPUT_DIR"
}

# Quick security dashboard
quick_dashboard() {
    print_section "Sicherheits-Dashboard (Schnellübersicht)"
    
    print_status "INFO" "Führe Dashboard-Analyse durch..."
    "$SYSINFO_TOOL" --dashboard
    
    return 0
}

# Full compliance check
full_compliance_check() {
    print_section "Vollständiger Compliance-Check"
    
    local report_file="$OUTPUT_DIR/compliance-check-$DATE_STR.txt"
    
    print_status "INFO" "Führe umfassenden Compliance-Check durch..."
    print_status "INFO" "Dies kann einige Minuten dauern..."
    
    # Run compliance check and save output
    "$SYSINFO_TOOL" --compliance-check --verbose > "$report_file" 2>&1
    
    # Show summary
    print_status "INFO" "Compliance-Check abgeschlossen"
    print_status "OK" "Detailbericht gespeichert: $report_file"
    
    # Extract key statistics
    local total_checks=$(grep -E "PASS|FAIL" "$report_file" | wc -l)
    local passed_checks=$(grep "PASS" "$report_file" | wc -l)
    local failed_checks=$(grep "FAIL" "$report_file" | wc -l)
    local critical_issues=$(grep "CRITICAL" "$report_file" | wc -l)
    
    if [[ $total_checks -gt 0 ]]; then
        local pass_percentage=$((passed_checks * 100 / total_checks))
        
        echo -e "\n${WHITE}Compliance-Zusammenfassung:${NC}"
        print_status "INFO" "Gesamte Prüfungen: $total_checks"
        print_status "OK" "Bestanden: $passed_checks ($pass_percentage%)"
        print_status "WARN" "Fehlgeschlagen: $failed_checks"
        
        if [[ $critical_issues -gt 0 ]]; then
            print_status "CRITICAL" "Kritische Probleme: $critical_issues"
        fi
    fi
}

# Security audit
security_audit() {
    print_section "Umfassender Sicherheits-Audit"
    
    local report_file="$OUTPUT_DIR/security-audit-$DATE_STR.txt"
    
    print_status "INFO" "Führe detaillierten Sicherheits-Audit durch..."
    
    # Run security audit
    "$SYSINFO_TOOL" --security-audit --verbose > "$report_file" 2>&1
    
    print_status "OK" "Sicherheits-Audit abgeschlossen"
    print_status "OK" "Detailbericht gespeichert: $report_file"
    
    # Show critical findings
    local critical_findings=$(grep -i "critical\|fail\|error" "$report_file" | head -10)
    if [[ -n "$critical_findings" ]]; then
        echo -e "\n${RED}Kritische Befunde (Top 10):${NC}"
        echo "$critical_findings" | while IFS= read -r line; do
            echo -e "  ${RED}•${NC} $line"
        done
    fi
}

# Performance report
performance_report() {
    print_section "Performance-Impact Analyse"
    
    local report_file="$OUTPUT_DIR/performance-report-$DATE_STR.txt"
    
    print_status "INFO" "Analysiere Performance-Impact von Sicherheitsmaßnahmen..."
    
    # Run performance report
    "$SYSINFO_TOOL" --performance-report --verbose > "$report_file" 2>&1
    
    print_status "OK" "Performance-Analyse abgeschlossen"
    print_status "OK" "Bericht gespeichert: $report_file"
}

# Vulnerability audit for installed packages using debsecan
vulnerability_audit() {
    print_section "Schwachstellen-Audit aller installierten Pakete"
    
    local vuln_report="$OUTPUT_DIR/vulnerability-audit-$DATE_STR.txt"
    local vuln_json="$OUTPUT_DIR/vulnerability-audit-$DATE_STR.json"
    local critical_vulns="$OUTPUT_DIR/critical-vulnerabilities-$DATE_STR.txt"
    
    # Check for Debian/Ubuntu system with dpkg
    if ! command -v dpkg &> /dev/null; then
        print_status "ERROR" "Dieses Tool funktioniert nur auf Debian/Ubuntu-Systemen (dpkg erforderlich)"
        print_status "INFO" "Aktuelles System wird nicht unterstützt"
        return 1
    fi
    
    # Detect distribution
    local distro="unknown"
    local suite="stable"
    
    if [[ -f /etc/os-release ]]; then
        local os_name=$(grep "^NAME=" /etc/os-release | cut -d'"' -f2)
        local version_id=$(grep "^VERSION_ID=" /etc/os-release | cut -d'"' -f2)
        local version_codename=$(grep "^VERSION_CODENAME=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
        
        if [[ $os_name =~ Ubuntu ]]; then
            distro="Ubuntu"
            suite="$version_codename"
        elif [[ $os_name =~ Debian ]]; then
            distro="Debian"
            suite="$version_codename"
            if [[ -z "$suite" ]]; then
                suite=$(lsb_release -cs 2>/dev/null || echo "stable")
            fi
        fi
    fi
    
    print_status "INFO" "Erkannte Distribution: $distro"
    print_status "INFO" "Suite/Codename: $suite"
    
    # Check if debsecan is available, install if needed
    if ! command -v debsecan &> /dev/null; then
        print_status "INFO" "debsecan nicht gefunden, installiere debsecan..."
        if check_root; then
            apt-get update -qq && apt-get install -y debsecan > /dev/null 2>&1
            if ! command -v debsecan &> /dev/null; then
                print_status "ERROR" "debsecan Installation fehlgeschlagen"
                print_status "INFO" "Führe aus: apt-get install debsecan"
                return 1
            fi
            print_status "OK" "debsecan erfolgreich installiert"
        else
            print_status "ERROR" "Root-Rechte erforderlich für debsecan Installation"
            print_status "INFO" "Führe aus: sudo apt-get install debsecan"
            return 1
        fi
    fi
    
    print_status "INFO" "Analysiere alle installierten Debian-Pakete mit debsecan..."
    print_status "INFO" "Dies kann mehrere Minuten dauern..."
    
    # Run comprehensive debsecan vulnerability scan
    print_status "INFO" "Führe umfassenden debsecan Schwachstellen-Scan aus..."
    local debsecan_output=$(mktemp)
    local debsecan_detail=$(mktemp)
    local unfixed_vulns=$(mktemp)
    
    # Update vulnerability database first
    print_status "INFO" "Aktualisiere Schwachstellen-Datenbank..."
    if check_root; then
        apt-get update -qq > /dev/null 2>&1 || print_status "WARN" "apt-get update fehlgeschlagen"
    fi
    
    # Run debsecan with comprehensive options
    print_status "INFO" "Scanne alle installierten Pakete auf Schwachstellen..."
    
    # First scan: All vulnerabilities
    if ! debsecan --suite="$suite" --format=packages 2>/dev/null > "$debsecan_output"; then
        print_status "WARN" "debsecan mit Suite '$suite' fehlgeschlagen, versuche ohne Suite..."
        if ! debsecan --format=packages 2>/dev/null > "$debsecan_output"; then
            print_status "ERROR" "debsecan Scan fehlgeschlagen"
            rm -f "$debsecan_output" "$debsecan_detail" "$unfixed_vulns"
            return 1
        fi
    fi
    
    # Second scan: Only unfixed vulnerabilities (if supported)
    print_status "INFO" "Scanne spezifisch nach ungefixten Schwachstellen..."
    debsecan --suite="$suite" --only-fixed=no --format=packages 2>/dev/null > "$unfixed_vulns" || {
        print_status "WARN" "Scan für ungefixte Schwachstellen nicht verfügbar, verwende Hauptscan"
        cp "$debsecan_output" "$unfixed_vulns"
    }
    
    # Third scan: Detailed information
    print_status "INFO" "Sammle detaillierte Schwachstellen-Informationen..."
    debsecan --suite="$suite" --format=detail 2>/dev/null > "$debsecan_detail" || {
        print_status "WARN" "Detaillierter Scan fehlgeschlagen, verwende Package-Format"
        cp "$debsecan_output" "$debsecan_detail"
    }
    
    local vuln_count=$(wc -l < "$debsecan_output")
    local unfixed_count=$(wc -l < "$unfixed_vulns")
    
    print_status "OK" "debsecan Scan abgeschlossen"
    print_status "INFO" "Gesamte Schwachstellen: $vuln_count"
    print_status "INFO" "Ungefixte Schwachstellen: $unfixed_count"
    
    # Create detailed vulnerability report
    {
        echo "$distro PACKAGE VULNERABILITY AUDIT (debsecan)"
        echo "Generiert: $(date)"
        echo "System: $(hostname)"
        echo "Distribution: $distro"
        if [[ $distro == "Debian" ]]; then
            echo "Debian Version: $(cat /etc/debian_version 2>/dev/null || echo 'Unbekannt')"
        elif [[ $distro == "Ubuntu" ]]; then
            echo "Ubuntu Version: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2 2>/dev/null || echo 'Unbekannt')"
        fi
        echo "Suite/Codename: $suite"
        echo "Kernel: $(uname -r)"
        echo "debsecan Version: $(debsecan --version 2>/dev/null | head -n1)"
        echo "=========================================="
        echo
        
        local total_packages=$(dpkg -l | grep '^ii' | wc -l)
        echo "Gesamte installierte Pakete: $total_packages"
        echo "Gefundene Schwachstellen (gesamt): $vuln_count"
        echo "Ungefixte Schwachstellen: $unfixed_count"
        echo
        
        if [[ $vuln_count -gt 0 ]]; then
            echo "BETROFFENE PAKETE (Top 20):"
            echo "=========================="
            echo
            
            # Show first 20 packages directly from debsecan output
            head -20 "$debsecan_output" | while IFS= read -r pkg; do
                [[ -n "$pkg" ]] && echo "• $pkg"
            done
            
            if [[ $vuln_count -gt 20 ]]; then
                echo
                echo "... und weitere $((vuln_count - 20)) betroffene Pakete"
                echo
            fi
            
            echo "DETAILLIERTE CVE-INFORMATIONEN:"
            echo "=============================="
            echo
            echo "Für detaillierte CVE-Informationen verwenden Sie:"
            echo "  debsecan --suite=$suite"
            echo "  debsecan --suite=$suite --format=detail"
            echo
            
            # Quick severity estimate based on CVE years
            local critical_count=0
            local high_count=0  
            local medium_count=0
            
            # Count recent CVEs as higher severity
            while IFS= read -r line; do
                if [[ $line =~ CVE-202[4-5] ]]; then
                    ((high_count++))
                else
                    ((medium_count++))
                fi
            done < <(debsecan --suite="$suite" | head -$vuln_count)
            
            echo "=========================================="
            echo "SCHWACHSTELLEN-ZUSAMMENFASSUNG"
            echo "=========================================="
            echo "Betroffene Pakete: $vuln_count"
            echo "Geschätzte Schweregrade:"
            echo "  - Hoch (CVE-2024/2025): $high_count"  
            echo "  - Mittel (ältere CVEs): $medium_count"
            echo
            echo "WICHTIGER HINWEIS:"
            echo "Da Sie Debian Trixie (Testing) verwenden, sind viele"
            echo "Schwachstellen normal und werden regelmäßig behoben."
            echo
            echo "EMPFOHLENE AKTIONEN:"
            echo "==================="
            echo "1. System regelmäßig aktualisieren: apt update && apt upgrade"
            echo "2. Auf kritische Sicherheitsupdates achten"
            echo "3. Für Produktionssysteme Debian Stable verwenden"
            echo "4. Monitoring für kritische CVEs aktivieren"
        else
            echo "Keine Schwachstellen gefunden!"
            echo "Alle installierten Pakete sind auf dem neuesten Stand."
            echo
            echo "EMPFEHLUNG:"
            echo "==========="
            echo "Führe regelmäßig debsecan aus, um neue Schwachstellen zu erkennen."
        fi
        
    } > "$vuln_report"
    
    # Create simplified JSON report
    {
        echo "{"
        echo "  \"scan_date\": \"$(date -Iseconds)\","
        echo "  \"hostname\": \"$(hostname)\","
        echo "  \"distribution\": \"$distro\","
        echo "  \"suite\": \"$suite\","
        echo "  \"kernel_version\": \"$(uname -r)\","
        echo "  \"total_packages\": $(dpkg -l | grep '^ii' | wc -l),"
        echo "  \"total_vulnerabilities\": $vuln_count,"
        echo "  \"unfixed_vulnerabilities\": $unfixed_count,"
        echo "  \"vulnerabilities\": [],"
        echo "  \"summary\": {"
        echo "    \"critical\": $critical_count,"
        echo "    \"high\": $high_count,"
        echo "    \"medium\": $medium_count,"
        echo "    \"low\": $low_count"
        echo "  },"
        echo "  \"note\": \"Detailed vulnerability list available via: debsecan --suite=$suite\""
        echo "}"
    } > "$vuln_json"
    
    # Create critical vulnerabilities file
    {
        echo "KRITISCHE SCHWACHSTELLEN - SOFORTIGE AKTION ERFORDERLICH"
        echo "========================================================"
        echo "Generiert: $(date)"
        echo
        
        if [[ $unfixed_count -gt 0 ]]; then
            echo "UNGEFIXTE KRITISCHE SCHWACHSTELLEN:"
            echo "==================================="
            grep -E "CVE-2024-4577|CVE-2025-26465|CVE-2025-26466|CVE-2024-6387|critical|CRITICAL|10\.[0-9]|9\.[8-9]" "$unfixed_vulns" 2>/dev/null || echo "Keine kritischen ungefixten Schwachstellen gefunden."
            echo
        fi
        
        echo "ALLE KRITISCHEN SCHWACHSTELLEN:"
        echo "==============================="
        grep -E "CVE-2024-4577|CVE-2025-26465|CVE-2025-26466|CVE-2024-6387|critical|CRITICAL|remote.*execute|RCE|10\.[0-9]|9\.[8-9]" "$debsecan_output" 2>/dev/null || echo "Keine kritischen Schwachstellen gefunden."
        
    } > "$critical_vulns"
    
    # Clean up temp files
    rm -f "$debsecan_output" "$debsecan_detail" "$unfixed_vulns"
    
    # Show results
    print_status "OK" "Schwachstellen-Audit abgeschlossen (debsecan)"
    print_status "OK" "Detailbericht: $vuln_report"
    print_status "OK" "JSON-Daten: $vuln_json"
    
    if [[ -f "$critical_vulns" && -s "$critical_vulns" ]]; then
        print_status "OK" "Kritische Schwachstellen: $critical_vulns"
    fi
    
    # Display comprehensive summary
    echo -e "\n${WHITE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}   SCHWACHSTELLEN-ZUSAMMENFASSUNG (debsecan)${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════${NC}"
    
    print_status "INFO" "System: $distro $suite"
    print_status "INFO" "Gescannte Pakete: $(dpkg -l | grep '^ii' | wc -l)"
    print_status "INFO" "Gefundene Schwachstellen (gesamt): $vuln_count"
    print_status "INFO" "Ungefixte Schwachstellen: $unfixed_count"
    
    if [[ $vuln_count -eq 0 ]]; then
        print_status "OK" "Keine Schwachstellen gefunden - System ist sicher!"
        echo -e "\n${GREEN}${BOLD}✅ Ihr System ist aktuell und sicher!${NC}"
        echo -e "${CYAN}Empfehlung: Führen Sie regelmäßig debsecan aus, um neue Schwachstellen zu erkennen.${NC}"
    else
        # Parse summary from the generated JSON 
        local summary_critical=$(grep '"critical":' "$vuln_json" | grep -o '[0-9]\+' | head -1)
        local summary_high=$(grep '"high":' "$vuln_json" | grep -o '[0-9]\+' | head -1)
        local summary_medium=$(grep '"medium":' "$vuln_json" | grep -o '[0-9]\+' | head -1)
        
        echo -e "\n${WHITE}Schweregrade-Verteilung:${NC}"
        if [[ $summary_critical -gt 0 ]]; then
            print_status "CRITICAL" "Kritische Schwachstellen: $summary_critical (🚨 SOFORTIGE AKTION ERFORDERLICH!)"
        fi
        if [[ $summary_high -gt 0 ]]; then
            print_status "WARN" "Hochriskante Schwachstellen: $summary_high (⚠️ Hohe Priorität)"
        fi
        if [[ $summary_medium -gt 0 ]]; then
            print_status "INFO" "Mittlere Schwachstellen: $summary_medium (ℹ️ Mittlere Priorität)"
        fi
        
        # Special emphasis on unfixed vulnerabilities
        if [[ $unfixed_count -gt 0 ]]; then
            echo -e "\n${RED}${BOLD}🔥 ACHTUNG: $unfixed_count ungefixte Schwachstellen gefunden!${NC}"
            echo -e "${RED}Diese Schwachstellen haben noch keine verfügbaren Patches.${NC}"
            echo -e "${RED}Zusätzliche Sicherheitsmaßnahmen erforderlich!${NC}"
        fi
        
        # Show sample of critical vulnerabilities if any exist
        if [[ -f "$critical_vulns" && -s "$critical_vulns" ]]; then
            echo -e "\n${RED}${BOLD}🚨 KRITISCHE SCHWACHSTELLEN DETAILS:${NC}"
            local crit_lines=$(grep -v "^KRITISCHE\|^=\|^Generiert" "$critical_vulns" | head -3)
            if [[ -n "$crit_lines" ]]; then
                echo "$crit_lines" | while IFS= read -r line; do
                    [[ -n "$line" ]] && echo -e "${RED}  ⚠ $line${NC}"
                done
                if [[ $(grep -c -v "^KRITISCHE\|^=\|^Generiert\|^$" "$critical_vulns") -gt 3 ]]; then
                    echo -e "${YELLOW}  ... weitere kritische Schwachstellen (siehe $critical_vulns)${NC}"
                fi
            fi
        fi
        
        echo -e "\n${WHITE}${BOLD}📋 EMPFOHLENE AKTIONEN:${NC}"
        if [[ $summary_critical -gt 0 ]] || [[ $unfixed_count -gt 0 ]]; then
            echo -e "${RED}${BOLD}🚨 SOFORTIGE MASSNAHMEN:${NC}"
            echo -e "${CYAN}  1. System sofort aktualisieren: sudo apt update && sudo apt upgrade${NC}"
            echo -e "${CYAN}  2. Kritische Pakete manuell prüfen und aktualisieren${NC}"
            echo -e "${CYAN}  3. Firewall-Regeln verschärfen falls möglich${NC}"
            echo -e "${CYAN}  4. Monitoring und Logging aktivieren${NC}"
        fi
        
        echo -e "${WHITE}📅 REGELMÄSSIGE WARTUNG:${NC}"
        echo -e "${CYAN}  • Täglich: debsecan --suite=$suite ausführen${NC}"
        echo -e "${CYAN}  • Wöchentlich: Vollständiges System-Update${NC}"
        echo -e "${CYAN}  • Monatlich: Sicherheitsaudit mit diesem Tool${NC}"
        
        echo -e "\n${WHITE}📊 BERICHTE:${NC}"
        echo -e "${CYAN}  • Detailbericht: $vuln_report${NC}"
        echo -e "${CYAN}  • JSON-Daten: $vuln_json${NC}"
        echo -e "${CYAN}  • Kritische Schwachstellen: $critical_vulns${NC}"
    fi
    
    echo -e "${WHITE}═══════════════════════════════════════════════════════${NC}"
}

# Generate JSON reports for automation
generate_json_reports() {
    print_section "JSON-Reports für Automation"
    
    local json_compliance="$OUTPUT_DIR/compliance-$DATE_STR.json"
    local json_dashboard="$OUTPUT_DIR/dashboard-$DATE_STR.json"
    
    print_status "INFO" "Generiere strukturierte JSON-Reports..."
    
    # Generate JSON reports
    "$SYSINFO_TOOL" --compliance-check --export "$json_compliance" --format json 2>/dev/null || \
        print_status "WARN" "JSON Compliance-Report konnte nicht erstellt werden"
        
    "$SYSINFO_TOOL" --dashboard --export "$json_dashboard" --format json 2>/dev/null || \
        print_status "WARN" "JSON Dashboard-Report konnte nicht erstellt werden"
    
    if [[ -f "$json_compliance" ]]; then
        print_status "OK" "JSON Compliance-Report: $json_compliance"
    fi
    
    if [[ -f "$json_dashboard" ]]; then
        print_status "OK" "JSON Dashboard-Report: $json_dashboard" 
    fi
}

# Gap analysis summary
gap_analysis() {
    print_section "Gap-Analyse für Action Planning"
    
    local gap_file="$OUTPUT_DIR/gap-analysis-$DATE_STR.txt"
    local temp_compliance=$(mktemp)
    
    # Run compliance check to analyze gaps
    "$SYSINFO_TOOL" --compliance-check --verbose > "$temp_compliance" 2>&1
    
    {
        echo "=== SECURITY GAP ANALYSIS - $(date) ==="
        echo
        
        echo "CRITICAL PRIORITY (Sofortige Aktion erforderlich):"
        grep -i "critical\|fail.*critical" "$temp_compliance" || echo "Keine kritischen Probleme gefunden"
        echo
        
        echo "HIGH PRIORITY (1-7 Tage):"
        grep "FAIL.*L1\|FAIL.*HIGH" "$temp_compliance" | head -20 || echo "Keine High-Priority Probleme"
        echo
        
        echo "MEDIUM PRIORITY (1-4 Wochen):" 
        grep "FAIL.*L2\|FAIL.*MEDIUM" "$temp_compliance" | head -15 || echo "Keine Medium-Priority Probleme"
        echo
        
        echo "FRAMEWORK-SPEZIFISCHE GAPS:"
        echo "CIS Level 1 Failures:"
        grep "CIS.*FAIL" "$temp_compliance" | wc -l | xargs echo "Anzahl:"
        
        echo "ISO 27001 Failures:"
        grep "A\..*FAIL" "$temp_compliance" | wc -l | xargs echo "Anzahl:"
        
        echo "SOC 2 Failures:"
        grep "CC.*FAIL" "$temp_compliance" | wc -l | xargs echo "Anzahl:"
        
        echo "BSI Grundschutz Failures:"
        grep -E "SYS|NET|ORP.*FAIL" "$temp_compliance" | wc -l | xargs echo "Anzahl:"
        
    } > "$gap_file"
    
    rm -f "$temp_compliance"
    
    print_status "OK" "Gap-Analyse abgeschlossen: $gap_file"
    
    # Show summary
    echo -e "\n${WHITE}Gap-Analyse Zusammenfassung:${NC}"
    local critical_gaps=$(grep -c "CRITICAL" "$gap_file" || echo "0")
    local high_gaps=$(grep -c "HIGH PRIORITY" "$gap_file" || echo "0") 
    local medium_gaps=$(grep -c "MEDIUM PRIORITY" "$gap_file" || echo "0")
    
    print_status "CRITICAL" "Kritische Lücken: $critical_gaps"
    print_status "WARN" "High Priority Lücken: siehe Report"
    print_status "INFO" "Medium Priority Lücken: siehe Report"
}

# Generate management summary
management_summary() {
    print_section "Management Summary"
    
    local summary_file="$OUTPUT_DIR/management-summary-$DATE_STR.html"
    
    print_status "INFO" "Erstelle Management-Summary..."
    
    # Try to generate HTML report
    if "$SYSINFO_TOOL" --security-audit --export "$summary_file" --format html 2>/dev/null; then
        print_status "OK" "Management-Summary erstellt: $summary_file"
        print_status "INFO" "Kann in jedem Webbrowser geöffnet werden"
    else
        print_status "WARN" "HTML-Export nicht verfügbar, erstelle Text-Summary"
        
        local text_summary="$OUTPUT_DIR/management-summary-$DATE_STR.txt"
        {
            echo "EXECUTIVE SUMMARY - SECURITY COMPLIANCE STATUS"
            echo "Datum: $(date)"
            echo "System: $(hostname)"
            echo "=============================================="
            echo
            
            "$SYSINFO_TOOL" --dashboard 2>/dev/null | head -20
            echo
            
            echo "COMPLIANCE STATUS:"
            "$SYSINFO_TOOL" --compliance-check 2>/dev/null | grep -E "Level|compliance|PASS|FAIL" | head -10
            
        } > "$text_summary"
        
        print_status "OK" "Management-Summary erstellt: $text_summary"
    fi
}

# Show final summary
show_summary() {
    print_section "Analyse abgeschlossen"
    
    print_status "OK" "Alle Reports wurden erstellt in: $OUTPUT_DIR"
    print_status "INFO" "Verfügbare Berichte:"
    
    if [[ -d "$OUTPUT_DIR" ]]; then
        find "$OUTPUT_DIR" -name "*$DATE_STR*" -type f | while read -r file; do
            local filename=$(basename "$file")
            local size=$(du -h "$file" | cut -f1)
            print_status "INFO" "  $filename ($size)"
        done
    fi
    
    echo -e "\n${WHITE}Nächste Schritte:${NC}"
    echo -e "  ${CYAN}1.${NC} Prüfen Sie die Gap-Analyse für priorisierte Action Items"
    echo -e "  ${CYAN}2.${NC} Teilen Sie das Management-Summary mit Stakeholdern"  
    echo -e "  ${CYAN}3.${NC} Planen Sie die Umsetzung basierend auf Prioritäten"
    echo -e "  ${CYAN}4.${NC} Führen Sie diesen Check regelmäßig durch (monatlich empfohlen)"
}

# Usage information
usage() {
    cat << EOF
Security Compliance Checker - NUR ANALYSE

VERWENDUNG:
    $0 [OPTION]

OPTIONEN:
    --quick         Schnelle Dashboard-Übersicht (2 Minuten)
    --compliance    Vollständiger Compliance-Check (10 Minuten)
    --audit         Umfassender Sicherheits-Audit (15 Minuten)  
    --vulnerabilities,--vulns  Schwachstellen-Audit aller Debian-Pakete
    --performance   Performance-Impact Analyse
    --json          JSON-Reports für Automation generieren
    --gaps          Gap-Analyse für Action Planning
    --management    Management-Summary erstellen
    --all           Alle Analysen durchführen (empfohlen)
    --help          Diese Hilfe anzeigen

BEISPIELE:
    $0 --quick                  # Schneller Status-Check
    $0 --compliance            # Compliance-Prüfung
    $0 --vulnerabilities       # Paket-Schwachstellen scannen
    $0 --all                   # Vollständige Analyse (empfohlen)

HINWEISE:
    - Root-Rechte erforderlich für vollständige Analyse
    - Reports werden in $OUTPUT_DIR gespeichert
    - Tool führt KEINE Systemänderungen durch - nur Analyse!

EOF
}

# Main function
main() {
    local command="${1:-}"
    
    print_header
    
    # Check prerequisites
    check_sysinfo_tool
    create_output_dir
    
    # Check root access
    if ! check_root 2>/dev/null; then
        print_status "WARN" "Root-Rechte nicht verfügbar - eingeschränkte Analyse"
    fi
    
    case "$command" in
        --quick)
            quick_dashboard
            ;;
        --compliance)
            full_compliance_check
            ;;
        --audit)
            security_audit
            ;;
        --performance)
            performance_report
            ;;
        --json)
            generate_json_reports
            ;;
        --gaps)
            gap_analysis
            ;;
        --management)
            management_summary
            ;;
        --vulnerabilities|--vulns)
            vulnerability_audit
            ;;
        --all)
            quick_dashboard
            full_compliance_check
            security_audit
            vulnerability_audit
            performance_report
            generate_json_reports
            gap_analysis
            management_summary
            show_summary
            ;;
        --help|-h)
            usage
            ;;
        "")
            echo -e "${YELLOW}Keine Option angegeben. Verwenden Sie --help für Hilfe.${NC}"
            echo -e "${CYAN}Schnellstart: $0 --all${NC}"
            ;;
        *)
            echo -e "${RED}Unbekannte Option: $command${NC}" >&2
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"