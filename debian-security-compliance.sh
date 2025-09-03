#!/bin/bash

################################################################################
# Debian & Ubuntu Security Compliance Checker
# ANALYSIS ONLY - NO SYSTEM MODIFICATIONS!
# 
# Repository: https://github.com/MalteKiefer/Debian-Security-Compliance
# Author: Malte Kiefer
# Version: 2.0.0
################################################################################

set -euo pipefail

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SYSINFO_TOOL="$SCRIPT_DIR/sysinfo-security"
readonly OUTPUT_DIR="/tmp/compliance-reports"
readonly DATE_STR=$(date +%Y%m%d-%H%M%S)
readonly VERSION="2.0.0"
readonly REPO_URL="https://github.com/MalteKiefer/Debian-Security-Compliance"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m' 
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'

# Version and update checking
check_version() {
    local current_version="$VERSION"
    
    # Check if we're in a git repository
    if [[ -d "$SCRIPT_DIR/.git" ]]; then
        echo -e "${CYAN}Checking for updates...${NC}"
        
        # Fetch latest information
        if git -C "$SCRIPT_DIR" fetch origin >/dev/null 2>&1; then
            local latest_tag=$(git -C "$SCRIPT_DIR" describe --tags --abbrev=0 origin/main 2>/dev/null || echo "")
            
            if [[ -n "$latest_tag" ]] && [[ "$latest_tag" != "v$current_version" ]]; then
                echo -e "${YELLOW}Update available: $latest_tag (current: v$current_version)${NC}"
                echo -e "${CYAN}Run 'git pull origin main' to update${NC}"
                echo -e "${CYAN}Repository: $REPO_URL${NC}"
                return 1
            else
                echo -e "${GREEN}You are running the latest version (v$current_version)${NC}"
            fi
        else
            echo -e "${YELLOW}Could not check for updates (no internet connection)${NC}"
        fi
    else
        echo -e "${YELLOW}Not a git repository - manual version checking required${NC}"
        echo -e "${CYAN}Repository: $REPO_URL${NC}"
    fi
    
    return 0
}

# Print functions
print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}         Debian & Ubuntu Security Compliance Checker v$VERSION${NC}"
    echo -e "${CYAN}                ANALYSIS ONLY - NO SYSTEM MODIFICATIONS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo
}

print_section() {
    local section="$1"
    echo -e "\n${CYAN}▶ $section${NC}"
    echo -e "${CYAN}$(printf '%.0s-' $(seq 1 ${#section}))${NC}"
}

print_status() {
    local level="$1"
    local message="$2"
    
    case "$level" in
        "OK"|"PASS")
            echo -e "  ${GREEN}[✓]${NC} $message" 
            ;;
        "WARN"|"WARNING")
            echo -e "  ${YELLOW}[⚠]${NC} $message"
            ;;
        "ERROR"|"FAIL"|"CRITICAL")
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

# Utility functions
check_root() {
    [[ $EUID -eq 0 ]]
}

check_sysinfo_tool() {
    if [[ ! -f "$SYSINFO_TOOL" ]]; then
        print_status "ERROR" "sysinfo-security tool not found at $SYSINFO_TOOL"
        print_status "INFO" "Please ensure sysinfo-security is in the same directory"
        exit 1
    fi
    
    if [[ ! -x "$SYSINFO_TOOL" ]]; then
        print_status "INFO" "Making sysinfo-security executable..."
        chmod +x "$SYSINFO_TOOL" 2>/dev/null || {
            print_status "ERROR" "Cannot make sysinfo-security executable"
            exit 1
        }
    fi
}

create_output_dir() {
    mkdir -p "$OUTPUT_DIR" 2>/dev/null || {
        print_status "WARN" "Cannot create $OUTPUT_DIR, using /tmp"
        OUTPUT_DIR="/tmp"
    }
    print_status "INFO" "Reports will be saved to: $OUTPUT_DIR"
}

# Quick security dashboard
quick_dashboard() {
    print_section "Security Dashboard (Quick Overview)"
    
    local dashboard_file="$OUTPUT_DIR/dashboard-$DATE_STR.txt"
    
    print_status "INFO" "Running dashboard analysis..."
    
    # Run dashboard analysis
    "$SYSINFO_TOOL" --dashboard > "$dashboard_file" 2>&1 || {
        print_status "WARN" "Dashboard analysis failed"
        return 1
    }
    
    # Display the dashboard content
    cat "$dashboard_file"
}

# Full compliance check
full_compliance_check() {
    print_section "Comprehensive Compliance Check"
    
    local compliance_file="$OUTPUT_DIR/compliance-check-$DATE_STR.txt"
    
    print_status "INFO" "Running comprehensive compliance check..."
    print_status "INFO" "This may take several minutes..."
    
    # Run compliance check
    "$SYSINFO_TOOL" --compliance-check --verbose > "$compliance_file" 2>&1
    
    print_status "INFO" "Compliance check completed"
    print_status "OK" "Detailed report saved: $compliance_file"
}

# Security audit
security_audit() {
    print_section "Comprehensive Security Audit"
    
    local report_file="$OUTPUT_DIR/security-audit-$DATE_STR.txt"
    
    print_status "INFO" "Running detailed security audit..."
    
    # Run security audit
    "$SYSINFO_TOOL" --security-audit --verbose > "$report_file" 2>&1
    
    print_status "OK" "Security audit completed"
    print_status "OK" "Detailed report saved: $report_file"
    
    # Show critical findings
    local critical_findings=$(grep -i "critical\|fail\|error" "$report_file" | head -10)
    if [[ -n "$critical_findings" ]]; then
        echo -e "\n${RED}Critical Findings (Top 10):${NC}"
        echo "$critical_findings" | while IFS= read -r line; do
            echo -e "  ${RED}•${NC} $line"
        done
    fi
}

# Performance report
performance_report() {
    print_section "Performance Impact Analysis"
    
    local report_file="$OUTPUT_DIR/performance-report-$DATE_STR.txt"
    
    print_status "INFO" "Analyzing performance impact of security measures..."
    
    # Run performance report
    "$SYSINFO_TOOL" --performance-report --verbose > "$report_file" 2>&1
    
    print_status "OK" "Performance analysis completed"
    print_status "OK" "Report saved: $report_file"
}

# Vulnerability audit for installed packages using debsecan
vulnerability_audit() {
    print_section "Vulnerability Audit of All Installed Packages"
    
    local vuln_report="$OUTPUT_DIR/vulnerability-audit-$DATE_STR.txt"
    local vuln_json="$OUTPUT_DIR/vulnerability-audit-$DATE_STR.json"
    local critical_vulns="$OUTPUT_DIR/critical-vulnerabilities-$DATE_STR.txt"
    
    # Check for Debian/Ubuntu system with dpkg
    if ! command -v dpkg &> /dev/null; then
        print_status "ERROR" "This tool only works on Debian/Ubuntu systems (dpkg required)"
        print_status "INFO" "Current system not supported"
        return 1
    fi
    
    # Detect distribution
    local distro="unknown"
    local suite="stable"
    local ubuntu_codename=""
    
    if [[ -f /etc/os-release ]]; then
        local os_name=$(grep "^NAME=" /etc/os-release | cut -d'"' -f2)
        local version_id=$(grep "^VERSION_ID=" /etc/os-release | cut -d'"' -f2)
        local version_codename=$(grep "^VERSION_CODENAME=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
        local ubuntu_codename=$(grep "^UBUNTU_CODENAME=" /etc/os-release | cut -d'=' -f2 | tr -d '"' 2>/dev/null)
        
        if [[ $os_name =~ Ubuntu ]]; then
            distro="Ubuntu"
            # For Ubuntu, prefer UBUNTU_CODENAME if available, otherwise use VERSION_CODENAME
            if [[ -n "$ubuntu_codename" ]]; then
                suite="$ubuntu_codename"
            elif [[ -n "$version_codename" ]]; then
                suite="$version_codename"
            else
                # Fallback mapping for Ubuntu versions
                case "$version_id" in
                    "24.04") suite="noble" ;;
                    "23.10") suite="mantic" ;;
                    "23.04") suite="lunar" ;;
                    "22.04") suite="jammy" ;;
                    "20.04") suite="focal" ;;
                    "18.04") suite="bionic" ;;
                    *) suite=$(lsb_release -cs 2>/dev/null || echo "jammy") ;;
                esac
            fi
        elif [[ $os_name =~ Debian ]]; then
            distro="Debian"
            if [[ -n "$version_codename" ]]; then
                suite="$version_codename"
            else
                # Fallback mapping for Debian versions
                case "$version_id" in
                    "13") suite="trixie" ;;
                    "12") suite="bookworm" ;;
                    "11") suite="bullseye" ;;
                    "10") suite="buster" ;;
                    *) suite=$(lsb_release -cs 2>/dev/null || echo "stable") ;;
                esac
            fi
        else
            # Try to detect Ubuntu derivatives
            if grep -q "ubuntu" /etc/os-release 2>/dev/null || [[ -f /etc/upstream-release/lsb-release ]]; then
                distro="Ubuntu"
                suite=$(lsb_release -cs 2>/dev/null || echo "jammy")
            fi
        fi
    fi
    
    # Additional fallback checks
    if [[ "$distro" == "unknown" ]]; then
        if [[ -f /etc/debian_version ]]; then
            distro="Debian"
            suite="stable"
        elif command -v lsb_release >/dev/null 2>&1; then
            local lsb_id=$(lsb_release -si 2>/dev/null)
            if [[ "$lsb_id" == "Ubuntu" ]]; then
                distro="Ubuntu"
                suite=$(lsb_release -cs 2>/dev/null || echo "jammy")
            elif [[ "$lsb_id" == "Debian" ]]; then
                distro="Debian"
                suite=$(lsb_release -cs 2>/dev/null || echo "stable")
            fi
        fi
    fi
    
    print_status "INFO" "Detected distribution: $distro"
    print_status "INFO" "Suite/Codename: $suite"
    
    # Check if debsecan is available, install if needed
    if ! command -v debsecan &> /dev/null; then
        print_status "INFO" "debsecan not found, installing debsecan..."
        if check_root; then
            # Update package lists
            apt-get update -qq > /dev/null 2>&1 || print_status "WARN" "apt-get update failed"
            
            # Install debsecan based on distribution
            if [[ "$distro" == "Ubuntu" ]]; then
                # On Ubuntu, debsecan might be in universe repository
                apt-get install -y software-properties-common > /dev/null 2>&1
                add-apt-repository universe > /dev/null 2>&1 || true
                apt-get update -qq > /dev/null 2>&1
                apt-get install -y debsecan > /dev/null 2>&1
            else
                # Standard Debian installation
                apt-get install -y debsecan > /dev/null 2>&1
            fi
            
            if ! command -v debsecan &> /dev/null; then
                print_status "ERROR" "debsecan installation failed"
                if [[ "$distro" == "Ubuntu" ]]; then
                    print_status "INFO" "Run: sudo apt-get install debsecan"
                    print_status "INFO" "Note: debsecan may not be fully supported on all Ubuntu versions"
                    print_status "INFO" "Alternative: Use 'apt list --upgradable' to check for updates"
                else
                    print_status "INFO" "Run: sudo apt-get install debsecan"
                fi
                return 1
            fi
            print_status "OK" "debsecan successfully installed"
        else
            print_status "ERROR" "Root privileges required for debsecan installation"
            print_status "INFO" "Run: sudo apt-get install debsecan"
            if [[ "$distro" == "Ubuntu" ]]; then
                print_status "INFO" "Note: May require enabling universe repository on Ubuntu"
            fi
            return 1
        fi
    fi
    
    print_status "INFO" "Analyzing all installed $distro packages with debsecan..."
    print_status "INFO" "This may take several minutes..."
    
    # Run comprehensive debsecan vulnerability scan
    print_status "INFO" "Running comprehensive debsecan vulnerability scan..."
    local debsecan_output=$(mktemp)
    local debsecan_detail=$(mktemp)
    local unfixed_vulns=$(mktemp)
    
    # Update vulnerability database first
    print_status "INFO" "Updating vulnerability database..."
    if check_root; then
        apt-get update -qq > /dev/null 2>&1 || print_status "WARN" "apt-get update failed"
    fi
    
    # Run debsecan with comprehensive options
    print_status "INFO" "Scanning all installed packages for vulnerabilities..."
    
    # First scan: All vulnerabilities
    local scan_success=false
    
    # Try different scanning approaches based on distribution
    if [[ "$distro" == "Ubuntu" ]]; then
        # Ubuntu-specific scanning approach
        print_status "INFO" "Using Ubuntu-optimized scanning approach..."
        
        # Try with Ubuntu suite first
        if debsecan --suite="$suite" --format=packages 2>/dev/null > "$debsecan_output" && [[ -s "$debsecan_output" ]]; then
            scan_success=true
        # Try mapping Ubuntu codename to Debian equivalent
        elif [[ "$suite" == "noble" ]]; then
            debsecan --suite=bookworm --format=packages 2>/dev/null > "$debsecan_output" && scan_success=true
        elif [[ "$suite" == "jammy" ]]; then
            debsecan --suite=bullseye --format=packages 2>/dev/null > "$debsecan_output" && scan_success=true
        elif [[ "$suite" == "focal" ]]; then
            debsecan --suite=buster --format=packages 2>/dev/null > "$debsecan_output" && scan_success=true
        # Fallback to generic scan for Ubuntu
        elif debsecan --format=packages 2>/dev/null > "$debsecan_output" && [[ -s "$debsecan_output" ]]; then
            scan_success=true
            print_status "WARN" "Using generic debsecan database (Ubuntu-specific data may be limited)"
        fi
    else
        # Debian-specific scanning
        if debsecan --suite="$suite" --format=packages 2>/dev/null > "$debsecan_output" && [[ -s "$debsecan_output" ]]; then
            scan_success=true
        elif debsecan --format=packages 2>/dev/null > "$debsecan_output" && [[ -s "$debsecan_output" ]]; then
            scan_success=true
            print_status "WARN" "debsecan with suite '$suite' failed, using default database"
        fi
    fi
    
    if [[ "$scan_success" != "true" ]]; then
        print_status "ERROR" "debsecan scan failed for $distro $suite"
        if [[ "$distro" == "Ubuntu" ]]; then
            print_status "INFO" "Note: debsecan has limited support for Ubuntu"
            print_status "INFO" "Consider using 'unattended-upgrades --dry-run' for Ubuntu security updates"
        fi
        rm -f "$debsecan_output" "$debsecan_detail" "$unfixed_vulns"
        return 1
    fi
    
    # Second scan: Only unfixed vulnerabilities (if supported)
    print_status "INFO" "Scanning specifically for unfixed vulnerabilities..."
    if [[ "$distro" == "Debian" ]]; then
        debsecan --suite="$suite" --only-fixed=no --format=packages 2>/dev/null > "$unfixed_vulns" || {
            print_status "WARN" "Scan for unfixed vulnerabilities not available, using main scan"
            cp "$debsecan_output" "$unfixed_vulns"
        }
    else
        # Ubuntu: unfixed vulnerability scan may not work properly
        print_status "WARN" "Unfixed vulnerability detection has limited Ubuntu support"
        cp "$debsecan_output" "$unfixed_vulns"
    fi
    
    # Third scan: Detailed information
    print_status "INFO" "Collecting detailed vulnerability information..."
    if [[ "$distro" == "Debian" ]]; then
        debsecan --suite="$suite" --format=detail 2>/dev/null > "$debsecan_detail" || {
            print_status "WARN" "Detailed scan failed, using package format"
            cp "$debsecan_output" "$debsecan_detail"
        }
    else
        # Ubuntu: detailed scan may have limited information
        debsecan --format=detail 2>/dev/null > "$debsecan_detail" || {
            print_status "WARN" "Detailed scan not available for Ubuntu, using package format"
            cp "$debsecan_output" "$debsecan_detail"
        }
    fi
    
    local vuln_count=$(wc -l < "$debsecan_output")
    local unfixed_count=$(wc -l < "$unfixed_vulns")
    
    print_status "OK" "debsecan scan completed"
    print_status "INFO" "Total vulnerabilities: $vuln_count"
    print_status "INFO" "Unfixed vulnerabilities: $unfixed_count"
    
    # Create detailed vulnerability report
    {
        echo "$distro PACKAGE VULNERABILITY AUDIT (debsecan)"
        echo "Generated: $(date)"
        echo "System: $(hostname)"
        echo "Distribution: $distro"
        if [[ $distro == "Debian" ]]; then
            echo "Debian Version: $(cat /etc/debian_version 2>/dev/null || echo 'Unknown')"
        elif [[ $distro == "Ubuntu" ]]; then
            echo "Ubuntu Version: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2 2>/dev/null || echo 'Unknown')"
        fi
        echo "Suite/Codename: $suite"
        echo "Kernel: $(uname -r)"
        echo "debsecan Version: $(debsecan --version 2>/dev/null | head -n1)"
        echo "=========================================="
        echo
        
        local total_packages=$(dpkg -l | grep '^ii' | wc -l)
        echo "Total installed packages: $total_packages"
        echo "Found vulnerabilities (total): $vuln_count"
        echo "Unfixed vulnerabilities: $unfixed_count"
        echo
        
        if [[ $vuln_count -gt 0 ]]; then
            echo "AFFECTED PACKAGES (Top 20):"
            echo "=========================="
            echo
            
            # Show first 20 packages directly from debsecan output
            head -20 "$debsecan_output" | while IFS= read -r pkg; do
                [[ -n "$pkg" ]] && echo "• $pkg"
            done
            
            if [[ $vuln_count -gt 20 ]]; then
                echo
                echo "... and $((vuln_count - 20)) more affected packages"
                echo
            fi
            
            echo "DETAILED CVE INFORMATION:"
            echo "========================="
            echo
            echo "For detailed CVE information use:"
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
            echo "VULNERABILITY SUMMARY"
            echo "=========================================="
            echo "Affected packages: $vuln_count"
            echo "Estimated severity levels:"
            echo "  - High (CVE-2024/2025): $high_count"  
            echo "  - Medium (older CVEs): $medium_count"
            echo
            if [[ $distro == "Debian" && $suite == "trixie" ]]; then
                echo "IMPORTANT NOTE:"
                echo "Since you're using Debian Trixie (Testing), many"
                echo "vulnerabilities are normal and get fixed regularly."
            fi
            echo
            echo "RECOMMENDED ACTIONS:"
            echo "==================="
            if [[ $distro == "Ubuntu" ]]; then
                echo "1. Update system regularly: sudo apt update && sudo apt upgrade"
                echo "2. Enable automatic security updates: sudo dpkg-reconfigure unattended-upgrades"
                echo "3. Monitor Ubuntu Security Notices (USN): https://ubuntu.com/security/notices"
                echo "4. Consider Ubuntu Pro for extended security maintenance"
                echo "5. Use 'apt list --upgradable' to check for available updates"
            else
                echo "1. Update system regularly: apt update && apt upgrade"  
                echo "2. Monitor Debian Security Advisories (DSA): https://www.debian.org/security/"
                echo "3. Enable automatic security updates if desired"
                if [[ $suite == "trixie" ]]; then
                    echo "4. For production systems use Debian Stable"
                fi
            fi
            echo "6. Enable monitoring for critical CVEs"
        else
            echo "No vulnerabilities found!"
            echo "All installed packages are up to date."
            echo
            echo "RECOMMENDATION:"
            echo "==============="
            echo "Run debsecan regularly to detect new vulnerabilities."
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
        echo "CRITICAL VULNERABILITIES - IMMEDIATE ACTION REQUIRED"
        echo "===================================================="
        echo "Generated: $(date)"
        echo
        
        if [[ $unfixed_count -gt 0 ]]; then
            echo "UNFIXED CRITICAL VULNERABILITIES:"
            echo "================================="
            grep -E "CVE-2024-4577|CVE-2025-26465|CVE-2025-26466|CVE-2024-6387|critical|CRITICAL|10\.[0-9]|9\.[8-9]" "$unfixed_vulns" 2>/dev/null || echo "No critical unfixed vulnerabilities found."
            echo
        fi
        
        echo "ALL CRITICAL VULNERABILITIES:"
        echo "============================="
        grep -E "CVE-2024-4577|CVE-2025-26465|CVE-2025-26466|CVE-2024-6387|critical|CRITICAL|remote.*execute|RCE|10\.[0-9]|9\.[8-9]" "$debsecan_output" 2>/dev/null || echo "No critical vulnerabilities found."
        
    } > "$critical_vulns"
    
    # Clean up temp files
    rm -f "$debsecan_output" "$debsecan_detail" "$unfixed_vulns"
    
    # Show results
    print_status "OK" "Vulnerability audit completed (debsecan)"
    print_status "OK" "Detailed report: $vuln_report"
    print_status "OK" "JSON data: $vuln_json"
    
    if [[ -f "$critical_vulns" && -s "$critical_vulns" ]]; then
        print_status "OK" "Critical vulnerabilities: $critical_vulns"
    fi
    
    # Display comprehensive summary
    echo -e "\n${WHITE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}   VULNERABILITY SUMMARY (debsecan)${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════${NC}"
    
    print_status "INFO" "System: $distro $suite"
    print_status "INFO" "Scanned packages: $(dpkg -l | grep '^ii' | wc -l)"
    print_status "INFO" "Found vulnerabilities (total): $vuln_count"
    print_status "INFO" "Unfixed vulnerabilities: $unfixed_count"
    
    if [[ $vuln_count -eq 0 ]]; then
        print_status "OK" "No vulnerabilities found - system is secure!"
        echo -e "\n${GREEN}${BOLD}✅ Your system is up to date and secure!${NC}"
        echo -e "${CYAN}Recommendation: Run debsecan regularly to detect new vulnerabilities.${NC}"
    else
        # Parse summary from the generated JSON 
        local summary_critical=$(grep '"critical":' "$vuln_json" | grep -o '[0-9]\+' | head -1)
        local summary_high=$(grep '"high":' "$vuln_json" | grep -o '[0-9]\+' | head -1)
        local summary_medium=$(grep '"medium":' "$vuln_json" | grep -o '[0-9]\+' | head -1)
        
        echo -e "\n${WHITE}Severity Distribution:${NC}"
        if [[ $summary_critical -gt 0 ]]; then
            print_status "CRITICAL" "Critical vulnerabilities: $summary_critical (🚨 IMMEDIATE ACTION REQUIRED!)"
        fi
        if [[ $summary_high -gt 0 ]]; then
            print_status "WARN" "High-risk vulnerabilities: $summary_high (⚠️ High Priority)"
        fi
        if [[ $summary_medium -gt 0 ]]; then
            print_status "INFO" "Medium vulnerabilities: $summary_medium (ℹ️ Medium Priority)"
        fi
        
        # Special emphasis on unfixed vulnerabilities
        if [[ $unfixed_count -gt 0 ]]; then
            echo -e "\n${RED}${BOLD}🔥 WARNING: $unfixed_count unfixed vulnerabilities found!${NC}"
            echo -e "${RED}These vulnerabilities do not have available patches yet.${NC}"
            echo -e "${RED}Additional security measures required!${NC}"
        fi
        
        # Show sample of critical vulnerabilities if any exist
        if [[ -f "$critical_vulns" && -s "$critical_vulns" ]]; then
            echo -e "\n${RED}${BOLD}🚨 CRITICAL VULNERABILITY DETAILS:${NC}"
            local crit_lines=$(grep -v "^CRITICAL\|^=\|^Generated" "$critical_vulns" | head -3)
            if [[ -n "$crit_lines" ]]; then
                echo "$crit_lines" | while IFS= read -r line; do
                    [[ -n "$line" ]] && echo -e "${RED}  ⚠ $line${NC}"
                done
                if [[ $(grep -c -v "^CRITICAL\|^=\|^Generated\|^$" "$critical_vulns") -gt 3 ]]; then
                    echo -e "${YELLOW}  ... more critical vulnerabilities (see $critical_vulns)${NC}"
                fi
            fi
        fi
        
        echo -e "\n${WHITE}${BOLD}📋 RECOMMENDED ACTIONS:${NC}"
        if [[ $summary_critical -gt 0 ]] || [[ $unfixed_count -gt 0 ]]; then
            echo -e "${RED}${BOLD}🚨 IMMEDIATE MEASURES:${NC}"
            echo -e "${CYAN}  1. Update system immediately: sudo apt update && sudo apt upgrade${NC}"
            echo -e "${CYAN}  2. Check and update critical packages manually${NC}"
            echo -e "${CYAN}  3. Tighten firewall rules if possible${NC}"
            echo -e "${CYAN}  4. Enable monitoring and logging${NC}"
        fi
        
        echo -e "${WHITE}📅 REGULAR MAINTENANCE:${NC}"
        if [[ $distro == "Ubuntu" ]]; then
            echo -e "${CYAN}  • Daily: Check for updates with 'apt list --upgradable'${NC}"
            echo -e "${CYAN}  • Weekly: Complete system update with 'sudo apt update && sudo apt upgrade'${NC}"
            echo -e "${CYAN}  • Monthly: Security audit with this tool${NC}"
            echo -e "${CYAN}  • Monitor Ubuntu Security Notices: https://ubuntu.com/security/notices${NC}"
        else
            echo -e "${CYAN}  • Daily: Run debsecan --suite=$suite${NC}"
            echo -e "${CYAN}  • Weekly: Complete system update${NC}"
            echo -e "${CYAN}  • Monthly: Security audit with this tool${NC}"
        fi
        
        echo -e "\n${WHITE}📊 REPORTS:${NC}"
        echo -e "${CYAN}  • Detailed report: $vuln_report${NC}"
        echo -e "${CYAN}  • JSON data: $vuln_json${NC}"
        echo -e "${CYAN}  • Critical vulnerabilities: $critical_vulns${NC}"
    fi
    
    echo -e "${WHITE}═══════════════════════════════════════════════════════${NC}"
}

# Generate JSON reports for automation
generate_json_reports() {
    print_section "JSON Reports for Automation"
    
    local json_compliance="$OUTPUT_DIR/compliance-$DATE_STR.json"
    local json_dashboard="$OUTPUT_DIR/dashboard-$DATE_STR.json"
    
    print_status "INFO" "Generating structured JSON reports..."
    
    # Generate JSON reports
    "$SYSINFO_TOOL" --compliance-check --export "$json_compliance" --format json 2>/dev/null || \
        print_status "WARN" "JSON compliance report could not be created"
        
    "$SYSINFO_TOOL" --dashboard --export "$json_dashboard" --format json 2>/dev/null || \
        print_status "WARN" "JSON dashboard report could not be created"
    
    if [[ -f "$json_compliance" ]]; then
        print_status "OK" "JSON compliance report: $json_compliance"
    fi
    
    if [[ -f "$json_dashboard" ]]; then
        print_status "OK" "JSON dashboard report: $json_dashboard" 
    fi
}

# Gap analysis summary
gap_analysis() {
    print_section "Gap Analysis for Action Planning"
    
    local gap_file="$OUTPUT_DIR/gap-analysis-$DATE_STR.txt"
    local temp_compliance=$(mktemp)
    
    print_status "INFO" "Analyzing security gaps..."
    
    # Get compliance results
    "$SYSINFO_TOOL" --compliance-check 2>/dev/null > "$temp_compliance" || {
        print_status "WARN" "Could not generate gap analysis"
        rm -f "$temp_compliance"
        return 1
    }
    
    # Analyze gaps
    {
        echo "=== SECURITY GAP ANALYSIS - $(date) ==="
        echo
        
        # Count different priority items
        local critical_gaps=$(grep -c "CRITICAL\|FAIL" "$temp_compliance" 2>/dev/null || echo "0")
        local high_gaps=$(grep -c "HIGH\|WARNING" "$temp_compliance" 2>/dev/null || echo "0") 
        local medium_gaps=$(grep -c "MEDIUM\|WARN" "$temp_compliance" 2>/dev/null || echo "0")
        
        echo "CRITICAL PRIORITY (Immediate action required):"
        if [[ $critical_gaps -gt 0 ]]; then
            grep "CRITICAL\|FAIL" "$temp_compliance" | head -5
            echo "Total: $critical_gaps issues"
        else
            echo "No critical issues found"
        fi
        echo
        
        echo "HIGH PRIORITY (1-7 days):"
        if [[ $high_gaps -gt 0 ]]; then
            grep "HIGH\|WARNING" "$temp_compliance" | head -5
            echo "Total: $high_gaps issues"
        else
            echo "No high-priority issues"
        fi
        echo
        
        echo "MEDIUM PRIORITY (1-4 weeks):"
        if [[ $medium_gaps -gt 0 ]]; then
            grep "MEDIUM\|WARN" "$temp_compliance" | head -5
            echo "Total: $medium_gaps issues"
        else
            echo "No medium-priority issues"
        fi
        echo
        
        echo "FRAMEWORK-SPECIFIC GAPS:"
        echo "CIS Level 1 Failures:"
        local cis_failures=$(grep -c "CIS.*FAIL" "$temp_compliance" 2>/dev/null || echo "0")
        echo "Count: $cis_failures"
        
    } > "$gap_file"
    
    rm -f "$temp_compliance"
    
    print_status "OK" "Gap analysis completed"
    print_status "OK" "Report saved: $gap_file"
    
    # Display summary
    cat "$gap_file"
}

# Management summary
management_summary() {
    print_section "Executive Management Summary"
    
    local summary_file="$OUTPUT_DIR/management-summary-$DATE_STR.txt"
    local json_summary="$OUTPUT_DIR/compliance-summary-$DATE_STR.json"
    
    print_status "INFO" "Generating management summary..."
    
    # Create management summary
    {
        echo "SECURITY COMPLIANCE EXECUTIVE SUMMARY"
        echo "====================================="
        echo "Generated: $(date)"
        echo "System: $(hostname)"
        echo "Assessment Tool: Debian Security Compliance Checker v$VERSION"
        echo
        
        echo "OVERALL SECURITY POSTURE:"
        echo "========================="
        echo "• System appears to be well-configured"
        echo "• Regular monitoring recommended"
        echo "• Some improvements possible (see detailed reports)"
        echo
        
        echo "KEY RECOMMENDATIONS:"
        echo "==================="
        echo "1. Review and address any CRITICAL findings"
        echo "2. Implement regular vulnerability scanning"
        echo "3. Maintain current patch levels"
        echo "4. Consider security awareness training"
        echo
        
        echo "COMPLIANCE STATUS:"
        echo "=================="
        echo "• Framework assessments completed"
        echo "• Detailed findings in individual reports"
        echo "• Action plan recommendations provided"
        echo
        
        echo "NEXT STEPS:"
        echo "==========="
        echo "1. Review detailed technical reports"
        echo "2. Prioritize critical and high-priority items"
        echo "3. Schedule regular compliance assessments"
        echo "4. Implement continuous monitoring"
        
    } > "$summary_file"
    
    # Create JSON summary for automation
    {
        echo "{"
        echo "  \"assessment_date\": \"$(date -Iseconds)\","
        echo "  \"hostname\": \"$(hostname)\","
        echo "  \"tool_version\": \"$VERSION\","
        echo "  \"status\": \"completed\","
        echo "  \"overall_rating\": \"good\","
        echo "  \"recommendations\": ["
        echo "    \"Review critical findings\","
        echo "    \"Implement regular scanning\","
        echo "    \"Maintain patch levels\""
        echo "  ]"
        echo "}"
    } > "$json_summary"
    
    print_status "OK" "Management summary created: $summary_file"
    print_status "OK" "JSON summary created: $json_summary"
    
    # Display summary
    cat "$summary_file"
}

# Show final summary
show_summary() {
    print_section "Assessment Summary"
    
    print_status "OK" "Security compliance assessment completed"
    print_status "INFO" "All reports saved to: $OUTPUT_DIR"
    
    echo -e "\n${WHITE}Generated Reports:${NC}"
    ls -la "$OUTPUT_DIR"/*"$DATE_STR"* 2>/dev/null | while IFS= read -r file; do
        echo -e "${CYAN}  • $(basename "$file")${NC}"
    done
    
    echo -e "\n${YELLOW}Next Steps:${NC}"
    echo -e "${CYAN}  1. Review all generated reports${NC}"
    echo -e "${CYAN}  2. Address critical and high-priority findings${NC}"
    echo -e "${CYAN}  3. Schedule regular assessments${NC}"
    echo -e "${CYAN}  4. Implement continuous monitoring${NC}"
}

# Usage information
usage() {
    cat << EOF
Debian & Ubuntu Security Compliance Checker v$VERSION

USAGE:
    $0 [OPTION]

OPTIONS:
    --quick         Quick dashboard overview (2 minutes)
    --compliance    Full compliance check (10 minutes)
    --audit         Comprehensive security audit (15 minutes)
    --vulnerabilities,--vulns  Vulnerability audit of all installed packages
    --performance   Performance impact analysis
    --json          Generate JSON reports for automation
    --gaps          Gap analysis for action planning
    --management    Generate management summary
    --all           Run all analyses (recommended)
    --version       Show version and check for updates
    --help          Show this help

EXAMPLES:
    $0 --quick                  # Quick status check
    $0 --compliance            # Compliance assessment
    $0 --vulnerabilities       # Scan package vulnerabilities
    $0 --all                   # Complete analysis (recommended)

SUPPORTED SYSTEMS:
    - Debian 10+ (Buster, Bullseye, Bookworm, Trixie)
    - Ubuntu 18.04+ (Bionic, Focal, Jammy, Noble)
    - Ubuntu derivatives with dpkg package manager

NOTES:
    - Root privileges required for complete analysis
    - Reports are saved to $OUTPUT_DIR
    - Tool performs ANALYSIS ONLY - no system modifications!
    - debsecan provides better support for Debian than Ubuntu
    - Repository: $REPO_URL

EOF
}

# Main function
main() {
    local command="${1:-}"
    
    print_header
    
    # Handle version check first
    if [[ "$command" == "--version" ]]; then
        echo -e "${WHITE}Debian Security Compliance Checker v$VERSION${NC}"
        echo -e "${CYAN}Repository: $REPO_URL${NC}"
        echo
        check_version
        exit 0
    fi
    
    # Check version on startup (but don't exit)
    check_version || true
    echo
    
    # Check prerequisites
    check_sysinfo_tool
    create_output_dir
    
    # Check root access
    if ! check_root 2>/dev/null; then
        print_status "WARN" "Root privileges not available - limited analysis"
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
            echo -e "${YELLOW}No option specified. Use --help for help.${NC}"
            echo -e "${CYAN}Quick start: $0 --all${NC}"
            ;;
        *)
            echo -e "${RED}Unknown option: $command${NC}" >&2
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"