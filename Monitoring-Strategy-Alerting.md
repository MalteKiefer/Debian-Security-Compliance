#!/bin/bash

################################################################################
# Real-time Security Monitoring Script
# Monitors critical security events and generates alerts
# Version: 2.0
# Compliance: ISO 27001, SOC 2, CIS Level 2
################################################################################

set -euo pipefail

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_FILE="/etc/security-hardening/monitor.conf"
readonly LOG_FILE="/var/log/security-hardening/security-monitor.log"
readonly ALERT_LOG="/var/log/security-hardening/security-alerts.log"
readonly PID_FILE="/var/run/security-monitor.pid"

# Default configuration
ALERT_EMAIL="${ALERT_EMAIL:-admin@localhost}"
SMS_GATEWAY="${SMS_GATEWAY:-}"
WEBHOOK_URL="${WEBHOOK_URL:-}"
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-90}"
MONITORING_INTERVAL="${MONITORING_INTERVAL:-30}"

# Alert thresholds
MAX_FAILED_LOGINS="${MAX_FAILED_LOGINS:-10}"
FAILED_LOGIN_WINDOW="${FAILED_LOGIN_WINDOW:-3600}"
MAX_SUDO_ATTEMPTS="${MAX_SUDO_ATTEMPTS:-5}"
DISK_USAGE_THRESHOLD="${DISK_USAGE_THRESHOLD:-90}"
CPU_THRESHOLD="${CPU_THRESHOLD:-80}"
MEMORY_THRESHOLD="${MEMORY_THRESHOLD:-80}"

# Load configuration if exists
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

# Logging function
log_event() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Alert function
send_alert() {
    local priority="$1"
    local subject="$2"
    local message="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Log alert
    echo "[$timestamp] [ALERT-$priority] $subject: $message" | tee -a "$ALERT_LOG"
    
    # Send email alert
    if command -v mail >/dev/null 2>&1 && [[ -n "$ALERT_EMAIL" ]]; then
        echo -e "Time: $timestamp\nHost: $(hostname)\nPriority: $priority\n\nMessage:\n$message" | \
            mail -s "[$priority] Security Alert: $subject" "$ALERT_EMAIL"
    fi
    
    # Send SMS for critical alerts
    if [[ "$priority" == "CRITICAL" ]] && [[ -n "$SMS_GATEWAY" ]]; then
        curl -s -X POST "$SMS_GATEWAY" \
            -d "message=CRITICAL Security Alert on $(hostname): $subject" \
            2>/dev/null || true
    fi
    
    # Send webhook notification
    if [[ -n "$WEBHOOK_URL" ]]; then
        curl -s -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"priority\":\"$priority\",\"host\":\"$(hostname)\",\"subject\":\"$subject\",\"message\":\"$message\",\"timestamp\":\"$timestamp\"}" \
            2>/dev/null || true
    fi
}

# Check for root access attempts
monitor_root_access() {
    local recent_attempts
    recent_attempts=$(grep "$(date '+%b %d')" /var/log/auth.log 2>/dev/null | \
                     grep -i "root" | grep -E "(authentication failure|login failed)" | tail -5)
    
    if [[ -n "$recent_attempts" ]]; then
        send_alert "CRITICAL" "Root Access Attempts Detected" "$recent_attempts"
    fi
}

# Monitor failed login attempts
monitor_failed_logins() {
    local current_time=$(date +%s)
    local window_start=$((current_time - FAILED_LOGIN_WINDOW))
    local failed_count=0
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local log_time=$(date -d "$(echo "$line" | awk '{print $1, $2, $3}')" +%s 2>/dev/null || echo 0)
            if [[ $log_time -gt $window_start ]]; then
                ((failed_count++))
            fi
        fi
    done < <(grep "authentication failure" /var/log/auth.log 2>/dev/null | tail -20)
    
    if [[ $failed_count -gt $MAX_FAILED_LOGINS ]]; then
        send_alert "HIGH" "Excessive Failed Login Attempts" \
            "$failed_count failed login attempts in the last hour"
    fi
}

# Monitor privilege escalation
monitor_privilege_escalation() {
    local recent_sudo
    recent_sudo=$(grep "$(date '+%b %d')" /var/log/auth.log 2>/dev/null | \
                 grep "sudo:" | grep "root" | tail -10)
    
    if [[ -n "$recent_sudo" ]]; then
        local sudo_count=$(echo "$recent_sudo" | wc -l)
        if [[ $sudo_count -gt $MAX_SUDO_ATTEMPTS ]]; then
            send_alert "HIGH" "Multiple Privilege Escalations" \
                "$sudo_count sudo commands to root executed today"
        fi
    fi
}

# Monitor system file changes
monitor_file_integrity() {
    local aide_log="/var/log/aide/aide-$(date +%Y%m%d).log"
    
    if [[ -f "$aide_log" ]]; then
        if grep -q "changed\|added\|removed" "$aide_log"; then
            local changes=$(grep -E "changed|added|removed" "$aide_log" | head -10)
            send_alert "HIGH" "File Integrity Changes Detected" \
                "AIDE detected system file changes:\n$changes"
        fi
    fi
}

# Monitor critical services
monitor_security_services() {
    local failed_services=()
    local services=("sshd" "fail2ban" "auditd" "apparmor" "ufw")
    
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            failed_services+=("$service")
            
            # Attempt to restart service
            if systemctl restart "$service" 2>/dev/null; then
                send_alert "HIGH" "Security Service Recovered" \
                    "Service $service was down and has been restarted"
            else
                send_alert "CRITICAL" "Security Service Failed" \
                    "Service $service is down and failed to restart"
            fi
        fi
    done
}

# Monitor system resources
monitor_system_resources() {
    # Check disk usage
    while IFS= read -r line; do
        local usage=$(echo "$line" | awk '{print $5}' | sed 's/%//')
        local mount=$(echo "$line" | awk '{print $6}')
        
        if [[ $usage -gt $DISK_USAGE_THRESHOLD ]]; then
            send_alert "HIGH" "High Disk Usage" \
                "Mount point $mount is ${usage}% full"
        fi
    done < <(df -h | grep -E '^/dev')
    
    # Check CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    local cpu_idle=$(vmstat 1 2 | tail -n1 | awk '{print $15}')
    local cpu_used=$((100 - cpu_idle))
    
    if [[ $cpu_used -gt $CPU_THRESHOLD ]]; then
        send_alert "MEDIUM" "High CPU Usage" \
            "CPU usage is ${cpu_used}%"
    fi
    
    # Check memory usage
    local memory_info=$(free | grep '^Mem:')
    local total_mem=$(echo "$memory_info" | awk '{print $2}')
    local used_mem=$(echo "$memory_info" | awk '{print $3}')
    local mem_percent=$((used_mem * 100 / total_mem))
    
    if [[ $mem_percent -gt $MEMORY_THRESHOLD ]]; then
        send_alert "MEDIUM" "High Memory Usage" \
            "Memory usage is ${mem_percent}%"
    fi
}

# Monitor network security events
monitor_network_events() {
    # Check for port scans in UFW logs
    local port_scans
    port_scans=$(grep "$(date '+%b %d')" /var/log/ufw.log 2>/dev/null | \
                grep "DPT" | awk '{print $12}' | sort | uniq -c | \
                awk '$1 > 10 {print $2}' | head -5)
    
    if [[ -n "$port_scans" ]]; then
        send_alert "MEDIUM" "Port Scan Activity Detected" \
            "Multiple port access attempts detected from: $port_scans"
    fi
    
    # Check Fail2Ban status
    if command -v fail2ban-client >/dev/null 2>&1; then
        local banned_ips
        banned_ips=$(fail2ban-client status sshd 2>/dev/null | \
                    grep "Currently banned:" | awk -F: '{print $2}' | wc -w)
        
        if [[ $banned_ips -gt 0 ]]; then
            send_alert "INFO" "Fail2Ban Activity" \
                "$banned_ips IP addresses currently banned by Fail2Ban"
        fi
    fi
}

# Monitor web application attacks
monitor_web_attacks() {
    local apache_log="/var/log/apache2/error.log"
    local nginx_log="/var/log/nginx/error.log"
    
    # Check for SQL injection attempts in Apache logs
    if [[ -f "$apache_log" ]]; then
        local sql_attacks
        sql_attacks=$(grep "$(date '+%Y-%m-%d')" "$apache_log" 2>/dev/null | \
                     grep -iE "(union|select|insert|drop|delete)" | wc -l)
        
        if [[ $sql_attacks -gt 0 ]]; then
            send_alert "HIGH" "SQL Injection Attempts" \
                "$sql_attacks potential SQL injection attempts detected in Apache logs"
        fi
    fi
    
    # Check for attacks in Nginx logs
    if [[ -f "$nginx_log" ]]; then
        local web_attacks
        web_attacks=$(grep "$(date '+%Y/%m/%d')" "$nginx_log" 2>/dev/null | \
                     grep -iE "(script|alert|onerror)" | wc -l)
        
        if [[ $web_attacks -gt 0 ]]; then
            send_alert "HIGH" "XSS Attack Attempts" \
                "$web_attacks potential XSS attempts detected in Nginx logs"
        fi
    fi
}

# Monitor database security
monitor_database_security() {
    # Check MySQL/MariaDB logs for suspicious activity
    local mysql_log="/var/log/mysql/error.log"
    if [[ -f "$mysql_log" ]]; then
        local db_errors
        db_errors=$(grep "$(date '+%Y-%m-%d')" "$mysql_log" 2>/dev/null | \
                   grep -iE "(access denied|aborted connection)" | wc -l)
        
        if [[ $db_errors -gt 5 ]]; then
            send_alert "MEDIUM" "Database Access Issues" \
                "$db_errors database access denied or connection aborted events"
        fi
    fi
    
    # Check PostgreSQL logs
    local pg_log_dir="/var/log/postgresql"
    if [[ -d "$pg_log_dir" ]]; then
        local latest_pg_log=$(ls -t "$pg_log_dir"/*.log 2>/dev/null | head -1)
        if [[ -f "$latest_pg_log" ]]; then
            local pg_errors
            pg_errors=$(grep "$(date '+%Y-%m-%d')" "$latest_pg_log" 2>/dev/null | \
                       grep -iE "(authentication failed|connection rejected)" | wc -l)
            
            if [[ $pg_errors -gt 5 ]]; then
                send_alert "MEDIUM" "PostgreSQL Access Issues" \
                    "$pg_errors PostgreSQL authentication failures detected"
            fi
        fi
    fi
}

# Monitor compliance status
monitor_compliance() {
    # Check if compliance script exists and run it
    local compliance_script="$SCRIPT_DIR/sysinfo-security"
    if [[ -x "$compliance_script" ]]; then
        local compliance_result
        compliance_result=$("$compliance_script" --compliance-check 2>/dev/null | \
                           grep -E "(FAIL|CRITICAL)" | wc -l)
        
        if [[ $compliance_result -gt 0 ]]; then
            send_alert "MEDIUM" "Compliance Issues Detected" \
                "$compliance_result compliance failures detected"
        fi
    fi
}

# Clean up old logs
cleanup_logs() {
    find /var/log/security-hardening -name "*.log" -mtime +$LOG_RETENTION_DAYS -delete 2>/dev/null || true
    find /var/log/aide -name "aide-*.log" -mtime +$LOG_RETENTION_DAYS -delete 2>/dev/null || true
}

# Signal handlers
cleanup_on_exit() {
    [[ -f "$PID_FILE" ]] && rm -f "$PID_FILE"
    log_event "INFO" "Security monitor stopped"
    exit 0
}

trap cleanup_on_exit TERM INT

# Main monitoring loop
main() {
    # Check if already running
    if [[ -f "$PID_FILE" ]]; then
        local old_pid=$(cat "$PID_FILE")
        if kill -0 "$old_pid" 2>/dev/null; then
            echo "Security monitor already running (PID: $old_pid)"
            exit 1
        else
            rm -f "$PID_FILE"
        fi
    fi
    
    # Create PID file
    echo $$ > "$PID_FILE"
    
    log_event "INFO" "Security monitor started (PID: $$)"
    
    # Main monitoring loop
    while true; do
        log_event "DEBUG" "Running monitoring cycle"
        
        # Execute monitoring functions
        monitor_root_access
        monitor_failed_logins
        monitor_privilege_escalation
        monitor_file_integrity
        monitor_security_services
        monitor_system_resources
        monitor_network_events
        monitor_web_attacks
        monitor_database_security
        monitor_compliance
        
        # Clean up old logs daily
        if [[ $(date +%H:%M) == "03:00" ]]; then
            cleanup_logs
        fi
        
        # Wait for next monitoring cycle
        sleep "$MONITORING_INTERVAL"
    done
}

# Command line interface
case "${1:-}" in
    start)
        main
        ;;
    stop)
        if [[ -f "$PID_FILE" ]]; then
            local pid=$(cat "$PID_FILE")
            kill "$pid" 2>/dev/null && echo "Security monitor stopped"
            rm -f "$PID_FILE"
        else
            echo "Security monitor not running"
        fi
        ;;
    status)
        if [[ -f "$PID_FILE" ]]; then
            local pid=$(cat "$PID_FILE")
            if kill -0 "$pid" 2>/dev/null; then
                echo "Security monitor running (PID: $pid)"
            else
                echo "Security monitor not running (stale PID file)"
                rm -f "$PID_FILE"
            fi
        else
            echo "Security monitor not running"
        fi
        ;;
    test)
        send_alert "INFO" "Test Alert" "This is a test alert from security monitor"
        ;;
    *)
        echo "Usage: $0 {start|stop|status|test}"
        exit 1
        ;;
esac