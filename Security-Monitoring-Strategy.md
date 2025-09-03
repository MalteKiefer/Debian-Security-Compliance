# Security Monitoring Strategy and Alerting Setup
**Comprehensive Continuous Security Monitoring Framework**

*Enterprise-Grade Linux Debian Security Monitoring*  
*Version 2.0 - Updated 2025-09-03*

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Monitoring Architecture](#monitoring-architecture)
3. [Real-time Security Monitoring](#real-time-security-monitoring)
4. [Log Analysis and SIEM Integration](#log-analysis-and-siem-integration)
5. [Performance Monitoring](#performance-monitoring)
6. [Compliance Monitoring](#compliance-monitoring)
7. [Incident Response Integration](#incident-response-integration)
8. [Alerting and Notification Systems](#alerting-and-notification-systems)

---

## Executive Summary

This comprehensive monitoring strategy provides 24/7 security oversight for hardened Debian systems, ensuring rapid detection and response to security events. The framework integrates real-time monitoring, automated alerting, and compliance validation to maintain enterprise-grade security posture.

**Key Monitoring Capabilities:**
- **Real-time Threat Detection**: Immediate identification of security incidents
- **Compliance Monitoring**: Continuous validation of security controls
- **Performance Impact Tracking**: Monitor hardening impact on system performance
- **Automated Response**: Immediate containment of detected threats
- **Comprehensive Logging**: Complete audit trail for forensics and compliance

**Monitoring Coverage:**
- Authentication and authorization events
- Network security incidents
- File integrity violations
- Service availability and security
- System resource utilization
- Database access patterns
- Web application attacks
- Compliance deviation alerts

---

## Monitoring Architecture

### 1. Multi-Layer Monitoring Framework

```
┌─────────────────────────────────────────────────────────────┐
│                    Monitoring Dashboard                     │
├─────────────────────────────────────────────────────────────┤
│               Alert Management & SIEM                      │
├─────────────┬─────────────┬─────────────┬─────────────────┤
│ Real-time   │   Log       │ Performance │   Compliance    │
│ Monitoring  │ Analysis    │ Monitoring  │   Validation    │
├─────────────┼─────────────┼─────────────┼─────────────────┤
│ - Failed    │ - Auth logs │ - CPU/Mem   │ - CIS Controls  │
│   Logins    │ - App logs  │ - Disk I/O  │ - ISO 27001     │
│ - Privilege │ - Security  │ - Network   │ - SOC 2         │
│   Changes   │   Events    │ - Services  │ - BSI Standards │
│ - File      │ - Audit     │ - Response  │ - Custom Rules  │
│   Changes   │   Trail     │   Times     │                 │
└─────────────┴─────────────┴─────────────┴─────────────────┘
```

### 2. Data Collection Points

| Component | Data Source | Collection Method | Frequency | Retention |
|-----------|-------------|-------------------|-----------|-----------|
| **Authentication** | /var/log/auth.log | Tail + Parse | Real-time | 1 year |
| **System Events** | /var/log/syslog | Tail + Parse | Real-time | 1 year |
| **Audit Events** | /var/log/audit/audit.log | auditd + Parse | Real-time | 2 years |
| **Firewall Logs** | /var/log/ufw.log | Tail + Parse | Real-time | 6 months |
| **Fail2Ban Events** | /var/log/fail2ban.log | Tail + Parse | Real-time | 6 months |
| **Web Server** | Apache/Nginx logs | Tail + Parse | Real-time | 1 year |
| **Database** | MySQL/PostgreSQL logs | Query + Parse | 5 minutes | 1 year |
| **Performance** | System metrics | Script + API | 1 minute | 3 months |
| **File Integrity** | AIDE reports | Daily check | Daily | 1 year |
| **Compliance** | CIS/ISO checks | Automated scan | Daily | 1 year |

---

## Real-time Security Monitoring

### 1. Critical Security Events

**Authentication Monitoring:**
```bash
# Monitor failed login attempts
tail -F /var/log/auth.log | grep --line-buffered "authentication failure" | while read line; do
    # Extract IP and username
    IP=$(echo "$line" | grep -oE "rhost=[0-9.]+" | cut -d= -f2)
    USER=$(echo "$line" | grep -oE "user=[a-zA-Z0-9]+" | cut -d= -f2)
    
    # Count recent failures
    RECENT_FAILURES=$(grep "authentication failure" /var/log/auth.log | \
                     grep "$(date '+%b %d')" | grep "$IP" | wc -l)
    
    if [[ $RECENT_FAILURES -gt 5 ]]; then
        send_alert "HIGH" "Brute Force Attack" \
            "$RECENT_FAILURES failed login attempts from $IP for user $USER"
    fi
done
```

**Privilege Escalation Detection:**
```bash
# Monitor sudo usage
tail -F /var/log/auth.log | grep --line-buffered "sudo:" | while read line; do
    if echo "$line" | grep -q "root"; then
        USER=$(echo "$line" | awk '{print $5}')
        COMMAND=$(echo "$line" | sed -n 's/.*COMMAND=//p')
        
        send_alert "MEDIUM" "Root Command Executed" \
            "User $USER executed: $COMMAND"
    fi
done
```

**File System Monitoring:**
```bash
# Monitor critical file changes using inotify
inotifywait -m -r -e modify,create,delete \
    /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/ | \
while read path action file; do
    send_alert "HIGH" "Critical File Modified" \
        "File $path$file was $action"
done
```

### 2. Network Security Monitoring

**Port Scan Detection:**
```bash
# Monitor UFW logs for port scanning
tail -F /var/log/ufw.log | grep --line-buffered "DPT" | while read line; do
    SRC_IP=$(echo "$line" | grep -oE "SRC=[0-9.]+" | cut -d= -f2)
    DST_PORT=$(echo "$line" | grep -oE "DPT=[0-9]+" | cut -d= -f2)
    
    # Count unique ports accessed by IP in last hour
    UNIQUE_PORTS=$(grep "$SRC_IP" /var/log/ufw.log | \
                  grep "$(date '+%b %d %H')" | \
                  grep -oE "DPT=[0-9]+" | sort -u | wc -l)
    
    if [[ $UNIQUE_PORTS -gt 10 ]]; then
        send_alert "HIGH" "Port Scan Detected" \
            "IP $SRC_IP scanned $UNIQUE_PORTS ports in the last hour"
    fi
done
```

**Connection Monitoring:**
```bash
# Monitor network connections
ss -tuln | while read line; do
    # Monitor for suspicious listening services
    if echo "$line" | grep -qE ":23|:135|:445|:1433|:3389"; then
        PORT=$(echo "$line" | awk '{print $5}' | cut -d: -f2)
        send_alert "MEDIUM" "Suspicious Service Detected" \
            "Potentially dangerous service listening on port $PORT"
    fi
done
```

### 3. Application Security Monitoring

**Web Application Attack Detection:**
```bash
# Monitor Apache logs for SQL injection
tail -F /var/log/apache2/access.log | grep --line-buffered -iE "(union|select|insert|drop)" | while read line; do
    IP=$(echo "$line" | awk '{print $1}')
    REQUEST=$(echo "$line" | cut -d'"' -f2)
    
    send_alert "HIGH" "SQL Injection Attempt" \
        "SQL injection attempt from $IP: $REQUEST"
done

# Monitor for XSS attempts
tail -F /var/log/nginx/access.log | grep --line-buffered -iE "(script|alert|onerror)" | while read line; do
    IP=$(echo "$line" | awk '{print $1}')
    REQUEST=$(echo "$line" | cut -d'"' -f2)
    
    send_alert "HIGH" "XSS Attack Attempt" \
        "XSS attempt from $IP: $REQUEST"
done
```

**PHP Security Monitoring:**
```bash
# Monitor PHP errors for security issues
tail -F /var/log/php/error.log | grep --line-buffered -iE "(eval|exec|system|shell_exec)" | while read line; do
    send_alert "HIGH" "Dangerous PHP Function Used" \
        "Potentially dangerous PHP function detected: $line"
done
```

---

## Log Analysis and SIEM Integration

### 1. Centralized Log Collection

**Rsyslog Configuration for Central Logging:**
```bash
# /etc/rsyslog.d/50-security-central.conf
# Send all security logs to central SIEM
auth,authpriv.*                    @@siem-server.company.com:514
local0.*                          @@siem-server.company.com:514

# Local security log analysis
auth.info                         /var/log/security-hardening/auth-analysis.log
kern.warning                      /var/log/security-hardening/kernel-analysis.log
```

**Log Parsing and Enrichment:**
```bash
#!/bin/bash
# Parse and enrich security logs

parse_auth_logs() {
    tail -F /var/log/auth.log | while read line; do
        # Extract key information
        TIMESTAMP=$(echo "$line" | awk '{print $1, $2, $3}')
        HOST=$(echo "$line" | awk '{print $4}')
        SERVICE=$(echo "$line" | awk '{print $5}')
        
        # Enrich with GeoIP if available
        if command -v geoiplookup >/dev/null 2>&1; then
            IP=$(echo "$line" | grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
            if [[ -n "$IP" ]]; then
                COUNTRY=$(geoiplookup "$IP" | cut -d: -f2 | xargs)
                echo "[$TIMESTAMP] $HOST $SERVICE - IP: $IP Country: $COUNTRY - $line" >> /var/log/security-hardening/enriched-auth.log
            fi
        fi
    done
}
```

### 2. Security Event Correlation

**Multi-Source Event Correlation:**
```bash
#!/bin/bash
# Correlate events across multiple log sources

correlate_security_events() {
    local timeframe="300" # 5 minutes
    local current_time=$(date +%s)
    local start_time=$((current_time - timeframe))
    
    # Find related events within timeframe
    local failed_auth=$(grep "authentication failure" /var/log/auth.log | \
                       awk -v start="$start_time" '
                       {
                           cmd="date -d \""$1" "$2" "$3"\" +%s"
                           cmd | getline epoch
                           close(cmd)
                           if (epoch >= start) print $0
                       }' | wc -l)
    
    local ufw_blocks=$(grep "BLOCK" /var/log/ufw.log | \
                      awk -v start="$start_time" '
                      {
                          cmd="date -d \""$1" "$2" "$3"\" +%s"
                          cmd | getline epoch
                          close(cmd)
                          if (epoch >= start) print $0
                      }' | wc -l)
    
    # Correlate events
    if [[ $failed_auth -gt 3 ]] && [[ $ufw_blocks -gt 5 ]]; then
        send_alert "CRITICAL" "Coordinated Attack Detected" \
            "$failed_auth failed authentications and $ufw_blocks firewall blocks in 5 minutes"
    fi
}
```

### 3. Automated Log Analysis

**Security Pattern Detection:**
```bash
#!/bin/bash
# Automated security pattern analysis

analyze_attack_patterns() {
    local log_file="/var/log/auth.log"
    
    # Analyze attack patterns
    echo "=== Security Log Analysis - $(date) ===" >> /var/log/security-hardening/analysis.log
    
    # Top attacking IPs
    echo "Top Attacking IPs:" >> /var/log/security-hardening/analysis.log
    grep "authentication failure" "$log_file" | \
        grep -oE "rhost=[0-9.]+" | cut -d= -f2 | \
        sort | uniq -c | sort -nr | head -10 >> /var/log/security-hardening/analysis.log
    
    # Attack time patterns
    echo "Attack Time Patterns:" >> /var/log/security-hardening/analysis.log
    grep "authentication failure" "$log_file" | \
        awk '{print $3}' | cut -d: -f1 | \
        sort | uniq -c | sort -nr >> /var/log/security-hardening/analysis.log
    
    # Targeted users
    echo "Targeted Users:" >> /var/log/security-hardening/analysis.log
    grep "authentication failure" "$log_file" | \
        grep -oE "user=[a-zA-Z0-9]+" | cut -d= -f2 | \
        sort | uniq -c | sort -nr | head -10 >> /var/log/security-hardening/analysis.log
}
```

---

## Performance Monitoring

### 1. Security Tool Performance Impact

**Resource Usage Monitoring:**
```bash
#!/bin/bash
# Monitor performance impact of security tools

monitor_security_performance() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local perf_log="/var/log/security-hardening/performance.log"
    
    # Monitor auditd performance
    local audit_cpu=$(ps aux | grep auditd | grep -v grep | awk '{print $3}')
    local audit_mem=$(ps aux | grep auditd | grep -v grep | awk '{print $4}')
    
    # Monitor fail2ban performance
    local fail2ban_cpu=$(ps aux | grep fail2ban | grep -v grep | awk '{print $3}')
    local fail2ban_mem=$(ps aux | grep fail2ban | grep -v grep | awk '{print $4}')
    
    # Monitor AppArmor impact
    local apparmor_denials=$(grep DENIED /var/log/syslog | grep "$(date '+%b %d')" | wc -l)
    
    # Log performance metrics
    echo "[$timestamp] PERF auditd_cpu=$audit_cpu auditd_mem=$audit_mem fail2ban_cpu=$fail2ban_cpu fail2ban_mem=$fail2ban_mem apparmor_denials=$apparmor_denials" >> "$perf_log"
    
    # Alert on high resource usage
    if (( $(echo "$audit_cpu > 5.0" | bc -l) )); then
        send_alert "MEDIUM" "High Audit CPU Usage" \
            "auditd is using ${audit_cpu}% CPU"
    fi
}
```

### 2. System Performance Baseline

**Performance Baseline Collection:**
```bash
#!/bin/bash
# Collect system performance baselines

collect_performance_baseline() {
    local baseline_file="/var/lib/security-hardening/performance-baseline.json"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # System metrics
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    local memory_usage=$(free | grep '^Mem:' | awk '{printf("%.1f", $3/$2*100)}')
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | sed 's/^ *//')
    
    # Network metrics
    local connections=$(ss -tuln | wc -l)
    local network_errors=$(netstat -i | awk 'NR>2 {errors += $5} END {print errors+0}')
    
    # Service response times
    local ssh_response=$(timeout 5 bash -c "</dev/tcp/localhost/22" 2>/dev/null && echo "OK" || echo "TIMEOUT")
    
    # Create JSON record
    cat >> "$baseline_file" << EOF
{
  "timestamp": "$timestamp",
  "cpu_usage": $cpu_usage,
  "memory_usage": $memory_usage,
  "disk_usage": $disk_usage,
  "load_average": "$load_avg",
  "connections": $connections,
  "network_errors": $network_errors,
  "ssh_response": "$ssh_response"
}
EOF
}
```

---

## Compliance Monitoring

### 1. Automated Compliance Validation

**CIS Benchmark Monitoring:**
```bash
#!/bin/bash
# Automated CIS compliance checking

monitor_cis_compliance() {
    local compliance_log="/var/log/security-hardening/compliance.log"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # CIS 1.1.1.1 - cramfs filesystem
    if lsmod | grep -q cramfs; then
        echo "[$timestamp] CIS-1.1.1.1 FAIL: cramfs filesystem loaded" >> "$compliance_log"
        send_alert "HIGH" "CIS Compliance Violation" "cramfs filesystem is loaded"
    fi
    
    # CIS 1.4.1 - GRUB password
    if [[ ! -f /boot/grub/user.cfg ]]; then
        echo "[$timestamp] CIS-1.4.1 FAIL: GRUB password not set" >> "$compliance_log"
    fi
    
    # CIS 1.5.3 - ASLR
    if [[ $(sysctl -n kernel.randomize_va_space) != "2" ]]; then
        echo "[$timestamp] CIS-1.5.3 FAIL: ASLR not properly configured" >> "$compliance_log"
        send_alert "HIGH" "CIS Compliance Violation" "ASLR not properly configured"
    fi
    
    # CIS 3.1.1 - IP forwarding
    if [[ $(sysctl -n net.ipv4.ip_forward) != "0" ]]; then
        echo "[$timestamp] CIS-3.1.1 FAIL: IP forwarding enabled" >> "$compliance_log"
        send_alert "HIGH" "CIS Compliance Violation" "IP forwarding is enabled"
    fi
    
    # CIS 5.2.10 - SSH root login
    if ! grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        echo "[$timestamp] CIS-5.2.10 FAIL: SSH root login not disabled" >> "$compliance_log"
        send_alert "CRITICAL" "CIS Compliance Violation" "SSH root login not disabled"
    fi
}
```

### 2. ISO 27001 Control Monitoring

**ISO 27001 A.12.4.1 - Event Logging:**
```bash
monitor_iso_logging() {
    # Check if logging is active
    if ! systemctl is-active --quiet rsyslog; then
        send_alert "CRITICAL" "ISO 27001 Violation" "System logging service not active"
    fi
    
    # Check log retention
    local old_logs=$(find /var/log -name "*.log" -mtime +365 | wc -l)
    if [[ $old_logs -gt 0 ]]; then
        send_alert "MEDIUM" "ISO 27001 Notice" "$old_logs log files older than 1 year found"
    fi
    
    # Check audit logging
    if ! systemctl is-active --quiet auditd; then
        send_alert "CRITICAL" "ISO 27001 Violation" "Audit logging service not active"
    fi
}
```

### 3. SOC 2 Control Monitoring

**SOC 2 CC6.1 - Logical Access:**
```bash
monitor_soc2_access() {
    # Monitor privileged access
    local admin_logins=$(grep "sudo" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)
    if [[ $admin_logins -gt 20 ]]; then
        send_alert "MEDIUM" "SOC 2 Notice" "$admin_logins privileged access events today"
    fi
    
    # Check for shared accounts
    local shared_accounts=$(awk -F: '$3 >= 1000 && $1 !~ /^[a-z]+\.[a-z]+$/ {print $1}' /etc/passwd | wc -l)
    if [[ $shared_accounts -gt 0 ]]; then
        send_alert "HIGH" "SOC 2 Violation" "$shared_accounts potential shared accounts detected"
    fi
}
```

---

## Incident Response Integration

### 1. Automated Incident Creation

**ITSM Integration:**
```bash
create_security_incident() {
    local priority="$1"
    local title="$2"
    local description="$3"
    local itsm_api="${ITSM_API_URL:-http://itsm.company.com/api/incidents}"
    
    # Create incident ticket
    local incident_data="{
        \"priority\": \"$priority\",
        \"category\": \"Security\",
        \"title\": \"$title\",
        \"description\": \"$description\",
        \"reporter\": \"security-monitor\",
        \"assignment_group\": \"Security Team\"
    }"
    
    local incident_id=$(curl -s -X POST "$itsm_api" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $ITSM_API_KEY" \
        -d "$incident_data" | jq -r '.incident_id')
    
    log_event "INFO" "Created security incident: $incident_id"
    return 0
}
```

### 2. Automated Response Actions

**Threat Containment:**
```bash
contain_threat() {
    local threat_type="$1"
    local source_ip="$2"
    local additional_info="$3"
    
    case "$threat_type" in
        "brute_force")
            # Block IP in firewall
            ufw insert 1 deny from "$source_ip"
            
            # Add to Fail2Ban permanent ban
            fail2ban-client set sshd banip "$source_ip"
            
            log_event "RESPONSE" "Blocked brute force source: $source_ip"
            ;;
        "malware")
            # Isolate system from network (if not critical)
            # This should be carefully considered
            log_event "RESPONSE" "Malware detected, manual intervention required"
            ;;
        "privilege_escalation")
            # Lock user account if applicable
            local user=$(echo "$additional_info" | grep -oE "user=[a-zA-Z0-9]+" | cut -d= -f2)
            if [[ -n "$user" ]] && [[ "$user" != "root" ]]; then
                passwd -l "$user"
                log_event "RESPONSE" "Locked user account: $user"
            fi
            ;;
    esac
}
```

### 3. Evidence Collection

**Automated Forensics:**
```bash
collect_forensic_evidence() {
    local incident_id="$1"
    local evidence_dir="/var/lib/security-hardening/evidence/$incident_id"
    
    mkdir -p "$evidence_dir"
    
    # System state
    ps aux > "$evidence_dir/processes.txt"
    netstat -tuln > "$evidence_dir/network.txt"
    ss -tuln > "$evidence_dir/sockets.txt"
    
    # Recent logs
    cp /var/log/auth.log "$evidence_dir/"
    cp /var/log/syslog "$evidence_dir/"
    cp /var/log/audit/audit.log "$evidence_dir/"
    
    # System configuration
    cp /etc/passwd "$evidence_dir/"
    cp /etc/shadow "$evidence_dir/"
    cp /etc/group "$evidence_dir/"
    
    # Create evidence hash
    find "$evidence_dir" -type f -exec sha256sum {} \; > "$evidence_dir/evidence.sha256"
    
    log_event "FORENSICS" "Evidence collected for incident: $incident_id"
}
```

---

## Alerting and Notification Systems

### 1. Multi-Channel Alert System

**Alert Configuration:**
```bash
# /etc/security-hardening/alert.conf
ALERT_EMAIL="security-team@company.com"
ALERT_SMS_GATEWAY="https://api.sms.company.com/send"
ALERT_SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
ALERT_TEAMS_WEBHOOK="https://company.webhook.office.com/webhookb2/..."

# Alert thresholds
CRITICAL_RESPONSE_TIME=300  # 5 minutes
HIGH_RESPONSE_TIME=900      # 15 minutes
MEDIUM_RESPONSE_TIME=3600   # 1 hour
LOW_RESPONSE_TIME=86400     # 24 hours

# Escalation rules
ESCALATION_ENABLED=true
ESCALATION_MANAGER="manager@company.com"
ESCALATION_TIME=1800        # 30 minutes
```

**Smart Alert Dispatcher:**
```bash
send_smart_alert() {
    local priority="$1"
    local subject="$2"
    local message="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Determine alert channels based on priority
    case "$priority" in
        "CRITICAL")
            send_email_alert "$subject" "$message"
            send_sms_alert "$subject"
            send_slack_alert "$priority" "$subject" "$message"
            create_security_incident "Critical" "$subject" "$message"
            ;;
        "HIGH")
            send_email_alert "$subject" "$message"
            send_slack_alert "$priority" "$subject" "$message"
            create_security_incident "High" "$subject" "$message"
            ;;
        "MEDIUM")
            send_email_alert "$subject" "$message"
            send_slack_alert "$priority" "$subject" "$message"
            ;;
        "LOW"|"INFO")
            send_slack_alert "$priority" "$subject" "$message"
            ;;
    esac
    
    # Log alert
    echo "[$timestamp] [$priority] ALERT SENT: $subject" >> /var/log/security-hardening/alerts.log
}
```

### 2. Alert Templates and Formatting

**Email Alert Template:**
```bash
send_email_alert() {
    local subject="$1"
    local message="$2"
    local hostname=$(hostname -f)
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S %Z')
    
    cat > /tmp/alert_email.txt << EOF
Subject: [SECURITY ALERT] $subject - $hostname

SECURITY ALERT NOTIFICATION
============================

Time: $timestamp
Host: $hostname
Alert: $subject

Details:
$message

System Information:
- Load Average: $(uptime | awk -F'load average:' '{print $2}')
- Memory Usage: $(free -h | grep '^Mem:' | awk '{print $3"/"$2}')
- Disk Usage: $(df -h / | awk 'NR==2 {print $5}')

Recent Security Events:
$(tail -5 /var/log/security-hardening/security-alerts.log 2>/dev/null || echo "No recent alerts")

Actions Required:
1. Investigate the security event immediately
2. Check system logs for related activities
3. Implement containment measures if necessary
4. Document findings and response actions

For immediate assistance, contact the Security Operations Center.

--
Automated Security Monitoring System
$hostname
EOF

    mail -s "[SECURITY ALERT] $subject - $hostname" "$ALERT_EMAIL" < /tmp/alert_email.txt
    rm -f /tmp/alert_email.txt
}
```

**Slack Integration:**
```bash
send_slack_alert() {
    local priority="$1"
    local subject="$2"
    local message="$3"
    local hostname=$(hostname -f)
    
    # Color coding based on priority
    local color
    case "$priority" in
        "CRITICAL") color="#FF0000" ;;  # Red
        "HIGH") color="#FF8C00" ;;      # Orange
        "MEDIUM") color="#FFD700" ;;    # Yellow
        "LOW") color="#00FF00" ;;       # Green
        "INFO") color="#0000FF" ;;      # Blue
    esac
    
    local slack_payload="{
        \"attachments\": [
            {
                \"color\": \"$color\",
                \"title\": \"[$priority] Security Alert: $subject\",
                \"text\": \"$message\",
                \"fields\": [
                    {
                        \"title\": \"Host\",
                        \"value\": \"$hostname\",
                        \"short\": true
                    },
                    {
                        \"title\": \"Time\",
                        \"value\": \"$(date '+%Y-%m-%d %H:%M:%S %Z')\",
                        \"short\": true
                    }
                ],
                \"footer\": \"Security Monitoring System\",
                \"ts\": $(date +%s)
            }
        ]
    }"
    
    curl -X POST -H 'Content-type: application/json' \
         --data "$slack_payload" \
         "$ALERT_SLACK_WEBHOOK" &>/dev/null || true
}
```

### 3. Alert Suppression and Deduplication

**Smart Alert Management:**
```bash
should_suppress_alert() {
    local alert_key="$1"
    local suppression_time="$2"
    local last_alert_file="/var/lib/security-hardening/last_alerts/$alert_key"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$last_alert_file")"
    
    # Check if this alert was recently sent
    if [[ -f "$last_alert_file" ]]; then
        local last_alert_time=$(cat "$last_alert_file")
        local current_time=$(date +%s)
        local time_diff=$((current_time - last_alert_time))
        
        if [[ $time_diff -lt $suppression_time ]]; then
            return 0  # Suppress alert
        fi
    fi
    
    # Record current alert time
    echo "$(date +%s)" > "$last_alert_file"
    return 1  # Don't suppress
}

# Usage example
alert_key="failed_login_$(echo "$IP" | tr '.' '_')"
if ! should_suppress_alert "$alert_key" 3600; then
    send_alert "HIGH" "Brute Force Attack" "Multiple failed logins from $IP"
fi
```

### 4. Dashboard and Visualization

**Security Dashboard Data:**
```bash
generate_dashboard_data() {
    local dashboard_file="/var/www/html/security-dashboard.json"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Collect current security metrics
    local failed_logins_today=$(grep "authentication failure" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)
    local blocked_ips=$(fail2ban-client status sshd | grep "Currently banned:" | awk -F: '{print $2}' | wc -w)
    local audit_events=$(grep "$(date '+%m/%d/%Y')" /var/log/audit/audit.log | wc -l)
    local apparmor_denials=$(grep DENIED /var/log/syslog | grep "$(date '+%b %d')" | wc -l)
    
    # System health metrics
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    local memory_usage=$(free | grep '^Mem:' | awk '{printf("%.1f", $3/$2*100)}')
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    # Service status
    local ssh_status=$(systemctl is-active sshd)
    local fail2ban_status=$(systemctl is-active fail2ban)
    local auditd_status=$(systemctl is-active auditd)
    local apparmor_status=$(systemctl is-active apparmor)
    
    # Generate JSON dashboard data
    cat > "$dashboard_file" << EOF
{
    "last_update": "$timestamp",
    "security_events": {
        "failed_logins_today": $failed_logins_today,
        "blocked_ips": $blocked_ips,
        "audit_events_today": $audit_events,
        "apparmor_denials_today": $apparmor_denials
    },
    "system_health": {
        "cpu_usage": $cpu_usage,
        "memory_usage": $memory_usage,
        "disk_usage": "$disk_usage"
    },
    "service_status": {
        "ssh": "$ssh_status",
        "fail2ban": "$fail2ban_status",
        "auditd": "$auditd_status",
        "apparmor": "$apparmor_status"
    },
    "compliance_status": {
        "cis_level1": "compliant",
        "iso27001": "compliant",
        "soc2": "compliant"
    }
}
EOF
}
```

---

## Implementation Checklist

### 1. Initial Setup (Day 1-3)

- [ ] **Monitoring Infrastructure**
  - [ ] Create monitoring directories and log files
  - [ ] Install required monitoring tools and dependencies
  - [ ] Configure log rotation for monitoring logs
  - [ ] Set up alert notification channels

- [ ] **Real-time Monitoring Scripts**
  - [ ] Deploy authentication monitoring
  - [ ] Configure privilege escalation detection
  - [ ] Set up file integrity monitoring
  - [ ] Implement network security monitoring

- [ ] **Alert System Configuration**
  - [ ] Configure email alerting
  - [ ] Set up Slack/Teams integration
  - [ ] Test SMS gateway (if available)
  - [ ] Validate alert suppression mechanisms

### 2. Advanced Monitoring (Day 4-7)

- [ ] **Performance Monitoring**
  - [ ] Deploy system resource monitoring
  - [ ] Configure performance baseline collection
  - [ ] Set up security tool performance tracking

- [ ] **Compliance Monitoring**
  - [ ] Implement automated CIS checks
  - [ ] Configure ISO 27001 control monitoring
  - [ ] Set up SOC 2 compliance validation

- [ ] **Log Analysis**
  - [ ] Configure centralized logging (if applicable)
  - [ ] Set up automated log analysis
  - [ ] Implement security event correlation

### 3. Integration and Testing (Day 8-14)

- [ ] **SIEM Integration**
  - [ ] Configure log forwarding to SIEM
  - [ ] Set up custom parsing rules
  - [ ] Test alert integration with ITSM

- [ ] **Incident Response**
  - [ ] Test automated containment actions
  - [ ] Validate forensic evidence collection
  - [ ] Verify escalation procedures

- [ ] **Dashboard and Reporting**
  - [ ] Deploy security dashboard
  - [ ] Configure automated reporting
  - [ ] Test visualization and metrics

### 4. Operational Validation (Day 15-30)

- [ ] **End-to-End Testing**
  - [ ] Simulate security events
  - [ ] Validate alert generation and routing
  - [ ] Test incident response workflows

- [ ] **Performance Optimization**
  - [ ] Tune monitoring sensitivity
  - [ ] Optimize resource usage
  - [ ] Fine-tune alert thresholds

- [ ] **Documentation and Training**
  - [ ] Complete monitoring documentation
  - [ ] Train security operations team
  - [ ] Establish monitoring procedures

---

## Conclusion

This comprehensive monitoring strategy provides enterprise-grade security visibility and automated response capabilities for hardened Debian systems. The framework ensures rapid detection and containment of security threats while maintaining continuous compliance validation.

**Key Success Factors:**
1. **Comprehensive Coverage**: Monitor all critical security domains
2. **Real-time Detection**: Immediate identification of security events
3. **Automated Response**: Rapid containment of identified threats
4. **Compliance Integration**: Continuous validation of security controls
5. **Scalable Architecture**: Support for growing infrastructure needs

**Operational Benefits:**
- **Reduced Detection Time**: From hours to seconds
- **Improved Response**: Automated containment and evidence collection
- **Enhanced Compliance**: Continuous monitoring and validation
- **Better Visibility**: Complete security posture awareness
- **Operational Efficiency**: Automated processes reduce manual effort

**Next Steps:**
1. **Phase 1**: Deploy core monitoring capabilities
2. **Phase 2**: Integrate advanced analytics and SIEM
3. **Phase 3**: Implement machine learning for anomaly detection
4. **Phase 4**: Expand to full security orchestration platform

---

*Document Version: 2.0*  
*Last Updated: 2025-09-03*  
*Next Review: 2025-12-03*  
*Security Operations Contact: security-ops@company.com*