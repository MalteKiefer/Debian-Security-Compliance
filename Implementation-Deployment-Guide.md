# Implementation and Deployment Guide
**Enterprise-Grade Linux Debian Security Hardening**

*Comprehensive Step-by-Step Deployment Procedures*  
*Version 2.0 - Updated 2025-09-03*

---

## Table of Contents
1. [Pre-Implementation Requirements](#pre-implementation-requirements)
2. [System Preparation](#system-preparation)
3. [Security Hardening Implementation](#security-hardening-implementation)
4. [Service Configuration Deployment](#service-configuration-deployment)
5. [Validation and Testing](#validation-and-testing)
6. [Rollback Procedures](#rollback-procedures)
7. [Troubleshooting Guide](#troubleshooting-guide)
8. [Maintenance and Monitoring](#maintenance-and-monitoring)

---

## Pre-Implementation Requirements

### 1. System Requirements

**Minimum System Specifications:**
- **Operating System:** Debian 11 (Bullseye) or newer
- **Architecture:** x86_64 (amd64)
- **Memory:** 2GB RAM minimum, 4GB recommended
- **Storage:** 20GB free space for logs and backups
- **Network:** Static IP configuration recommended

**Software Prerequisites:**
```bash
# Verify Debian version
cat /etc/debian_version

# Verify architecture
uname -m

# Check available disk space
df -h

# Verify network connectivity
ping -c 3 security.debian.org
```

### 2. Backup Requirements

**Critical Data Backup:**
```bash
# Create backup directory
mkdir -p /backup/pre-hardening/$(date +%Y%m%d)
cd /backup/pre-hardening/$(date +%Y%m%d)

# System configuration backup
tar -czf system-config-backup.tar.gz \
    /etc \
    /boot/grub \
    /var/spool/cron \
    /home/*/.ssh 2>/dev/null

# Package list backup
dpkg --get-selections > installed-packages.list
apt-mark showmanual > manual-packages.list

# Services status backup
systemctl list-unit-files > services-status.list
```

**Database Backups (if applicable):**
```bash
# MySQL/MariaDB backup
mysqldump --all-databases > mysql-backup.sql

# PostgreSQL backup
sudo -u postgres pg_dumpall > postgresql-backup.sql
```

### 3. Access Requirements

**Administrative Access:**
- Root access or sudo privileges required
- SSH key-based authentication recommended
- Console access available for emergency recovery
- Network access to Debian security repositories

**Team Communication:**
- Change management approval obtained
- Stakeholders notified of maintenance window
- Rollback decision makers identified and available

---

## System Preparation

### 1. Environment Setup

**Create Working Directories:**
```bash
#!/bin/bash
# Setup script environment
export HARDENING_DATE=$(date +%Y%m%d-%H%M%S)
export BACKUP_DIR="/var/backups/security-hardening"
export LOG_DIR="/var/log/security-hardening"
export CONFIG_DIR="/etc/security-hardening"

# Create necessary directories
mkdir -p "$BACKUP_DIR" "$LOG_DIR" "$CONFIG_DIR"
chmod 700 "$BACKUP_DIR" "$CONFIG_DIR"
chmod 750 "$LOG_DIR"
```

**Download and Verify Scripts:**
```bash
# Download hardening script
wget -O /tmp/debian-security-hardening.sh \
    https://your-repository/debian-security-hardening.sh

# Verify script integrity (if checksums available)
sha256sum /tmp/debian-security-hardening.sh

# Set executable permissions
chmod +x /tmp/debian-security-hardening.sh

# Review script before execution (mandatory)
less /tmp/debian-security-hardening.sh
```

### 2. Pre-Implementation Validation

**System Health Check:**
```bash
#!/bin/bash
# Pre-implementation system check

echo "=== System Health Check ==="

# Check system load
echo "Current system load:"
uptime

# Check disk space
echo -e "\nDisk space usage:"
df -h

# Check memory usage
echo -e "\nMemory usage:"
free -h

# Check running services
echo -e "\nCritical services status:"
systemctl is-active sshd
systemctl is-active networking
systemctl is-active systemd-resolved

# Check network connectivity
echo -e "\nNetwork connectivity:"
ping -c 3 8.8.8.8

# Check for existing security tools
echo -e "\nExisting security tools:"
which fail2ban-client 2>/dev/null && echo "fail2ban: installed" || echo "fail2ban: not installed"
which ufw 2>/dev/null && echo "ufw: installed" || echo "ufw: not installed"
which auditctl 2>/dev/null && echo "auditd: installed" || echo "auditd: not installed"
```

**Package Repository Check:**
```bash
# Update package lists
apt update

# Check for available security updates
apt list --upgradable | grep -i security

# Verify essential packages are available
apt-cache policy \
    fail2ban \
    ufw \
    auditd \
    apparmor \
    aide \
    unattended-upgrades
```

---

## Security Hardening Implementation

### 1. Phase 1: Core System Hardening

**Step 1: Execute Dry Run**
```bash
# Always perform dry run first
./debian-security-hardening.sh --dry-run --verbose

# Review proposed changes
less /var/log/security-hardening/debian-hardening-*.log
```

**Step 2: System Updates**
```bash
# Update package lists
apt update

# Install security updates first
apt upgrade -t *-security -y

# Full system upgrade
apt dist-upgrade -y

# Remove unnecessary packages
apt autoremove --purge -y
```

**Step 3: Kernel Hardening**
```bash
# Backup current sysctl configuration
cp /etc/sysctl.conf /etc/sysctl.conf.backup

# Apply kernel security parameters
cp configs/99-security-hardening.conf /etc/sysctl.d/
sysctl -p /etc/sysctl.d/99-security-hardening.conf

# Verify applied settings
sysctl -a | grep -E "(ip_forward|accept_redirects|randomize_va_space)"
```

### 2. Phase 2: Network Security

**Step 1: Firewall Configuration**
```bash
# Reset UFW to defaults
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward

# Allow SSH (adjust port if needed)
ufw allow 22/tcp comment "SSH"

# Apply rate limiting to SSH
ufw limit 22/tcp

# Enable firewall
ufw --force enable

# Verify configuration
ufw status verbose
```

**Step 2: SSH Hardening**
```bash
# Backup SSH configuration
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Generate new host keys
rm -f /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -C ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -C ""

# Apply hardened SSH configuration
cp configs/sshd_config /etc/ssh/sshd_config

# Test configuration
sshd -t

# Restart SSH service
systemctl restart sshd
```

### 3. Phase 3: Access Control and Auditing

**Step 1: AppArmor Setup**
```bash
# Install AppArmor
apt install -y apparmor apparmor-profiles apparmor-profiles-extra apparmor-utils

# Enable AppArmor
systemctl enable apparmor
systemctl start apparmor

# Set profiles to enforce mode
find /etc/apparmor.d -name "*" -type f | while read profile; do
    aa-enforce "$profile" 2>/dev/null || true
done

# Verify AppArmor status
aa-status
```

**Step 2: Audit System Configuration**
```bash
# Install audit daemon
apt install -y auditd

# Backup existing configuration
cp /etc/audit/auditd.conf /etc/audit/auditd.conf.backup
cp -r /etc/audit/rules.d /etc/audit/rules.d.backup

# Apply hardened audit configuration
cp configs/auditd.conf /etc/audit/auditd.conf
cp configs/audit.rules /etc/audit/rules.d/audit.rules

# Restart audit daemon
systemctl restart auditd

# Verify audit rules
auditctl -l
```

**Step 3: Intrusion Detection**
```bash
# Install Fail2Ban
apt install -y fail2ban

# Apply custom configuration
cp configs/jail.local /etc/fail2ban/jail.local

# Enable and start Fail2Ban
systemctl enable fail2ban
systemctl restart fail2ban

# Verify jails are active
fail2ban-client status
```

### 4. Phase 4: File Integrity and Logging

**Step 1: AIDE Setup**
```bash
# Install AIDE
apt install -y aide

# Apply configuration
cp configs/aide.conf /etc/aide/aide.conf

# Initialize database (this may take several minutes)
echo "Initializing AIDE database - this may take 10-30 minutes..."
aide --init

# Move database to active location
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Setup daily checks
cp configs/aide-check /etc/cron.daily/aide-check
chmod +x /etc/cron.daily/aide-check
```

**Step 2: Enhanced Logging**
```bash
# Configure log rotation
cp configs/logrotate.conf /etc/logrotate.conf

# Configure rsyslog for security
cp configs/rsyslog-security.conf /etc/rsyslog.d/50-security.conf

# Restart logging services
systemctl restart rsyslog
systemctl restart logrotate
```

---

## Service Configuration Deployment

### 1. Web Server Hardening

**Apache Configuration:**
```bash
# Backup existing configuration
cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.backup

# Apply security configuration
cp configs/apache2-security.conf /etc/apache2/conf-available/security-hardening.conf

# Enable security configuration
a2enconf security-hardening

# Enable required modules
a2enmod headers
a2enmod ssl
a2enmod rewrite

# Test configuration
apache2ctl configtest

# Restart Apache
systemctl restart apache2
```

**NGINX Configuration:**
```bash
# Backup existing configuration
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup

# Apply security configuration
cp configs/nginx-security.conf /etc/nginx/nginx.conf

# Test configuration
nginx -t

# Restart NGINX
systemctl restart nginx
```

### 2. Database Hardening

**MariaDB/MySQL Configuration:**
```bash
# Stop MariaDB service
systemctl stop mariadb

# Backup configuration
cp /etc/mysql/mariadb.conf.d/50-server.cnf /etc/mysql/mariadb.conf.d/50-server.cnf.backup

# Apply security configuration
cp configs/mariadb-security.cnf /etc/mysql/mariadb.conf.d/99-security.cnf

# Start MariaDB
systemctl start mariadb

# Run security script
mysql_secure_installation

# Test connection
mysql -u root -p -e "SELECT VERSION();"
```

**PostgreSQL Configuration:**
```bash
# Stop PostgreSQL
systemctl stop postgresql

# Find PostgreSQL version and config path
PG_VERSION=$(ls /etc/postgresql/)
PG_CONFIG_DIR="/etc/postgresql/$PG_VERSION/main"

# Backup configurations
cp "$PG_CONFIG_DIR/postgresql.conf" "$PG_CONFIG_DIR/postgresql.conf.backup"
cp "$PG_CONFIG_DIR/pg_hba.conf" "$PG_CONFIG_DIR/pg_hba.conf.backup"

# Apply security configuration
cp configs/postgresql-security.conf "$PG_CONFIG_DIR/postgresql.conf"
cp configs/pg_hba.conf "$PG_CONFIG_DIR/pg_hba.conf"

# Start PostgreSQL
systemctl start postgresql

# Test connection
sudo -u postgres psql -c "SELECT version();"
```

### 3. PHP Hardening

```bash
# Find PHP version
PHP_VERSION=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;")

# Backup PHP configurations
cp "/etc/php/$PHP_VERSION/fpm/php.ini" "/etc/php/$PHP_VERSION/fpm/php.ini.backup"
cp "/etc/php/$PHP_VERSION/cli/php.ini" "/etc/php/$PHP_VERSION/cli/php.ini.backup"

# Apply security configuration
cp configs/php-security.ini "/etc/php/$PHP_VERSION/fpm/conf.d/99-security.ini"
cp configs/php-security.ini "/etc/php/$PHP_VERSION/cli/conf.d/99-security.ini"

# Create PHP error log directory
mkdir -p /var/log/php
chown www-data:adm /var/log/php
chmod 750 /var/log/php

# Restart PHP-FPM
systemctl restart "php$PHP_VERSION-fpm"
```

---

## Validation and Testing

### 1. Core Security Validation

**System Hardening Verification:**
```bash
#!/bin/bash
# Security validation script

echo "=== Security Hardening Validation ==="

# Check kernel parameters
echo "Checking kernel parameters..."
if [[ $(sysctl -n net.ipv4.ip_forward) == "0" ]]; then
    echo "✓ IP forwarding disabled"
else
    echo "✗ IP forwarding not disabled"
fi

if [[ $(sysctl -n kernel.randomize_va_space) == "2" ]]; then
    echo "✓ ASLR enabled"
else
    echo "✗ ASLR not properly configured"
fi

# Check firewall status
echo -e "\nChecking firewall..."
if ufw status | grep -q "Status: active"; then
    echo "✓ UFW firewall active"
else
    echo "✗ UFW firewall not active"
fi

# Check SSH configuration
echo -e "\nChecking SSH configuration..."
if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
    echo "✓ Root login disabled"
else
    echo "✗ Root login not disabled"
fi

if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
    echo "✓ Password authentication disabled"
else
    echo "✗ Password authentication not disabled"
fi

# Check services
echo -e "\nChecking security services..."
systemctl is-active --quiet fail2ban && echo "✓ Fail2Ban active" || echo "✗ Fail2Ban not active"
systemctl is-active --quiet auditd && echo "✓ Auditd active" || echo "✗ Auditd not active"
systemctl is-active --quiet apparmor && echo "✓ AppArmor active" || echo "✗ AppArmor not active"

# Check AIDE
echo -e "\nChecking AIDE..."
if [[ -f /var/lib/aide/aide.db ]]; then
    echo "✓ AIDE database exists"
else
    echo "✗ AIDE database not found"
fi
```

### 2. Service Configuration Testing

**Web Server Testing:**
```bash
# Apache security headers test
curl -I http://localhost/ | grep -E "(X-Frame-Options|X-XSS-Protection|X-Content-Type-Options)"

# NGINX security headers test
curl -I http://localhost/ | grep -E "(X-Frame-Options|X-XSS-Protection|X-Content-Type-Options)"

# SSL configuration test (if HTTPS enabled)
nmap --script ssl-enum-ciphers -p 443 localhost
```

**Database Connection Testing:**
```bash
# MariaDB connection test
mysql -u root -p -e "SHOW VARIABLES LIKE 'bind_address';"

# PostgreSQL connection test
sudo -u postgres psql -c "SHOW listen_addresses;"
```

### 3. Security Compliance Testing

**CIS Benchmark Validation:**
```bash
# Use the original script for compliance checking
./sysinfo-security --compliance-check

# Generate compliance report
./sysinfo-security --compliance-check --export /tmp/compliance-report.json --format json
```

**Vulnerability Scanning:**
```bash
# Install and run Lynis for security auditing
apt install -y lynis

# Run comprehensive security audit
lynis audit system

# Check results
less /var/log/lynis.log
```

### 4. Performance Impact Assessment

**System Performance Check:**
```bash
#!/bin/bash
# Performance impact assessment

echo "=== Performance Impact Assessment ==="

# Check system load
echo "System load:"
uptime

# Check memory usage
echo -e "\nMemory usage:"
free -h

# Check disk I/O
echo -e "\nDisk I/O:"
iostat -x 1 3

# Check network connectivity
echo -e "\nNetwork latency:"
ping -c 5 8.8.8.8 | tail -1

# Check service response times
echo -e "\nSSH response time:"
time ssh -o ConnectTimeout=5 localhost exit 2>/dev/null

# Check web server response (if applicable)
if systemctl is-active --quiet apache2 || systemctl is-active --quiet nginx; then
    echo -e "\nWeb server response time:"
    time curl -s -o /dev/null http://localhost/
fi
```

---

## Rollback Procedures

### 1. Emergency Rollback Process

**Immediate System Recovery:**
```bash
#!/bin/bash
# Emergency rollback script

echo "=== Emergency Rollback Process ==="

# Restore system configurations
BACKUP_DIR="/backup/pre-hardening/$(date +%Y%m%d)"

if [[ -d "$BACKUP_DIR" ]]; then
    echo "Restoring system configurations..."
    
    # Restore critical configurations
    tar -xzf "$BACKUP_DIR/system-config-backup.tar.gz" -C /
    
    # Restart critical services
    systemctl restart sshd
    systemctl restart networking
    
    echo "Emergency rollback completed"
else
    echo "Backup directory not found: $BACKUP_DIR"
    echo "Manual recovery required"
fi
```

### 2. Service-Specific Rollback

**SSH Configuration Rollback:**
```bash
# Restore SSH configuration
cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config

# Test configuration
sshd -t

# Restart SSH
systemctl restart sshd
```

**Firewall Rollback:**
```bash
# Disable UFW
ufw --force disable

# Reset to defaults
ufw --force reset

# Allow SSH immediately
ufw allow 22/tcp

# Re-enable with basic rules
ufw --force enable
```

**Kernel Parameters Rollback:**
```bash
# Remove hardening configuration
rm -f /etc/sysctl.d/99-security-hardening.conf

# Restore original sysctl.conf
cp /etc/sysctl.conf.backup /etc/sysctl.conf

# Apply original settings
sysctl -p
```

### 3. Database Rollback

**MariaDB Rollback:**
```bash
# Stop MariaDB
systemctl stop mariadb

# Restore configuration
cp /etc/mysql/mariadb.conf.d/50-server.cnf.backup /etc/mysql/mariadb.conf.d/50-server.cnf
rm -f /etc/mysql/mariadb.conf.d/99-security.cnf

# Start MariaDB
systemctl start mariadb
```

**PostgreSQL Rollback:**
```bash
# Stop PostgreSQL
systemctl stop postgresql

# Restore configurations
PG_VERSION=$(ls /etc/postgresql/)
PG_CONFIG_DIR="/etc/postgresql/$PG_VERSION/main"

cp "$PG_CONFIG_DIR/postgresql.conf.backup" "$PG_CONFIG_DIR/postgresql.conf"
cp "$PG_CONFIG_DIR/pg_hba.conf.backup" "$PG_CONFIG_DIR/pg_hba.conf"

# Start PostgreSQL
systemctl start postgresql
```

---

## Troubleshooting Guide

### 1. Common Issues and Solutions

**SSH Connection Issues:**
```bash
# Problem: Can't connect via SSH after hardening
# Solution 1: Check SSH service status
systemctl status sshd

# Solution 2: Verify SSH configuration
sshd -T

# Solution 3: Check firewall rules
ufw status verbose

# Solution 4: Review SSH logs
journalctl -u sshd -n 50

# Emergency access via console
nano /etc/ssh/sshd_config
# Temporarily enable: PasswordAuthentication yes
systemctl restart sshd
```

**Firewall Blocking Services:**
```bash
# Problem: Services not accessible after firewall enable
# Solution: Check UFW status and rules
ufw status numbered

# Add specific service rules
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 3306/tcp  # MySQL (if remote access needed)

# Check application profiles
ufw app list
ufw allow 'Apache Full'
```

**High System Load:**
```bash
# Problem: System load increased after hardening
# Check audit daemon impact
systemctl status auditd
auditctl -l | wc -l

# Adjust audit rules if needed
nano /etc/audit/rules.d/audit.rules

# Check AppArmor impact
aa-status | grep complain
# Set problematic profiles to complain mode if needed
aa-complain /etc/apparmor.d/profile-name
```

### 2. Log Analysis

**Key Log Locations:**
```bash
# Security hardening logs
/var/log/security-hardening/

# System logs
/var/log/syslog
/var/log/auth.log

# Service-specific logs
/var/log/apache2/error.log
/var/log/nginx/error.log
/var/log/mysql/error.log
/var/log/postgresql/postgresql-*.log

# Security service logs
/var/log/fail2ban.log
/var/log/audit/audit.log
```

**Log Analysis Commands:**
```bash
# Check for authentication failures
grep "authentication failure" /var/log/auth.log

# Check Fail2Ban activity
tail -f /var/log/fail2ban.log

# Check audit events
aureport -au

# Check AppArmor denials
grep DENIED /var/log/syslog

# Check system errors
journalctl -p err -n 50
```

### 3. Performance Optimization

**Audit System Optimization:**
```bash
# Reduce audit rule overhead
# Comment out intensive rules in /etc/audit/rules.d/audit.rules
# Focus on critical security events only

# Adjust buffer sizes
nano /etc/audit/auditd.conf
# Increase: num_logs = 10
# Increase: max_log_file = 100
```

**AppArmor Optimization:**
```bash
# Set learning profiles to complain mode temporarily
aa-complain /etc/apparmor.d/usr.bin.application

# Generate profiles for custom applications
aa-genprof /usr/bin/application

# Fine-tune profiles after learning period
aa-logprof
```

---

## Maintenance and Monitoring

### 1. Daily Maintenance Tasks

**Automated Daily Checks:**
```bash
#!/bin/bash
# Daily security maintenance script
# Place in /etc/cron.daily/security-maintenance

LOG_FILE="/var/log/security-hardening/daily-maintenance.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] Starting daily security maintenance" >> "$LOG_FILE"

# Check for security updates
apt list --upgradable 2>/dev/null | grep -i security >> "$LOG_FILE"

# Check Fail2Ban status
fail2ban-client status >> "$LOG_FILE"

# Check disk space for logs
df -h /var/log >> "$LOG_FILE"

# Verify critical services
systemctl is-active sshd auditd fail2ban apparmor >> "$LOG_FILE"

# Check for AIDE changes (if any)
if [[ -f /var/log/aide/aide-$(date +%Y%m%d).log ]]; then
    if grep -q "changed" /var/log/aide/aide-$(date +%Y%m%d).log; then
        echo "WARNING: AIDE detected file changes" >> "$LOG_FILE"
    fi
fi

echo "[$DATE] Daily security maintenance completed" >> "$LOG_FILE"
```

### 2. Weekly Maintenance Tasks

**Weekly Security Review:**
```bash
#!/bin/bash
# Weekly security review script
# Place in /etc/cron.weekly/security-review

# Generate compliance report
./sysinfo-security --compliance-check --export /var/lib/security-hardening/weekly-compliance.json

# Run Lynis audit
lynis audit system --quiet

# Check for failed login attempts
lastb | head -20

# Review Fail2Ban statistics
fail2ban-client status
for jail in $(fail2ban-client status | grep "Jail list:" | cut -d: -f2 | tr -d '\t' | tr ',' '\n'); do
    fail2ban-client status $jail
done

# Check audit log size and rotation
ls -lh /var/log/audit/

# Generate security summary email
mail -s "Weekly Security Report - $(hostname)" admin@company.com < /var/lib/security-hardening/weekly-compliance.json
```

### 3. Monthly Maintenance Tasks

**Monthly Security Assessment:**
```bash
#!/bin/bash
# Monthly security assessment

# Update CIS benchmark check
./sysinfo-security --compliance-check

# Review and update firewall rules
ufw status numbered

# Check for new AppArmor profiles
apt list --upgradable | grep apparmor-profiles

# Review AIDE configuration and exclusions
aide --config-check

# Analyze authentication logs
journalctl --since "30 days ago" -u sshd | grep "authentication failure" | wc -l

# Check certificate expiration (if using SSL)
openssl x509 -in /etc/ssl/certs/your-cert.pem -noout -dates

# Review system performance metrics
sar -u -q -r -n DEV 1 1
```

### 4. Monitoring and Alerting Setup

**Log Monitoring Script:**
```bash
#!/bin/bash
# Real-time security monitoring
# Run as systemd service for continuous monitoring

ALERT_EMAIL="admin@company.com"

# Monitor auth.log for suspicious activity
tail -F /var/log/auth.log | while read line; do
    # Check for brute force attempts
    if echo "$line" | grep -q "authentication failure"; then
        COUNT=$(grep "authentication failure" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)
        if [[ $COUNT -gt 10 ]]; then
            echo "ALERT: $COUNT authentication failures detected today" | mail -s "Security Alert: Brute Force" $ALERT_EMAIL
        fi
    fi
    
    # Check for privilege escalation attempts
    if echo "$line" | grep -q "sudo.*COMMAND"; then
        echo "INFO: Sudo command executed: $line" >> /var/log/security-hardening/sudo-activity.log
    fi
    
    # Check for new user creation
    if echo "$line" | grep -q "new user"; then
        echo "ALERT: New user created: $line" | mail -s "Security Alert: New User" $ALERT_EMAIL
    fi
done
```

**System Health Monitoring:**
```bash
#!/bin/bash
# System health monitoring for security services
# Run every 5 minutes via cron

SERVICES=("sshd" "fail2ban" "auditd" "apparmor" "ufw")
ALERT_EMAIL="admin@company.com"

for service in "${SERVICES[@]}"; do
    if ! systemctl is-active --quiet "$service"; then
        echo "CRITICAL: Security service $service is not running on $(hostname)" | \
            mail -s "Security Alert: Service Down" $ALERT_EMAIL
        
        # Attempt to restart service
        systemctl restart "$service"
        
        if systemctl is-active --quiet "$service"; then
            echo "INFO: Service $service restarted successfully" | \
                mail -s "Security Info: Service Recovered" $ALERT_EMAIL
        fi
    fi
done

# Check disk space for security logs
DISK_USAGE=$(df /var/log | awk 'NR==2 {print $5}' | sed 's/%//')
if [[ $DISK_USAGE -gt 80 ]]; then
    echo "WARNING: /var/log partition is ${DISK_USAGE}% full" | \
        mail -s "Security Warning: Disk Space" $ALERT_EMAIL
fi
```

---

## Post-Implementation Checklist

### 1. Immediate Post-Implementation (Day 1)

- [ ] **System Accessibility Verified**
  - [ ] SSH access working with new configuration
  - [ ] Console access available
  - [ ] All critical services running

- [ ] **Security Services Active**
  - [ ] UFW firewall enabled and configured
  - [ ] Fail2Ban monitoring active
  - [ ] Audit daemon logging events
  - [ ] AppArmor profiles enforced

- [ ] **Configuration Validation**
  - [ ] SSH configuration tested
  - [ ] Firewall rules verified
  - [ ] Database connections tested
  - [ ] Web services responding

- [ ] **Monitoring Setup**
  - [ ] Log rotation configured
  - [ ] Daily maintenance scripts installed
  - [ ] Alert mechanisms tested

### 2. First Week Follow-up

- [ ] **Security Event Review**
  - [ ] Review Fail2Ban logs for blocked attempts
  - [ ] Check audit logs for security events
  - [ ] Monitor system performance impact

- [ ] **Fine-tuning**
  - [ ] Adjust firewall rules if needed
  - [ ] Optimize audit rules for performance
  - [ ] Configure additional monitoring

- [ ] **Backup Verification**
  - [ ] Test backup procedures
  - [ ] Verify rollback capabilities
  - [ ] Document any issues found

### 3. One Month Review

- [ ] **Compliance Assessment**
  - [ ] Run full compliance check
  - [ ] Generate security metrics report
  - [ ] Review and address any gaps

- [ ] **Performance Analysis**
  - [ ] Analyze system performance trends
  - [ ] Optimize configurations if needed
  - [ ] Plan capacity adjustments

- [ ] **Security Posture Review**
  - [ ] Assess threat landscape changes
  - [ ] Update security policies
  - [ ] Plan next hardening phase

---

## Conclusion

This implementation guide provides comprehensive procedures for deploying enterprise-grade security hardening on Debian systems. Success depends on careful preparation, methodical execution, and continuous monitoring.

**Key Success Factors:**
1. **Thorough Testing:** Always use dry-run mode and test in non-production first
2. **Proper Backup:** Ensure complete system backups before any changes
3. **Gradual Implementation:** Deploy in phases to minimize impact
4. **Continuous Monitoring:** Implement monitoring from day one
5. **Documentation:** Keep detailed records of all changes and configurations

**Support and Resources:**
- Documentation: Keep this guide accessible for reference
- Emergency Contacts: Maintain list of key personnel and vendors
- Rollback Procedures: Ensure all team members understand recovery steps
- Training: Provide team training on new security tools and procedures

---

*Document Version: 2.0*  
*Last Updated: 2025-09-03*  
*Next Review: 2025-12-03*  
*Emergency Contact: security-team@company.com*