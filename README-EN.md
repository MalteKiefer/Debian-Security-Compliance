# Debian Security Compliance Checker

A comprehensive security assessment tool for Debian and Ubuntu systems that provides detailed analysis without making any system modifications.

## Features

- **Multi-Framework Compliance**: CIS Level 1/2, ISO 27001, SOC 2, BSI IT-Grundschutz
- **Vulnerability Scanning**: Uses official `debsecan` database for CVE detection
- **Debian & Ubuntu Support**: Automatic distribution and version detection
- **Comprehensive Reporting**: Text, JSON, and executive summaries
- **Analysis Only**: No system modifications - pure assessment tool
- **Automatic Updates**: Built-in version checking and update notifications

## Quick Start

### Prerequisites

- Debian or Ubuntu system
- `dpkg` package manager
- Root privileges (recommended for complete analysis)
- Internet connection (for vulnerability database updates)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/MalteKiefer/Debian-Security-Compliance.git
cd Debian-Security-Compliance
```

2. Make the script executable:
```bash
chmod +x debian-security-compliance.sh
```

3. Run a quick assessment:
```bash
sudo ./debian-security-compliance.sh --quick
```

## Usage

### Basic Commands

```bash
# Quick dashboard overview (2 minutes)
sudo ./debian-security-compliance.sh --quick

# Full compliance assessment (10 minutes)  
sudo ./debian-security-compliance.sh --compliance

# Comprehensive security audit (15 minutes)
sudo ./debian-security-compliance.sh --audit

# Vulnerability scan of all packages
sudo ./debian-security-compliance.sh --vulnerabilities

# Complete analysis (recommended)
sudo ./debian-security-compliance.sh --all
```

### Advanced Options

```bash
# Performance impact analysis
sudo ./debian-security-compliance.sh --performance

# Generate JSON reports for automation
sudo ./debian-security-compliance.sh --json

# Gap analysis for action planning
sudo ./debian-security-compliance.sh --gaps

# Executive management summary
sudo ./debian-security-compliance.sh --management

# Version check and update notification
./debian-security-compliance.sh --version

# Show help
./debian-security-compliance.sh --help
```

## License

This project is licensed under the MIT License.

## Support

- **Issues**: [GitHub Issues](https://github.com/MalteKiefer/Debian-Security-Compliance/issues)
- **Documentation**: [Wiki](https://github.com/MalteKiefer/Debian-Security-Compliance/wiki)

## Changelog

### Version 2.0.0
- Complete English translation
- Added automatic version checking
- Enhanced vulnerability scanning with debsecan
- Improved multi-distribution support
- Added JSON automation support
- Comprehensive reporting system