# AD LDAP Filter Builder

A simple browser-based tool for building LDAP filters for Active Directory enumeration during penetration tests.

## What it does

Generates LDAP filters and ready-to-use commands for:
- PowerShell (Get-ADObject)
- Python (ldap3)
- dsquery
- ldapsearch
- BloodHound Cypher queries

## Features

- Pre-built filters for common attacks (Kerberoasting, AS-REP roasting, delegation abuse)
- UAC flag calculator
- Time-based filters (stale accounts, old passwords)
- Save/load custom presets
- Dark/light theme

## Usage

**Live tool**: [https://dv-smith.github.io/your-repo-name/](https://dv-smith.github.io/your-repo-name/)

Or download `index.html` and open in any browser. No dependencies needed.

## Disclaimer

For authorized penetration testing only. Get written permission before testing any systems you don't own.

## Development

Built with AI assistance as part of my penetration testing portfolio. Single HTML file for easy deployment.

## License

MIT
