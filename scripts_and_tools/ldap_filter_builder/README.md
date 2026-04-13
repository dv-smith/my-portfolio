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


