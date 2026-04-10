# Attack Playbook

## SQL Injection Overview
SQL Injection is a vulnerability where attackers insert malicious SQL code into input fields to manipulate the database.

## Why It Happens
- No input validation
- Direct string concatenation in queries

## Attack Type Used
- Union-based SQL Injection

## How It Worked
- The `/search` endpoint directly used user input in SQL query
- SQLMap exploited this and extracted full database data

## Data Exposed
- Usernames
- Emails
- SSN
- Credit card numbers

## Risk
- Complete data breach
- Loss of confidentiality
- Potential financial fraud

## Prevention
- Use parameterized queries
- Validate user input
- Use ORM frameworks
