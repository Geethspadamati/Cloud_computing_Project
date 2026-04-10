# Attack Simulation Summary

## Environment Setup
- Target EC2: 3.144.240.191
- Attacker EC2: 18.221.229.40
- Database: MySQL (RDS)

## Vulnerable Application
- Flask app running on port 5000
- Endpoints:
  - /login
  - /search

## Attack Performed
- Tool used: SQLMap
- Type: SQL Injection (Union-based)

## Command Used
python3 sqlmap.py -u "http://3.144.240.191:5000/search?name=test" --batch --dump

## Data Extracted
- Full user records
- Emails
- SSN
- Credit card numbers

## Impact
Sensitive user data was successfully extracted due to lack of input validation and unsafe SQL queries.
