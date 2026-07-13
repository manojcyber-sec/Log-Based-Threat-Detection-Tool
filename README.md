# Log-Based Threat Detection Tool

A Python-based log analysis tool that detects common authentication attack patterns such as brute force attacks, credential stuffing, and possible account compromise.

## Features
- Parses authentication logs
- Detects brute force attempts using time-based analysis
- Detects credential stuffing from a single IP
- Identifies possible account compromise by correlating failed and successful logins
- Generates structured alert reports

## Technologies Used
- Python
- Log Analysis
- Cybersecurity
- Incident Response

## Folder Structure
- `logs/` – sample input logs
- `reports/` – generated alert reports
- `screenshots/` – output screenshots
- `src/` – source code

## How to Run
1. Clone the repository
2. Open the `src` folder
3. Run the main Python file

## Project Outcome
This project helped me understand how SOC analysts identify suspicious authentication behavior from logs and turn raw events into actionable alerts.
