# Assignment – OpenAPI Security Analyzer (Guard0 Security)

This project is a **static security analysis tool for OpenAPI (Swagger) specifications**, developed as part of the **Guard0 Security interview assignment**.

The tool parses OpenAPI v2 and v3 specifications, validates their structure, detects common API security issues, and produces a **security score** with actionable recommendations.

---

## Problem Statement

Build a system that:
- Accepts OpenAPI specifications as input
- Validates the correctness of the specification
- Identifies security misconfigurations and bad practices
- Reports findings with severity and remediation guidance

---

## Features

- Supports **OpenAPI v2 (Swagger 2.0)** and **OpenAPI v3**
- Input methods:
  - Raw OpenAPI text
  - File upload (`.yaml`, `.yml`, `.json`)
  - URL-based OpenAPI spec fetching
- Rule-based security checks
- Severity-based scoring system (0–100)
- Grouped findings by rule ID
- Interactive Swagger UI for easy testing

---

## Tech Stack

- Python 3.9+
- FastAPI
- Uvicorn
- PyYAML
- Requests

---

## Project Structure

