# qai-threat-tracker

Aggregates open-source cyber and geopolitical risk signals on a schedule, computes a weighted threat score with category breakdowns, and publishes static JSON snapshots. These snapshots power a lightweight static website that visualizes real-time threat levels, recent drivers, and short-term trends without requiring a backend server.

## Overview

The threat data collector runs hourly via GitHub Actions and aggregates data from:
- **NVD (National Vulnerability Database)**: Recent CVE vulnerabilities and CVSS scores
- **CISA KEV (Known Exploited Vulnerabilities)**: Actively exploited vulnerabilities
- **EPSS (Exploit Prediction Scoring System)**: Probability of exploitation scores

### Threat Scoring

The system computes a composite threat score (0-100) with three category subscores:

- **CVE Severity Score** (30% weight): Based on average CVSS scores from recent CVEs
- **KEV Urgency Score** (50% weight): Based on the number of known exploited vulnerabilities
- **EPSS Probability Score** (20% weight): Based on average exploitation probability

### Output Files

Two JSON files are automatically generated and committed to the repository:

- **`latest.json`**: Current threat data snapshot with scores, top vulnerabilities, and recent KEVs
- **`history_24h.json`**: Rolling 24-hour history of threat scores for trend analysis

These files are:
- Static and cache-safe
- Directly consumable by static front-ends at `/latest.json` and `/history_24h.json`
- Resilient to individual feed failures (partial data is better than no data)

## Usage

### Automatic Collection

The threat data is automatically collected every hour via GitHub Actions workflow (`.github/workflows/collect-threat-data.yml`).

### Manual Collection

To run the collector manually:

```bash
pip install -r requirements.txt
python collector.py
```

### Trigger Manual Workflow

You can manually trigger the workflow from the GitHub Actions tab using the "workflow_dispatch" event.

## JSON Schema

### latest.json

```json
{
  "timestamp": "ISO8601 timestamp",
  "threatScore": {
    "compositeScore": 0-100,
    "categoryScores": {
      "cveSeverity": 0-100,
      "kevUrgency": 0-100,
      "epssProbability": 0-100
    },
    "metadata": {
      "cveCount": 0,
      "kevCount": 0,
      "epssCount": 0
    }
  },
  "topVulnerabilities": [...],
  "recentKEVs": [...],
  "dataStatus": {
    "nvdAvailable": true/false,
    "kevAvailable": true/false,
    "epssAvailable": true/false,
    "errors": [...]
  }
}
```

### history_24h.json

```json
{
  "lastUpdated": "ISO8601 timestamp",
  "entries": [
    {
      "timestamp": "ISO8601 timestamp",
      "compositeScore": 0-100,
      "categoryScores": {...}
    }
  ],
  "entryCount": 0
}
```

## Resilience

The system is designed to be resilient:
- Individual feed failures don't stop the collection
- Partial data is published if at least one source succeeds
- Errors are logged in the `dataStatus.errors` field
- Fallback output is created if all sources fail
