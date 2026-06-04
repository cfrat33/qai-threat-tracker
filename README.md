# qai-threat-tracker

Aggregates open-source cyber and geopolitical risk signals on a schedule, computes a weighted threat score with category breakdowns, and publishes static JSON snapshots. These snapshots power a lightweight static website that visualizes real-time threat levels, recent drivers, and short-term trends without requiring a backend server.

## 🌐 Live Dashboard

The threat tracker dashboard is publicly accessible at:
**https://cfrat33.github.io/qai-threat-tracker/**

The dashboard automatically updates hourly with the latest threat intelligence data from:
- **NVD (National Vulnerability Database)** - Recent CVE vulnerabilities
- **CISA KEV** - Known Exploited Vulnerabilities
- **EPSS** - Exploit Prediction Scoring System

## Features

- 📊 Real-time composite threat score (0-100)
- 📈 Category-based threat breakdowns
- 🎯 Top threat events with severity ratings
- 🔄 Automatic hourly data collection
- 🚀 Static site deployment via GitHub Pages

## How It Works

1. **Data Collection**: The `collector.py` script runs hourly via GitHub Actions, fetching threat data from multiple sources
2. **Data Processing**: Events are normalized, scored, and aggregated into `latest.json` and `history_24h.json`
3. **Visualization**: The static `index.html` dashboard loads JSON data and displays interactive threat metrics
4. **Deployment**: GitHub Pages serves the dashboard publicly, with automatic updates on each data refresh

## Local Development

To run the collector locally:

```bash
pip install -r requirements.txt
python scripts/collector.py
```

To view the dashboard locally, simply open `index.html` in a web browser.
