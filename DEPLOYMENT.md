# QAI Threat Tracker Deployment Guide

## Overview
This guide covers deploying the QAI Threat Tracker to Turbobuilt (or any static hosting service).

## Prerequisites
- GitHub repository with the threat tracker code
- Turbobuilt account (or alternative static host)
- (Optional) NVD API key for authenticated requests

## Deployment Steps

### 1. Configure GitHub Secrets (Optional but Recommended)

For better rate limits and reliability, add your NVD API key:

1. Go to your GitHub repository
2. Navigate to Settings > Secrets and variables > Actions
3. Click "New repository secret"
4. Name: `NVD_API_KEY`
5. Value: Your NVD API key from https://nvd.nist.gov/developers/request-an-api-key

### 2. Verify GitHub Actions Workflow

The workflow runs hourly and commits JSON updates to the repository.

Check that:
- `.github/workflows/collect-threat-data.yml` exists
- Workflow has `contents: write` permission
- Workflow is enabled in repository settings

Manual trigger:
1. Go to Actions tab in GitHub
2. Select "Threat Data Collection" workflow
3. Click "Run workflow"

### 3. Configure Turbobuilt Deployment

#### Option A: Turbobuilt Serving Repo Root

Configure your Turbobuilt project to:
- **Source**: Connect to your GitHub repository
- **Branch**: `main` (or your default branch)
- **Root Directory**: `/` (repository root)
- **Build Command**: None (static files)
- **Output Directory**: `/` (serve from root)

This ensures these URLs work:
- `https://qai.turbobuilt.com/` → index.html
- `https://qai.turbobuilt.com/latest.json` → latest.json
- `https://qai.turbobuilt.com/history_24h.json` → history_24h.json

#### Option B: GitHub Pages Fallback

If Turbobuilt can't serve repo root reliably:

1. Enable GitHub Pages in repository settings
2. Source: Deploy from branch (main)
3. Folder: / (root)
4. Your JSONs will be available at:
   - `https://[username].github.io/qai-threat-tracker/latest.json`
   - `https://[username].github.io/qai-threat-tracker/history_24h.json`

5. Update `index.html` to use full GitHub Pages URLs:
```javascript
const latestResponse = await fetch('https://[username].github.io/qai-threat-tracker/latest.json?t=' + Date.now());
```

### 4. Verify Deployment

#### Smoke Test Checklist

1. **Repository files present:**
   ```bash
   # Check your repo root contains:
   - index.html
   - latest.json
   - history_24h.json
   - collector.py
   - requirements.txt
   - .github/workflows/collect-threat-data.yml
   ```

2. **GitHub Actions running:**
   - Go to Actions tab
   - Verify workflow runs successfully
   - Check commit history for automated JSON updates

3. **JSON endpoints accessible:**
   ```bash
   curl https://qai.turbobuilt.com/latest.json
   curl https://qai.turbobuilt.com/history_24h.json
   ```
   Both should return JSON (not 404)

4. **Front-end loads:**
   - Visit https://qai.turbobuilt.com/
   - Status strip shows feed availability (✅ or ❌)
   - Composite score displays
   - Timestamp renders correctly
   - Category scores visible
   - Top CVEs and Recent KEVs populate

5. **Hard refresh works:**
   - Press Ctrl+Shift+R (or Cmd+Shift+R on Mac)
   - Page reloads without errors
   - Data persists

### 5. Troubleshooting

#### JSON files return 404

**Cause:** Turbobuilt not configured to serve repo root

**Solutions:**
1. Check Turbobuilt "Output Directory" setting is `/` not `/dist` or `/public`
2. Verify GitHub Actions is committing JSON files (check recent commits)
3. Try GitHub Pages fallback (see Option B above)

#### Workflow fails with API errors

**Cause:** Rate limiting or network restrictions

**Solutions:**
1. Add NVD_API_KEY secret for higher rate limits
2. The system is resilient - partial failures are OK
3. Check workflow logs for specific errors

#### Scores show as 0

**Cause:** All data sources failed

**Solutions:**
1. Check `dataStatus` in latest.json for errors
2. View errors dropdown in UI
3. Verify network connectivity from GitHub Actions runners
4. Wait for next hourly run

#### Front-end doesn't update

**Cause:** Browser cache

**Solutions:**
1. Hard refresh (Ctrl+Shift+R)
2. Add cache-busting timestamp to fetch URLs (already included)
3. Check browser console for fetch errors

### 6. Schema Compatibility

The front-end supports both schemas:

**New schema (current):**
```json
{
  "threatScore": {
    "compositeScore": 42.5,
    "categoryScores": {
      "cveSeverity": 35.2,
      "kevUrgency": 48.0,
      "epssProbability": 45.1
    }
  }
}
```

**Legacy schema (fallback):**
```json
{
  "overall_score": 42,
  "category_scores": {
    "cve_severity": 35,
    "kev_urgency": 48,
    "epss_probability": 45
  }
}
```

### 7. Monitoring

- Check GitHub Actions tab for workflow runs
- Monitor commit history for JSON updates
- Watch for errors in dataStatus.errors array
- Set up notifications for workflow failures (optional)

### 8. Future Enhancements

As mentioned in requirements:
1. **Novelty/recency decay**: Weight recent threats higher
2. **CVE deduplication**: Cap repeated CVEs
3. **Corroboration gates**: Require multiple sources for critical alerts
4. **Historical comparisons**: Add week/month trends

## Support

For issues with:
- **Collector script**: Check Python logs in Actions
- **JSON format**: Validate against schema
- **Front-end**: Check browser console
- **Deployment**: Verify Turbobuilt settings or use GitHub Pages
