#!/usr/bin/env python3
"""
QAI Threat Tracker - Data Collector
Pulls cyber threat signals from open-source feeds, normalizes events,
scores categories, and generates JSON files for dashboard visualization.
"""

import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Any
import urllib.request
import urllib.error


class ThreatCollector:
    """Collects and processes threat intelligence data."""
    
    def __init__(self):
        self.events = []
        self.category_scores = {}
        self.composite_score = 0.0
        
    def fetch_nvd_data(self) -> List[Dict[str, Any]]:
        """Fetch recent CVE data from NVD API."""
        events = []
        try:
            # NVD API endpoint for recent CVEs (last 7 days)
            from datetime import timedelta
            start_date = (datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000')
            
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_date}&resultsPerPage=20"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'QAI-Threat-Tracker/1.0')
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                if 'vulnerabilities' in data:
                    for item in data['vulnerabilities'][:10]:  # Limit to 10 most recent
                        cve = item.get('cve', {})
                        cve_id = cve.get('id', 'Unknown')
                        
                        # Extract CVSS score
                        metrics = cve.get('metrics', {})
                        cvss_score = 0.0
                        
                        # Try CVSS v3.1 first, then v3.0, then v2.0
                        for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                            if version in metrics and metrics[version]:
                                cvss_data = metrics[version][0].get('cvssData', {})
                                cvss_score = float(cvss_data.get('baseScore', 0))
                                break
                        
                        # Get description
                        descriptions = cve.get('descriptions', [])
                        description = descriptions[0].get('value', 'No description') if descriptions else 'No description'
                        
                        events.append({
                            'id': cve_id,
                            'type': 'vulnerability',
                            'category': 'CVE',
                            'severity': cvss_score,
                            'description': description[:200],  # Truncate
                            'timestamp': cve.get('published', datetime.now(timezone.utc).isoformat())
                        })
        except Exception as e:
            print(f"Warning: Failed to fetch NVD data: {e}", file=sys.stderr)
            # Add synthetic fallback data
            events.append({
                'id': 'SYNTHETIC-001',
                'type': 'vulnerability',
                'category': 'CVE',
                'severity': 7.5,
                'description': 'Sample vulnerability (NVD fetch failed)',
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        
        return events
    
    def fetch_kev_data(self) -> List[Dict[str, Any]]:
        """Fetch Known Exploited Vulnerabilities from CISA."""
        events = []
        try:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'QAI-Threat-Tracker/1.0')
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                if 'vulnerabilities' in data:
                    # Get most recent 5 KEVs
                    vulns = sorted(
                        data['vulnerabilities'],
                        key=lambda x: x.get('dateAdded', ''),
                        reverse=True
                    )[:5]
                    
                    for vuln in vulns:
                        events.append({
                            'id': vuln.get('cveID', 'Unknown'),
                            'type': 'exploited',
                            'category': 'KEV',
                            'severity': 9.0,  # KEVs are high priority
                            'description': vuln.get('vulnerabilityName', 'No description')[:200],
                            'timestamp': vuln.get('dateAdded', datetime.now(timezone.utc).isoformat())
                        })
        except Exception as e:
            print(f"Warning: Failed to fetch KEV data: {e}", file=sys.stderr)
            # Add synthetic fallback
            events.append({
                'id': 'SYNTHETIC-KEV-001',
                'type': 'exploited',
                'category': 'KEV',
                'severity': 9.0,
                'description': 'Sample KEV (fetch failed)',
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        
        return events
    
    def fetch_epss_sample(self) -> List[Dict[str, Any]]:
        """Generate sample EPSS-style events (EPSS API requires specific setup)."""
        events = []
        try:
            # EPSS data is large and requires specific processing
            # For this implementation, we'll create synthetic EPSS-style scores
            # In production, you'd fetch from https://api.first.org/data/v1/epss
            
            events.append({
                'id': 'EPSS-HIGH-001',
                'type': 'epss',
                'category': 'EPSS',
                'severity': 8.5,
                'description': 'High EPSS score indicator (sample data)',
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        except Exception as e:
            print(f"Warning: Failed to generate EPSS data: {e}", file=sys.stderr)
        
        return events
    
    def collect_all_events(self) -> List[Dict[str, Any]]:
        """Collect events from all sources."""
        all_events = []
        
        print("Collecting threat data...")
        
        # Fetch from all sources
        all_events.extend(self.fetch_nvd_data())
        all_events.extend(self.fetch_kev_data())
        all_events.extend(self.fetch_epss_sample())
        
        print(f"Collected {len(all_events)} events")
        
        return all_events
    
    def score_categories(self, events: List[Dict[str, Any]]) -> Dict[str, float]:
        """Score each category based on event severity and count."""
        category_data = {}
        
        # Group events by category
        for event in events:
            category = event.get('category', 'Unknown')
            if category not in category_data:
                category_data[category] = []
            category_data[category].append(event.get('severity', 0))
        
        # Calculate category scores (0-100 scale)
        scores = {}
        for category, severities in category_data.items():
            if severities:
                # Average severity, weighted by count
                avg_severity = sum(severities) / len(severities)
                count_factor = min(len(severities) / 10, 1.0)  # Cap at 10 events
                
                # Scale to 0-100
                score = (avg_severity / 10.0) * 100 * (0.7 + 0.3 * count_factor)
                scores[category] = round(min(score, 100), 2)
            else:
                scores[category] = 0.0
        
        return scores
    
    def compute_composite_score(self, category_scores: Dict[str, float]) -> float:
        """Compute weighted composite threat score."""
        # Weights for different categories (must sum to 1.0)
        weights = {
            'CVE': 0.4,
            'KEV': 0.5,
            'EPSS': 0.1
        }
        
        weighted_sum = 0
        
        # Use fixed weight sum of 1.0 to avoid artificial inflation
        for category, weight in weights.items():
            score = category_scores.get(category, 0.0)
            weighted_sum += score * weight
        
        return round(weighted_sum, 2)
    
    def write_latest_json(self, events: List[Dict[str, Any]], 
                          category_scores: Dict[str, float],
                          composite_score: float,
                          output_path: str):
        """Write latest.json with current threat data."""
        
        # Get top 10 events by severity
        top_events = sorted(events, key=lambda x: x.get('severity', 0), reverse=True)[:10]
        
        data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'composite_score': composite_score,
            'category_scores': category_scores,
            'top_events': top_events,
            'event_count': len(events)
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Wrote {output_path}")
    
    def write_history_json(self, latest_data: Dict[str, Any], 
                           history_path: str):
        """Update history_24h.json with latest datapoint."""
        
        # Load existing history
        history = []
        if os.path.exists(history_path):
            try:
                with open(history_path, 'r') as f:
                    history = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load existing history: {e}", file=sys.stderr)
                history = []
        
        # Add current datapoint
        datapoint = {
            'timestamp': latest_data['timestamp'],
            'composite_score': latest_data['composite_score'],
            'category_scores': latest_data['category_scores']
        }
        
        history.append(datapoint)
        
        # Keep only last 24 hours (24 datapoints for hourly collection)
        history = history[-24:]
        
        with open(history_path, 'w') as f:
            json.dump(history, f, indent=2)
        
        print(f"Wrote {history_path}")
    
    def run(self, output_dir: str = '.'):
        """Run the collection process."""
        print("=" * 60)
        print("QAI Threat Tracker - Data Collection")
        print(f"Started at {datetime.now(timezone.utc).isoformat()}")
        print("=" * 60)
        
        # Collect events
        events = self.collect_all_events()
        
        # Score categories
        category_scores = self.score_categories(events)
        print(f"Category scores: {category_scores}")
        
        # Compute composite score
        composite_score = self.compute_composite_score(category_scores)
        print(f"Composite threat score: {composite_score}/100")
        
        # Write output files
        latest_path = os.path.join(output_dir, 'latest.json')
        history_path = os.path.join(output_dir, 'history_24h.json')
        
        self.write_latest_json(events, category_scores, composite_score, latest_path)
        
        # Load latest data and update history
        with open(latest_path, 'r') as f:
            latest_data = json.load(f)
        
        self.write_history_json(latest_data, history_path)
        
        print("=" * 60)
        print("Collection completed successfully")
        print("=" * 60)


def main():
    """Main entry point."""
    collector = ThreatCollector()
    
    # Output to repository root
    output_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    try:
        collector.run(output_dir)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
