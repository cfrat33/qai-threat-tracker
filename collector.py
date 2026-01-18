#!/usr/bin/env python3
"""
Threat Data Collector
Aggregates cyber threat data from NVD, KEV, and EPSS sources,
computes composite threat scores, and outputs JSON files.
"""

import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import requests


# Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
REQUEST_TIMEOUT = 30
MAX_NVD_RESULTS = 100
MAX_EPSS_ENTRIES = 1000
KEV_NORMALIZATION_FACTOR = 10.0  # Normalize KEV count to 0-100 scale


class ThreatDataCollector:
    """Collects and processes threat data from multiple sources."""
    
    def __init__(self):
        self.nvd_data: List[Dict] = []
        self.kev_data: List[Dict] = []
        self.epss_data: Dict[str, float] = {}
        self.errors: List[str] = []
        
    def fetch_nvd_recent_cves(self) -> bool:
        """Fetch recent CVEs from NVD API."""
        try:
            print("Fetching NVD data...")
            params = {
                "resultsPerPage": MAX_NVD_RESULTS,
                "startIndex": 0
            }
            
            response = requests.get(NVD_API_URL, params=params, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")
                
                # Extract metrics
                metrics = cve_data.get("metrics", {})
                cvss_v3_list = metrics.get("cvssMetricV31", [])
                cvss_v2_list = metrics.get("cvssMetricV2", [])
                
                cvss_v3 = cvss_v3_list[0] if cvss_v3_list else {}
                cvss_v2 = cvss_v2_list[0] if cvss_v2_list else {}
                
                base_score = 0.0
                if cvss_v3:
                    base_score = cvss_v3.get("cvssData", {}).get("baseScore", 0.0)
                elif cvss_v2:
                    base_score = cvss_v2.get("cvssData", {}).get("baseScore", 0.0)
                
                self.nvd_data.append({
                    "id": cve_id,
                    "baseScore": base_score,
                    "published": cve_data.get("published", "")
                })
            
            print(f"Fetched {len(self.nvd_data)} CVEs from NVD")
            return True
            
        except Exception as e:
            error_msg = f"NVD fetch failed: {str(e)}"
            print(error_msg, file=sys.stderr)
            self.errors.append(error_msg)
            return False
    
    def fetch_kev_data(self) -> bool:
        """Fetch Known Exploited Vulnerabilities from CISA."""
        try:
            print("Fetching KEV data...")
            response = requests.get(KEV_API_URL, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            for vuln in vulnerabilities:
                self.kev_data.append({
                    "cveID": vuln.get("cveID", ""),
                    "vendorProject": vuln.get("vendorProject", ""),
                    "product": vuln.get("product", ""),
                    "dateAdded": vuln.get("dateAdded", "")
                })
            
            print(f"Fetched {len(self.kev_data)} KEV entries")
            return True
            
        except Exception as e:
            error_msg = f"KEV fetch failed: {str(e)}"
            print(error_msg, file=sys.stderr)
            self.errors.append(error_msg)
            return False
    
    def fetch_epss_data(self) -> bool:
        """Fetch EPSS scores for recent vulnerabilities."""
        try:
            print("Fetching EPSS data...")
            
            # Get EPSS scores for top CVEs
            response = requests.get(EPSS_API_URL, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            
            data = response.json()
            epss_entries = data.get("data", [])
            
            for entry in epss_entries[:MAX_EPSS_ENTRIES]:
                cve_id = entry.get("cve", "")
                epss_score = float(entry.get("epss", 0.0))
                self.epss_data[cve_id] = epss_score
            
            print(f"Fetched EPSS data for {len(self.epss_data)} CVEs")
            return True
            
        except Exception as e:
            error_msg = f"EPSS fetch failed: {str(e)}"
            print(error_msg, file=sys.stderr)
            self.errors.append(error_msg)
            return False
    
    def compute_threat_score(self) -> Dict[str, Any]:
        """Compute composite threat score and category subscores."""
        
        # Category subscores
        cve_severity_score = 0.0
        kev_urgency_score = 0.0
        epss_probability_score = 0.0
        
        # CVE Severity Score (0-100 based on CVSS scores)
        if self.nvd_data:
            avg_cvss = sum(cve["baseScore"] for cve in self.nvd_data) / len(self.nvd_data)
            cve_severity_score = (avg_cvss / 10.0) * 100
        
        # KEV Urgency Score (0-100 based on number of KEV entries)
        # More KEVs = higher urgency
        kev_count = len(self.kev_data)
        kev_urgency_score = min(100, (kev_count / KEV_NORMALIZATION_FACTOR) * 100)
        
        # EPSS Probability Score (0-100 based on average EPSS)
        if self.epss_data:
            avg_epss = sum(self.epss_data.values()) / len(self.epss_data)
            epss_probability_score = avg_epss * 100
        
        # Composite Score (weighted average)
        # Weights: CVE=30%, KEV=50%, EPSS=20%
        composite_score = (
            cve_severity_score * 0.3 +
            kev_urgency_score * 0.5 +
            epss_probability_score * 0.2
        )
        
        return {
            "compositeScore": round(composite_score, 2),
            "categoryScores": {
                "cveSeverity": round(cve_severity_score, 2),
                "kevUrgency": round(kev_urgency_score, 2),
                "epssProbability": round(epss_probability_score, 2)
            },
            "metadata": {
                "cveCount": len(self.nvd_data),
                "kevCount": len(self.kev_data),
                "epssCount": len(self.epss_data)
            }
        }
    
    def generate_latest_json(self, output_path: str = "latest.json"):
        """Generate latest.json with current threat data."""
        timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        
        threat_score = self.compute_threat_score()
        
        # Get top 10 recent CVEs
        top_cves = sorted(self.nvd_data, key=lambda x: x["baseScore"], reverse=True)[:10]
        
        # Get recent KEV entries (last 10), sorted by dateAdded
        # Filter out entries with invalid dates
        valid_kevs = [kev for kev in self.kev_data if kev.get("dateAdded")]
        recent_kevs = sorted(valid_kevs, key=lambda x: x["dateAdded"], reverse=True)[:10]
        
        latest_data = {
            "timestamp": timestamp,
            "threatScore": threat_score,
            "topVulnerabilities": top_cves,
            "recentKEVs": recent_kevs,
            "dataStatus": {
                "nvdAvailable": len(self.nvd_data) > 0,
                "kevAvailable": len(self.kev_data) > 0,
                "epssAvailable": len(self.epss_data) > 0,
                "errors": self.errors
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(latest_data, f, indent=2)
        
        print(f"Generated {output_path}")
        return latest_data
    
    def update_history_json(self, latest_data: Dict, history_path: str = "history_24h.json"):
        """Update or create history_24h.json with rolling 24-hour data."""
        
        # Load existing history
        history_entries = []
        if os.path.exists(history_path):
            try:
                with open(history_path, 'r') as f:
                    history_data = json.load(f)
                    history_entries = history_data.get("entries", [])
            except Exception as e:
                print(f"Could not load existing history: {e}", file=sys.stderr)
        
        # Add current entry
        current_entry = {
            "timestamp": latest_data["timestamp"],
            "compositeScore": latest_data["threatScore"]["compositeScore"],
            "categoryScores": latest_data["threatScore"]["categoryScores"]
        }
        history_entries.append(current_entry)
        
        # Filter to keep only last 24 hours of entries
        cutoff_time = datetime.now(timezone.utc)
        filtered_entries = []
        for entry in history_entries:
            try:
                # Handle both 'Z' and '+00:00' timezone formats
                timestamp_str = entry["timestamp"].replace('Z', '+00:00')
                entry_time = datetime.fromisoformat(timestamp_str)
                hours_diff = (cutoff_time - entry_time).total_seconds() / 3600
                if hours_diff <= 24:
                    filtered_entries.append(entry)
            except (ValueError, KeyError) as e:
                print(f"Skipping invalid history entry: {e}", file=sys.stderr)
        
        history_data = {
            "lastUpdated": latest_data["timestamp"],
            "entries": filtered_entries,
            "entryCount": len(filtered_entries)
        }
        
        with open(history_path, 'w') as f:
            json.dump(history_data, f, indent=2)
        
        print(f"Updated {history_path} with {len(filtered_entries)} entries")
    
    def run(self):
        """Execute the full data collection and processing pipeline."""
        print("=== Starting Threat Data Collection ===")
        print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
        
        # Fetch data from all sources (resilient to individual failures)
        nvd_success = self.fetch_nvd_recent_cves()
        kev_success = self.fetch_kev_data()
        epss_success = self.fetch_epss_data()
        
        # Log results
        print(f"Data collection results: NVD={nvd_success}, KEV={kev_success}, EPSS={epss_success}")
        
        # Check if we have at least some data from any source
        # This makes the system resilient to individual feed failures
        has_data = bool(self.nvd_data or self.kev_data or self.epss_data)
        
        if not has_data:
            print("ERROR: Failed to fetch data from all sources", file=sys.stderr)
            # Create minimal output even on total failure
            self._create_fallback_output()
            return
        
        # Generate outputs
        latest_data = self.generate_latest_json()
        self.update_history_json(latest_data)
        
        print("=== Collection Complete ===")
        if self.errors:
            print(f"Completed with {len(self.errors)} errors:")
            for error in self.errors:
                print(f"  - {error}")
        else:
            print("All sources processed successfully")
    
    def _create_fallback_output(self):
        """Create minimal fallback output when all sources fail."""
        timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        fallback_data = {
            "timestamp": timestamp,
            "threatScore": {
                "compositeScore": 0.0,
                "categoryScores": {
                    "cveSeverity": 0.0,
                    "kevUrgency": 0.0,
                    "epssProbability": 0.0
                },
                "metadata": {
                    "cveCount": 0,
                    "kevCount": 0,
                    "epssCount": 0
                }
            },
            "topVulnerabilities": [],
            "recentKEVs": [],
            "dataStatus": {
                "nvdAvailable": False,
                "kevAvailable": False,
                "epssAvailable": False,
                "errors": self.errors
            }
        }
        
        with open("latest.json", 'w') as f:
            json.dump(fallback_data, f, indent=2)
        
        print("Created fallback latest.json")


def main():
    """Main entry point."""
    collector = ThreatDataCollector()
    collector.run()


if __name__ == "__main__":
    main()
