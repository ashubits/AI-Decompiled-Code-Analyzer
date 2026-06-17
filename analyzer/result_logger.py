# ----------------------------------------------------------------------
# File: analyzer/result_logger.py
# Description: Logs analysis results to CSV and pushes to GitHub
# ----------------------------------------------------------------------
import os
import csv
import re
import base64
import requests
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# GitHub sync has been removed

# Local CSV file
LOCAL_CSV_PATH = 'analysis_results.csv'

class ResultLogger:
    """Handles logging of analysis results to CSV and GitHub."""

    def __init__(self):
        self.ensure_csv_exists()

    def ensure_csv_exists(self):
        """Create CSV file with headers if it doesn't exist."""
        if not os.path.exists(LOCAL_CSV_PATH):
            with open(LOCAL_CSV_PATH, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Filename', 'Verdict', 'Malicious_Artifacts', 'Family_Name', 'Risk_Score'])
            print(f"Created new CSV file: {LOCAL_CSV_PATH}")

    def extract_verdict(self, final_analysis_text):
        """Extract verdict from final analysis text."""
        # Look for "Final Verdict:" section
        verdict_match = re.search(
            r'(?:Final Verdict|VERDICT)[:\s]+(MALWARE|LEGITIMATE|SUSPICIOUS|CLEAN)',
            final_analysis_text,
            re.IGNORECASE | re.MULTILINE
        )

        if verdict_match:
            return verdict_match.group(1).upper()

        # Fallback: search for keywords
        if 'malware' in final_analysis_text.lower():
            return 'MALWARE'
        elif 'suspicious' in final_analysis_text.lower():
            return 'SUSPICIOUS'
        elif 'legitimate' in final_analysis_text.lower() or 'clean' in final_analysis_text.lower():
            return 'LEGITIMATE'

        return 'UNKNOWN'

    def extract_artifacts(self, final_analysis_text):
        """Extract malicious artifacts from final analysis text."""
        artifacts = []

        # Look for "Malicious Artifacts" section
        artifacts_section = re.search(
            r'(?:Malicious Artifacts|MALICIOUS ARTIFACTS)[:\s]*([^*\n][^\n]*(?:\n[^*\n][^\n]*)*)',
            final_analysis_text,
            re.IGNORECASE | re.MULTILINE
        )

        if artifacts_section:
            artifacts_text = artifacts_section.group(1)
            # Extract bullet points or individual indicators
            lines = artifacts_text.split('\n')
            for line in lines:
                line = line.strip()
                # Remove bullets and numbering
                line = re.sub(r'^[-•*]\s*', '', line)
                line = re.sub(r'^\d+\.\s*', '', line)
                if line and len(line) > 3:
                    artifacts.append(line)

        # If no artifacts found, search for common malware indicators
        if not artifacts:
            indicators = [
                'registry_modification', 'process_injection', 'file_encryption',
                'c2_communication', 'credential_theft', 'privilege_escalation',
                'persistence', 'lateral_movement', 'data_exfiltration',
                'command_execution', 'dll_injection', 'rootkit'
            ]
            for indicator in indicators:
                if indicator.replace('_', ' ') in final_analysis_text.lower():
                    artifacts.append(indicator)

        return '|'.join(artifacts) if artifacts else 'none'

    def extract_family(self, final_analysis_text):
        """Extract malware family name from analysis text."""
        # Common malware families
        families = [
            'Trojan', 'Ransomware', 'Worm', 'Virus', 'Backdoor', 'Downloader',
            'Spyware', 'Adware', 'Keylogger', 'Bot', 'Rootkit', 'Exploit',
            'PUA', 'Generic', 'Conti', 'Emotet', 'Mirai', 'Wannacry',
            'Petya', 'NotPetya', 'Cryptolocker', 'Zeus', 'Conficker'
        ]

        for family in families:
            # Look for exact family mentions
            pattern = rf'\b{family}(?:\.\w+)*\b'
            match = re.search(pattern, final_analysis_text, re.IGNORECASE)
            if match:
                return match.group(0)

        # If no specific family found, derive from verdict
        verdict = self.extract_verdict(final_analysis_text)
        if verdict == 'MALWARE':
            return 'Generic.Malware'
        elif verdict == 'SUSPICIOUS':
            return 'Suspicious.Generic'

        return 'N/A'

