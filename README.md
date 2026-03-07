# Wazuh IP Enrichment Pipeline

Real-time IP enrichment pipeline integrating Wazuh SIEM with AbuseIPDB for automated IP reputation enrichment and malicious inbound/outbound connection alerting.

## How it works

1. UniFi UDM Pro forwards firewall logs to Wazuh via syslog
2. Wazuh rule 100010 triggers the integration on firewall events
3. Python script queries AbuseIPDB for IP reputation data
4. Contains a local cache file to only query public IPs once every 24 hours
5. Enriched alert sent back to Wazuh with risk scoring
6. Custom rules fire on HIGH/CRITICAL outbound connections

## Files

- `custom-ip-enrichment.py` - Integration script
- `local_rules.xml` - Custom Wazuh detection rules
