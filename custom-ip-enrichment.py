#!/usr/bin/env python3

import sys
import json
import requests
import ipaddress
from datetime import datetime
import os
from socket import AF_UNIX, SOCK_DGRAM, socket as unix_socket

def load_api_key():
    with open("/var/ossec/etc/abuseipdb.conf") as f:
        for line in f:
            if line.startswith("ABUSEIPDB_KEY"):
                return line.split("=")[1].strip()
    return None


API_KEY = load_api_key()

def is_public_ip(ip):
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private:
            return False
        if obj.is_reserved:
            return False
        if obj.is_multicast:
            return False
        return True
    except ValueError:
        return False


def get_risk_level(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    elif score > 10:
        return "LOW"
    else:
        return "CLEAN"


def parse_result(response_json):
    if "data" not in response_json:
        print(f"Unexpected API response: {response_json}")
        sys.exit(1)
    data = response_json["data"]
    return {
        "ip": data["ipAddress"],
        "score": data["abuseConfidenceScore"],
        "country": data["countryCode"],
        "isp_name": data["isp"],
        "total_reports": data["totalReports"],
        "is_tor": data["isTor"],
        "usage_type": data["usageType"],
        "domain_name": data["domain"],
        "hostname": data["hostnames"],
    }



CACHE_FILE = "/var/ossec/tmp/ip_cache.json"
CACHE_HOURS = 24

def load_cache():
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"Cache load error: {e}")
        return {}

def save_cache(cache):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        print(f"Cache save error: {e}")

def is_cached(cache, ip):
    if ip not in cache:
        return False
    cached_time = datetime.fromisoformat(cache[ip]["timestamp"])
    age = datetime.now() - cached_time
    if age.total_seconds() < CACHE_HOURS * 3600:
        return True
    return False

def query_abuseipdb(ip, cache):
    if is_cached(cache, ip):
        return cache[ip]["result"]
    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90}
    )

    if response.status_code == 429:
        print("Rate limit hit - skipping enrichment")
        sys.exit(0)
    if response.status_code != 200:
        print(f"API error: {response.status_code}")
        sys.exit(0)

    result = parse_result(response.json())
    result["risk"] = get_risk_level(result["score"])
    cache[ip] = {
        "timestamp": datetime.now().isoformat(),
        "result": result
    }
    save_cache(cache)
    return result


SOCKET_ADDR = "/var/ossec/queue/sockets/queue"

def send_to_wazuh(alert, output):
    string = "1:custom-ip-enrichment:" + json.dumps(output)
    try:
        sock = unix_socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except Exception as e:
        with open("/var/ossec/logs/ip-enrichment-debug.log", "a") as f:
            f.write(f"Error: {e}\n")
        print(f"Error: {e}")
        sys.exit(1)
def main():
    alert_file = sys.argv[1]
    with open(alert_file) as f:
        alert = json.load(f)

    srcip = alert.get("data", {}).get("srcip", "")
    dstip = alert.get("data", {}).get("dstip", "")

    ip = ""
    direction = ""
    if is_public_ip(srcip):
        ip = srcip
        direction = "inbound"
    elif is_public_ip(dstip):
        ip = dstip
        direction = "outbound"
    else:
        print("No public IP found in alert")
        sys.exit(0)

    cache = load_cache()
    result = query_abuseipdb(ip, cache)

    output = {
        "integration": "custom-ip-enrichment",
        "direction": direction,
        "abuseipdb": result
    }

    send_to_wazuh(alert, output)

if __name__ == "__main__":
    main() 
