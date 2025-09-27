import requests
import os

API_KEY = os.getenv("ABUSEIPDB_API_KEY", "7ff0baaf5ccb45595db11cdd2719e82257581370ce59766d1636525691ec93ce62b62a0964a34d19")
BASE_URL = "https://api.abuseipdb.com/api/v2"

HEADERS = {
    "Accept": "application/json",
    "Key": API_KEY
}

def check(ip):
    url = f"{BASE_URL}/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(url, headers=HEADERS, params=params)
    return r.json()

def blacklist(limit=10, confidence_minimum=90):
    url = f"{BASE_URL}/blacklist"
    params = {"limit": limit, "confidenceMinimum": confidence_minimum}
    r = requests.get(url, headers=HEADERS, params=params)
    return r.json()

def bulkreport(reports):
    url = f"{BASE_URL}/bulk-report"
    data = {"reports": reports}
    r = requests.post(url, headers=HEADERS, json=data)
    return r.json()

def check_block(network):
    url = f"{BASE_URL}/check-block"
    params = {"network": network}
    r = requests.get(url, headers=HEADERS, params=params)
    return r.json()

def clear_address(ip):
    url = f"{BASE_URL}/clear-address"
    data = {"ipAddress": ip}
    r = requests.delete(url, headers=HEADERS, data=data)
    return r.json()

def report(ip, categories, comment=""):
    url = f"{BASE_URL}/report"
    data = {"ip": ip, "categories": categories, "comment": comment}
    r = requests.post(url, headers=HEADERS, data=data)
    return r.json()

def reports(ip):
    url = f"{BASE_URL}/reports"
    params = {"ipAddress": ip}
    r = requests.get(url, headers=HEADERS, params=params)
    return r.json()