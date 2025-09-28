from flask import Flask, render_template, request
import socket
import abuseipdb_api as abuse

app = Flask(__name__)

# Resolves domain to IP
def resolve_ip(ip_or_domain):
    try:
        return socket.gethostbyname(ip_or_domain)
    except Exception:
        return ip_or_domain

# Safely prepare table for JSON data
def prepare_table(data):
    rows = {}
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, list):
                # Convert list to comma-separated string
                rows[k] = ', '.join([str(i) if not isinstance(i, dict) else str(i) for i in v])
            elif isinstance(v, dict):
                # Convert nested dict to string
                rows[k] = str(v)
            else:
                rows[k] = v
    elif isinstance(data, list):
        rows = {"Items": ', '.join([str(i) for i in data])}
    else:
        rows = {"Value": data}
    return rows

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    risk_level = None
    ip_input = ''
    if request.method == "POST":
        ip_input = request.form.get("ip")
        endpoint = request.form.get("endpoint")
        ip = resolve_ip(ip_input)

        data = {}
        try:
            if endpoint == "check":
                data = abuse.check(ip)
            elif endpoint == "blacklist":
                data = abuse.blacklist()
            elif endpoint == "bulkreport":
                dummy_reports = [{"ip": ip, "categories": "18", "comment": "Suspicious"}]
                data = abuse.bulkreport(dummy_reports)
            elif endpoint == "check-block":
                data = abuse.check_block(ip)
            elif endpoint == "clear-address":
                data = abuse.clear_address(ip)
            elif endpoint == "report":
                data = abuse.report(ip, "18", "Manual report from dashboard")
            elif endpoint == "reports":
                data = abuse.reports(ip)
            else:
                data = {"error": "Invalid endpoint"}
        except Exception as e:
            data = {"error": str(e)}

        # Prepare Table
        if isinstance(data, dict) and "data" in data:
            result = prepare_table(data["data"])
        else:
            result = prepare_table(data)

        # Risk level evaluation for the endpoint /check only to generate piechart
        if endpoint == "check" and "abuseConfidenceScore" in result:
            try:
                score = int(result.get("abuseConfidenceScore", 0))
                if score > 75:
                    risk_level = "High"
                elif score > 40:
                    risk_level = "Medium"
                else:
                    risk_level = "Low"
            except Exception:
                risk_level = "Unknown"

    return render_template("index.html", result=result, risk_level=risk_level, ip_input=ip_input)

if __name__ == "__main__":
    app.run(debug=True)
