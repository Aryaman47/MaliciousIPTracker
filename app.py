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

# Safely prepare a readable key-value mapping
def prepare_table(data):
    rows = {}
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, list):
                rows[k] = ', '.join(
                    [str(i) if not isinstance(i, dict) else str(i) for i in v]
                )
            elif isinstance(v, dict):
                rows[k] = str(v)
            else:
                rows[k] = v
    elif isinstance(data, list):
        formatted_list = []
        for item in data:
            if isinstance(item, dict):
                formatted_list.append(', '.join(f"{k}: {v}" for k, v in item.items()))
            else:
                formatted_list.append(str(item))
        rows = {"Items": ', '.join(formatted_list)}
    else:
        rows = {"Value": data}
    return rows


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    report_results = None   # second table for reports endpoint
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

        # --- Unified table formatting logic ---
        if isinstance(data, dict):
            if "data" in data:
                payload = data["data"]
                # Special handling for 'reports' endpoint
                if endpoint == "reports" and "results" in payload:
                    # Summary table (excluding 'results')
                    summary_data = {k: v for k, v in payload.items() if k != "results"}
                    result = prepare_table(summary_data)

                    # Detailed reports table
                    report_results = []
                    for entry in payload["results"]:
                        report_results.append(prepare_table(entry))
                else:
                    result = prepare_table(payload)
            elif "message" in data:
                result = {"Message": data["message"]}
            elif "errors" in data:
                result = {"Error(s)": ', '.join(str(e) for e in data["errors"])}
            else:
                result = prepare_table(data)
        elif isinstance(data, list):
            result = prepare_table(data)
        else:
            result = {"Response": str(data)}

        # Risk level evaluation (for /check endpoint only)
        if endpoint == "check" and isinstance(result, dict):
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

    return render_template(
        "index.html",
        result=result,
        report_results=report_results,
        risk_level=risk_level,
        ip_input=ip_input
    )


if __name__ == "__main__":
    app.run(debug=True)
