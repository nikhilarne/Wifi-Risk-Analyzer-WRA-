import streamlit as st
import random
from fpdf import FPDF
import datetime
import subprocess
import re
import platform
import plotly.graph_objects as go

# Map raw security to standard type
def map_security_type(raw):
    raw = raw.lower()
    if "open" in raw or raw == "" or raw == "--":
        return "Open"
    elif "wep" in raw:
        return "WEP"
    elif "wpa3" in raw:
        return "WPA3"
    elif "wpa2" in raw:
        return "WPA2"
    elif "wpa" in raw:
        return "WPA"
    else:
        return "WPA2"

# Scan WiFi networks
def scan_wifi():
    system = platform.system()
    ssid_list = []
    wifi_security = {}
    try:
        if system == "Windows":
            output = subprocess.check_output("netsh wlan show networks mode=Bssid", shell=True, text=True)
            ssids = re.findall(r"SSID \d+ : (.+)", output)
            auths = re.findall(r"Authentication\s+:\s+(.+)", output)
            for i, ssid in enumerate(ssids):
                ssid = ssid.strip()
                ssid_list.append(ssid)
                raw_security = auths[i].strip() if i < len(auths) else "Unknown"
                wifi_security[ssid] = map_security_type(raw_security)
        elif system == "Linux":
            output = subprocess.check_output("nmcli -t -f SSID,SECURITY dev wifi", shell=True, text=True)
            lines = output.strip().split("\n")
            for line in lines:
                parts = line.split(":")
                if len(parts) >= 2:
                    ssid = parts[0].strip()
                    raw_security = parts[1].strip()
                    ssid_list.append(ssid)
                    wifi_security[ssid] = map_security_type(raw_security)
        else:
            st.warning("Auto WiFi scan not supported on this OS.")
    except Exception as e:
        st.error(f"WiFi scan failed: {e}")
    return ssid_list, wifi_security

# Analyze WiFi with attacks
def analyze_wifi(ssid: str, security: str):
    attacks = {
        "Open": ["Eavesdropping", "Data Theft", "Man-in-the-Middle (MITM)", "Session Hijacking"],
        "WEP": ["Weak Encryption Crack", "Replay Attacks", "Packet Injection", "ARP Spoofing"],
        "WPA": ["Dictionary Attacks", "Brute Force Password Attack", "Handshake Capture", "Evil Twin Attack"],
        "WPA2": ["KRACK Attack", "Weak Password Brute Force", "Handshake Capture", "Rogue Access Point"],
        "WPA3": ["Side-channel Attack (rare)", "Implementation Bugs", "Downgrade Attack", "Dragonblood Attack"]
    }
    scores = {"Open": 90, "WEP": 75, "WPA": 50, "WPA2": 30, "WPA3": 10}
    risk_score = scores.get(security, 50) + random.randint(-5,5)
    risk_attacks = attacks.get(security, ["Unknown Risks"])
    return {"SSID": ssid, "Security": security, "Risk Score": max(0, min(100, risk_score)), "Possible Attacks": risk_attacks}

# Determine risk level
def get_risk_level(score):
    if score <= 30:
        return "Low Risk", "green", "🟢"
    elif score <= 70:
        return "Medium Risk", "orange", "🟡"
    else:
        return "High Risk", "red", "🔴"

# Generate PDF report
def generate_pdf_report(wifi_data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, "WiFi Risk Analysis Report", ln=True, align="C")
    pdf.ln(10)
    pdf.cell(200, 10, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(200, 10, f"Network: {wifi_data['SSID']}", ln=True)
    pdf.cell(200, 10, f"Security: {wifi_data['Security']}", ln=True)
    pdf.ln(5)
    pdf.cell(200, 10, f"Risk Score: {wifi_data['Risk Score']} / 100", ln=True)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, "Possible Attacks:", ln=True)
    pdf.set_font("Arial", size=12)
    for attack in wifi_data["Possible Attacks"]:
        pdf.cell(200, 10, f"- {attack}", ln=True)
    file_name = f"wifi_report_{wifi_data['SSID']}.pdf"
    pdf.output(file_name)
    return file_name

# Display risk gauge
def display_gauge(risk_score):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        title={'text': "WiFi Risk Score"},
        gauge={'axis': {'range': [0, 100]},
               'bar': {'color': "black"},
               'steps': [{'range': [0, 30], 'color': "green"},
                         {'range': [30, 70], 'color': "orange"},
                         {'range': [70, 100], 'color': "red"}]}))
    st.plotly_chart(fig, use_container_width=True)

# Streamlit UI
st.title("📡 WiFi Risk Analyzer (WRA)")

ssid_list, wifi_security = scan_wifi()

if ssid_list:
    selected_ssid = st.selectbox("Select WiFi Network", ssid_list)
    security_type = wifi_security.get(selected_ssid, "Open")
    st.write(f"Detected Security: **{security_type}**")
else:
    selected_ssid = st.text_input("Enter WiFi SSID manually")
    security_type = st.selectbox("Select Security Type", ["Open", "WEP", "WPA", "WPA2", "WPA3"])

if st.button("Analyze"):
    result = analyze_wifi(selected_ssid, security_type)
    level_text, color, emoji = get_risk_level(result["Risk Score"])

    st.subheader("🔎 Analysis Result")
    st.write(f"**Network:** {result['SSID']}")
    st.write(f"**Security Type:** {result['Security']}")
    st.write(f"**Risk Score:** {result['Risk Score']} / 100 {emoji}")
    st.write(f"**Overall Risk Level:** {level_text}")

    st.write("**Possible Attacks:**")
    for attack in result["Possible Attacks"]:
        st.write(f"- {attack}")

    st.subheader("⚠️ Risk Gauge")
    display_gauge(result["Risk Score"])

    report_file = generate_pdf_report(result)
    with open(report_file, "rb") as f:
        st.download_button("⬇️ Download PDF Report", f, file_name=report_file)
