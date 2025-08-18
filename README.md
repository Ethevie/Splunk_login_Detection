# Splunk_login_Detection
A Splunk project detecting Failed Windows login attempts with dashboards for SOC analysis.

## 📌 Project Overview
This project demonstrates how to use **Splunk** to detect and visualize failed Windows login attempts (Event ID **4625**).  
The goal is to simulate a **Security Operations Center (SOC) workflow** for identifying suspicious authentication failures, which can indicate brute force attacks, insider threats, or misconfigured accounts.

---

## ⚙️ Environment Setup
- **SIEM Tool**: Splunk Enterprise (local instance)
- **Data Source**: Windows Security Logs (`.evtx` file)
- **Key Event**:  
  - Event ID **4625** → Failed Login Attempts  

---

## 🔎 Splunk Queries

### 1. Extract Event Code
```spl
index=security_logs source="C:\\Users\\yvett\\OneDrive\\Documents\\comptia Security\\CHATGPT\\exiting_sucurity_logs.evtx"
| table _time, host, source, sourcetype, _raw
| head 10

## 2. Count Successful Logins (4624)
```spl
index=security_logs source="C:\\Users\\yvett\\OneDrive\\Documents\\comptia Security\\CHATGPT\\exiting_sucurity_logs.evtx"
| rex "EventCode:\s(?<EventCode>\d+)"
| search EventCode=4624
| stats count by host, _time
| sort -_time

## 3. Count Credential Manager Events (5379)
```spl
index=security_logs source="C:\\Users\\yvett\\OneDrive\\Documents\\comptia Security\\CHATGPT\\exiting_sucurity_logs.evtx"
| rex "EventCode:\s(?<EventCode>\d+)"
| search EventCode=5379
| stats count by host, _time
| sort -_time

## 4. Detect Logins Outside Normal Hours (e.g., 9 PM – 6 AM)
```spl
index=security_logs source="C:\\Users\\yvett\\OneDrive\\Documents\\comptia Security\\CHATGPT\\exiting_sucurity_logs.evtx"
| rex "EventCode:\s(?<EventCode>\d+)"
| search EventCode=4624
| eval hour=strftime(_time,"%H")
| where hour<6 OR hour>21
| stats count by host, hour
| sort -hour

## 3. Multiple Logins 
```spl
index=security_logs source="C:\\Users\\yvett\\OneDrive\\Documents\\comptia Security\\CHATGPT\\exiting_sucurity_logs.evtx"
| rex "EventCode:\s(?<EventCode>\d+)"
| search EventCode=4624
| stats count by host
| where count>5
| sort -count

![Description](screenshots/image_name.png)


