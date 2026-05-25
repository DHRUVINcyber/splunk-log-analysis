# Splunk SIEM Log Analysis Project

This project demonstrates how to upload and analyze logs using Splunk SIEM.

## Features
- Log ingestion
- Search & Reporting
- Alerting
- Dashboard creation

## Tools Used
- Splunk Enterprise
- Windows Logs

## Steps
1. Install Splunk
2. Add data
3. Search logs using:
   ```spl
   index=main 

**Here, the main index is used because it is the default index in Splunk Enterprise. Splunk also provides an option to create separate custom indexes for organizing different types of log data.**


