# Splunk SIEM Log Analysis Project

This project demonstrates how to upload and analyze logs using Splunk SIEM.

## Features
- Log ingestion
- Search & Reporting
- Alerting


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

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 1. Bruteforce# Brute Force Detection Using Splunk ##

## Objective
Detect brute-force login attempts using Splunk SIEM by analyzing failed and successful login events.

## Queries Used

### Failed Login Attempts count by src_ip
```spl
index=main EventCode=4625 
| stats count by src_ip
```
- This query shows the count of failed login attempts based on source IP addresses.

### success Login Attempts count by src_ip
```spl
index=main EventCode=4624 
| stats count by src_ip
```
-This query shows the count of successful login attempts based on source IP addresses.


### Failed Login Attempts count by src_ip 
```spl
index=main status=failed user=administrator src_ip=45.67.210.12  OR index=main status=failed (src_ip=45.67.210.12 OR src_ip=77.120.10.88) 
```
-This query displays failed login events for the user administrator from the source IP address 45.67.210.12.

#### Main Brute Force Detection Alert Query
```spl
index=main status=failed
| bucket span=5m _time
| stats count by _time, user, src_ip
| where count > 5
```
-This alert detects more than 5 failed login attempts from the same source IP against a user within 5 minutes.

In the uploaded dataset, two suspicious IP addresses were identified performing multiple brute-force login attempts against user accounts.

## Suspicious ips (IOCs)

-45.67.210.** (Count of failed attempts = 80)
-77.120.10.** (Count of failed attempts = 40)

## Findings

-Multiple failed login attempts were detected from suspicious IP addresses.
-Repeated authentication failures indicate brute-force attack behavior.
-Suspicious activity targeted user authentication services.

## conclusion 

-The investigation successfully identified brute-force attack attempts using Splunk SIEM. Detection queries and alert rules were created to monitor repeated failed authentication attempts   and suspicious login activity.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 2. Successful Brute Force Detection Using Splunk ##

## Objective
-The objective of this investigation is to detect successful brute-force login attacks using Splunk SIEM by identifying multiple failed login attempts followed by a successful               authentication event from the same source IP address.

---

## Investigation Overview
-Authentication logs were analyzed in Splunk to identify suspicious login activity. The investigation focused on detecting attackers attempting repeated password guessing attacks against    user accounts.

---

## Queries Used

### Failed Login Attempts

```spl
index=bruteforce EventCode=4625
```
-Displays all failed login events.

### Successful Login Attempts
```
index=bruteforce EventCode=4624
```
-Displays all successful login events.

### Failed Login Count by Source IP
```
index=bruteforce EventCode=4625
| stats count by src_ip
```
-Shows the number of failed login attempts from each source IP address.

### Successful Login Count by Source IP
```
index=bruteforce EventCode=4624
| stats count by src_ip
```
-Shows the number of successful login attempts from each source IP address.

### Investigation of Suspicious Source IP
```
index=bruteforce EventCode=4625 src_ip=45.67.210.12
```
-Displays failed login attempts originating from a suspicious IP address.

### Successful Brute Force Detection Query
```
index=bruteforce (EventCode=4624 OR EventCode=4625)
| transaction user src_ip maxspan=5m
| search EventCode=4624 EventCode=4625
| where eventcount > 5
```
-Detects multiple failed login attempts followed by a successful login from the same source IP and user within 5 minutes.

## Suspicious ips (IOCs)

-45.67.210.** (Count of failed attempts = 133)
-77.120.10.** (Count of failed attempts = 139)

## Findings

-Multiple failed authentication attempts were detected from suspicious IP addresses.
-Successful authentication after repeated failures indicates possible account compromise.
-Brute-force attack behavior was successfully identified using Splunk SIEM.

## Conclusion

-The investigation successfully identified successful brute-force attack activity using Splunk SIEM using custom authentication logs and SPL queries.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 3. Password Spraying Detection Using Splunk ##

## Objective

-The objective of this investigation is to detect password spraying attacks using Splunk SIEM by identifying a single source IP attempting failed authentication attempts against multiple    user accounts within a short period of time.

## Investigation Overview

-Authentication logs were uploaded into Splunk and analyzed using SPL queries. The investigation focused on identifying suspicious login behavior where one source IP attempted to            authenticate against several user accounts using incorrect credentials.

## Queries Used

### Failed Login Attempts
```
index=pass-spray EventCode=4625
```
-Displays all failed authentication events.

### Successful Login Attempts
```
index=pass-spray EventCode=4624
```
-Displays all successful authentication events.

### Suspicious IP Detection Query
```
index=pass-spray EventCode=4625
| stats count by src_ip
| sort - count
```
-Displays source IP addresses generating the highest number of failed login attempts.

## Password Spraying Detection Query
```
index=pass-spray EventCode=4625
| stats dc(user) as targeted_users count by src_ip
| where targeted_users > 5 AND count > 15
| sort - count
```
-Detects a single source IP attempting failed logins against multiple user accounts.

### Users Targeted by Source IP
```
index=pass-spray EventCode=4625
| stats values(user) as targeted_users by src_ip
```
-Displays the user accounts targeted by each source IP address.

### Investigation of Suspicious Source IP
```
index=pass-spray src_ip=88.45.12.9
```
-Displays all authentication activity related to the suspicious source IP address.

### Successful Password Spraying Detection Query
```
index=pass-spray src_ip=88.45.12.9 (EventCode=4624 OR EventCode=4625)
| table _time EventCode user src_ip
| sort _time
```
-Displays failed authentication attempts followed by a successful login from the suspicious source IP.

### Compromised User Detection Query
```
index=pass-spray src_ip=88.45.12.9 EventCode=4624
| stats count by user
```
-Identifies the user account successfully authenticated from the malicious source IP.

## Suspicious IP Address Identified (IOCs)
Source IP  |  Activity
88.45.12.9 |  Password spraying attempts against multiple user accounts

## Findings

-Multiple failed login attempts were detected from a single source IP address.
-The attacker targeted several user accounts within a short period of time.
-Authentication behavior matched password spraying attack patterns.
-A successful login event was observed after repeated failed attempts.
-The compromised user account was identified through successful authentication events.
-The suspicious source IP responsible for the attack activity was successfully identified.

## Conclusion

-The investigation successfully identified password spraying activity using Splunk SIEM. SPL queries and authentication log analysis helped detect suspicious login behavior, identify        malicious source IPs, determine targeted user accounts, and detect successful compromise attempts.
