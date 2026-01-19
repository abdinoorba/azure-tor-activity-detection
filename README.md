---

# Detecting Azure Control-Plane Activity from Tor Exit Nodes

## Overview

This project demonstrates a threat-hunting detection in **Microsoft Sentinel** that identifies **Azure management-plane activity originating from Tor exit node infrastructure**. Such behavior is rare in legitimate environments and may indicate credential compromise, insider abuse, or attempts to anonymize malicious cloud operations.

---

## Objective

Identify Azure administrative actions performed from **known Tor exit node IP addresses** by correlating Azure activity logs with threat intelligence maintained in a Sentinel watchlist.

---

## Why This Detection Matters

Azure management actions are typically executed from:

* Corporate IP ranges
* Trusted VPN gateways
* Known geographic locations

Tor exit nodes are designed to anonymize traffic and obscure attribution. Their use for Azure control-plane operations is uncommon and represents a **high-risk security signal**.

This detection helps identify:

* Stolen Azure credentials used anonymously
* Insider activity attempting to evade attribution
* Unauthorized or destructive cloud operations
* Persistence or reconnaissance within Azure environments

---

## Data Sources

* **AzureActivity** logs (Azure control-plane operations)
* **Microsoft Sentinel Watchlist** containing known Tor exit node IP addresses

---

## Detection Logic

### Step 1 – Load Tor Exit Node Threat Intelligence

```kql
let TorExitNodeIPs = GetWatchlist('TorNetworkIps');
```

A Sentinel watchlist is used to maintain a dynamic and reusable list of known Tor exit node IP addresses.

---

### Step 2 – Query Azure Management Activity

```kql
AzureActivity
| where CallerIpAddress != ""
```

Filters for Azure activity events where a source IP address is present and usable for correlation.

---

### Step 3 – Enrich Events with Context

```kql
| extend 
    InitiatingIdentity = Caller,
    TargetResourceName = tostring(parse_json(Properties).Resource)
```

Adds clarity by identifying:

* The identity performing the action
* The Azure resource impacted by the operation

---

### Step 4 – Correlate Activity with Tor Exit Nodes

```kql
| join TorExitNodeIPs on $left.CallerIpAddress == $right.ExitPointsTor
```

Identifies Azure management actions originating from known Tor exit node infrastructure.

---

### Step 5 – Output Incident-Ready Fields

```kql
| project 
    TimeGenerated,
    OperationNameValue,
    SubscriptionId,
    InitiatingIdentity,
    TargetResourceName,
    ResourceGroup
```

Outputs fields useful for SOC triage, investigation, and escalation.

---

## Expected Results

The query returns Azure control-plane actions that:

* Originate from Tor exit node IPs
* Are tied to identifiable users or service principals
* Affect specific Azure resources and subscriptions

Examples include:

* Resource creation or deletion
* Role assignments
* Network or identity configuration changes

---

## Attack Scenarios Covered

* Use of compromised Azure credentials via Tor
* Insider activity attempting to conceal origin
* Malicious cloud operations designed to evade IP-based detections
* Post-compromise cloud persistence or reconnaissance

---

## Tuning and False Positive Reduction

False positives are minimized by:

* Correlating against known Tor exit node IPs
* Focusing exclusively on Azure management-plane activity

Additional tuning options:

* Exclude known corporate VPN IP ranges
* Limit detection to high-risk operations only
* Enrich results with identity risk or UEBA signals

---

## Operational Use Cases

This detection can be deployed as:

* A Microsoft Sentinel Analytics Rule
* A recurring threat-hunting query
* An investigation pivot during cloud incident response
* A component of a broader cloud security monitoring strategy

---

## Skills Demonstrated

* KQL threat hunting
* Cloud security monitoring
* Threat intelligence correlation
* Detection engineering
* SOC-focused investigation workflows
* Microsoft Sentinel and Azure logging

--- 
