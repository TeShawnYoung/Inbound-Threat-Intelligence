# Inbound Threat Intelligence

## Project Overview

This project demonstrates the implementation of a Microsoft Sentinel security visualization focused on **allowed inbound traffic from known threat-intelligence-listed IP addresses**, using **NTANetAnalytics** flow log data joined against **ThreatIntelIndicators**. By correlating accepted inbound traffic against a live threat-intel feed, this project transforms two independent data sources into a single interactive **KQL (Kusto Query Language) Workbook**.

The primary objective was to build a geographic visualization that identifies external IPs which are *both* present on the organization's threat-intel watchlist *and* successfully sent traffic the network allowed in — surfacing the intersection that represents a confirmed exposure, not just a raw match against a blocklist.

---

## Core Visualization & Scenario Implemented

### 1. Allowed Inbound Flows from Threat-Intel IPs — `NTANetAnalytics` ⋈ `ThreatIntelIndicators`

* **Log Source:** `NTANetAnalytics`, `ThreatIntelIndicators`
* **Objective:** Maps external source IPs that are both listed on the threat-intel feed and had inbound traffic **allowed** (`AllowedInFlows > 0`) through the network, sized by the number of allowed flows.
* **Business Value:** Unlike a raw malicious-flow map that simply re-displays a threat-intel verdict, this join proves the traffic *got in* rather than merely being observed or blocked — turning a passive intel match into an actionable, prioritized investigation list.

#### Visual Dashboard
### Allowed Inbound Flows from Threat-Intel IPs — NTANetAnalytics ⋈ ThreatIntelIndicators

<img width="940" height="365" alt="Inbound-Threat-Intelligence" src="https://github.com/user-attachments/assets/4d3942f4-e8c2-4878-8810-5ccb3de74068" />

#### The KQL Query

```kusto
// === Allowed inbound flows from known TI-listed IPs ===
// Joins our ACCEPTED inbound traffic against the live threat-intel feed.
// A bubble = a threat-intel-listed external IP whose traffic we LET IN.
// 1) Build a deduped, active TI IP watchlist (coalescing the IP observable keys).
let TI_IPs =
    ThreatIntelIndicators
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by Id        // dedup re-ingested indicators
    | where IsActive == true
    | where isempty(ValidUntil) or ValidUntil > now()  // not expired
    | where ObservableKey in ("ipv4-addr:value",
                              "network-traffic:src_ref.value",
                              "network-traffic:dst_ref.value")
    | extend ThreatType = tostring(Data.indicator_types[0])
    | project TI_IP = ObservableValue, Confidence, ThreatType, Tags
    | where isnotempty(TI_IP);
// 2) Our actual ALLOWED inbound flows (any FlowType), keyed on external source IP.
NTANetAnalytics
| where TimeGenerated {TimeRange}
| where SubType == "FlowLog"
| where AllowedInFlows > 0          // it got IN - not denied
| where isnotempty(SrcIp)
// 3) Match source IP against the TI watchlist.
| join kind=inner TI_IPs on $left.SrcIp == $right.TI_IP
// 4) Geo-enrich the matched hostile source.
| extend geo = geo_info_from_ip_address(SrcIp)
| extend Latitude  = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country   = tostring(geo.country),
         State     = tostring(geo.state),
         City      = tostring(geo.city)
// Only keep sources the geo DB placed to a city + country.
| where isnotempty(City) and isnotempty(Country)
| where isnotempty(Latitude) and isnotempty(Longitude)
// 5) One bubble per hostile source that got in.
| summarize AllowedFlows  = sum(AllowedInFlows),
            DeniedFlows   = sum(DeniedInFlows),
            BytesIn       = sum(BytesSrcToDest),
            Targets       = dcount(DestIp),
            Ports         = make_set(DestPort, 15),
            MaxConfidence = max(Confidence),
            ThreatTypes   = make_set(ThreatType, 10)
         by SrcIp, Country, State, City, Latitude, Longitude
| extend MapLabel = strcat(SrcIp, " (", City, ", ", State, ", ", Country, ") - ", AllowedFlows, " allowed, ", Targets, " targets")
| project Latitude, Longitude, MapLabel, AllowedFlows, DeniedFlows, BytesIn, Targets, Ports, MaxConfidence, ThreatTypes, SrcIp, Country, State, City
| order by AllowedFlows desc, Targets desc
```

### 📊 Dashboard Analysis & Key Findings

### 🔍 KQL Query Breakdown

* **Builds a Live TI Watchlist:** The `TI_IPs` subquery deduplicates re-ingested threat-intel indicators (`arg_max by Id`), filters to active and non-expired entries, and normalizes across the different observable key formats an IP can be stored under.
* **Isolates Traffic That Got In:** Filters `NTANetAnalytics` to `AllowedInFlows > 0`, so the analysis only includes traffic the network actually accepted — not denied attempts.
* **Joins Two Independent Sources:** An inner join on source IP correlates accepted network traffic against the threat-intel feed, meaning a result only appears when both conditions are true simultaneously.
* **Enriches the Matched Source:** Uses `geo_info_from_ip_address()` to add geographic coordinates, country, state, and city to each matched IP.
* **Aggregates by Source:** Sums allowed/denied flows and bytes in, and counts distinct internal destinations (`Targets`) reached by each matched source, alongside the threat-intel context (`MaxConfidence`, `ThreatTypes`) carried through from the feed.

### 🗺️ Map Visualization & Legend Key

* **Threat-Intel-Matched Bubbles:** Each bubble represents a unique external source IP that is both threat-intel-listed and had inbound traffic allowed through the network.
* **Bubble Size (Volume):** Bubble size is driven by `AllowedFlows` — larger bubbles indicate sources with a higher number of accepted inbound flows.
* **Color (Data Volume):** Bubble color reflects `BytesIn`, representing the volume of data received from that source.
* **Target Fan-Out:** The `Targets` field shows how many distinct internal hosts each matched source reached — a higher count suggests broader reconnaissance or lateral targeting rather than a single isolated hit.

### ⚠️ Key Security Anomalies Detected

* **High-Volume Confirmed Exposure:** In this dataset, a single source (`20.80.241.91`, Boydton, Virginia, United States) accounted for **329,345 allowed flows across 30 targets**, tagged `anomalous-activity` at 97% confidence, and transferred over **1.16 GB inbound** — more than 12x the allowed-flow count of the next-highest source. The port list for this source includes RDP (`3389`) and SMB (`445`), which combined with high target fan-out is consistent with lateral movement or credential-based access attempts across multiple internal hosts.
* **Clustered Source Infrastructure:** Four distinct IPs in the `194.165.16.0/24` range (all geolocated to Monaco) each appear independently in the results, with confidence scores of 89–98% and threat types split between `malicious-activity` and `anomalous-activity`. Multiple IPs from the same narrow address block hitting the network independently is consistent with a single actor or infrastructure provider operating across several hosts.
* **Broad Port Scanning Behavior:** Several Monaco-cluster sources (and `158.94.211.70`) show `Targets` counts in the teens to forties, combined with long, varied `Ports` lists spanning both common services (22, 80, 443, 3389) and unusual high ports — a pattern more consistent with scanning/enumeration than normal application traffic.
* **Low-Confidence Watchlist Hits:** Several sources are tagged only as `WatchList` at 50% confidence, with low allowed-flow counts (single digits to low hundreds). These are lower-priority relative to the high-confidence, high-volume matches above, but still represent confirmed threat-intel-listed IPs that reached the network and may warrant lower-urgency follow-up.

> A threat-intel match combined with allowed traffic is a strong signal, but confidence scores, threat types, and traffic volume should all be weighed together — a single low-confidence `WatchList` hit with minimal traffic carries far less urgency than a high-confidence, high-volume, multi-target match.

---

### 2. TI-Matched Source Breakdown

* **Log Source:** `NTANetAnalytics`, `ThreatIntelIndicators`
* **Objective:** Provides a source-level, ranked breakdown of every threat-intel-matched IP that had traffic allowed in, alongside the full threat-intel context (confidence, threat type, tags) for each.
* **Business Value:** Allows analysts to move from the geographic map to a sortable table for triage — ranking matched sources by allowed-flow volume so the most active confirmed exposures are reviewed first.

#### The KQL Query

```kusto
// Companion grid: same TI-matched allowed-inbound sources, ranked, with the
// threat-intel context (confidence, threat type) carried alongside the traffic.
let TI_IPs =
    ThreatIntelIndicators
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by Id
    | where IsActive == true
    | where isempty(ValidUntil) or ValidUntil > now()
    | where ObservableKey in ("ipv4-addr:value",
                              "network-traffic:src_ref.value",
                              "network-traffic:dst_ref.value")
    | extend ThreatType = tostring(Data.indicator_types[0])
    | project TI_IP = ObservableValue, Confidence, ThreatType, Tags
    | where isnotempty(TI_IP);
NTANetAnalytics
| where TimeGenerated {TimeRange}
| where SubType == "FlowLog"
| where AllowedInFlows > 0
| where isnotempty(SrcIp)
| join kind=inner TI_IPs on $left.SrcIp == $right.TI_IP
| extend geo = geo_info_from_ip_address(SrcIp)
| extend Country = tostring(geo.country),
         State   = tostring(geo.state),
         City    = tostring(geo.city)
// Only keep sources the geo DB placed to a city + country.
| where isnotempty(City) and isnotempty(Country)
| summarize AllowedFlows  = sum(AllowedInFlows),
            DeniedFlows   = sum(DeniedInFlows),
            BytesIn       = sum(BytesSrcToDest),
            Targets       = dcount(DestIp),
            Ports         = make_set(DestPort, 15),
            MaxConfidence = max(Confidence),
            ThreatTypes   = make_set(ThreatType, 10),
            Tags          = make_set(Tags, 10)
         by SrcIp, Country, State, City
| order by AllowedFlows desc, Targets desc
```

### 📊 Dashboard Analysis & Key Findings

### 🔍 KQL Query Breakdown

* **Reuses the Same TI Watchlist and Join Logic:** Builds the identical deduplicated, active TI watchlist and joins it against allowed inbound flows, consistent with the map query above.
* **Carries Full Threat-Intel Context:** In addition to `MaxConfidence` and `ThreatTypes`, this version also surfaces `Tags` from the feed, giving analysts the complete intel picture for each matched source in one row.
* **Formats for Triage:** Applies red-scale heatmap formatting to `BytesIn` and `AllowedFlows` directly in the grid, visually flagging the highest-volume rows without needing to cross-reference the map.
* **Ranks by Volume, Then Fan-Out:** Orders results by `AllowedFlows` descending, then `Targets` descending, so the most active and broadest-reaching matches surface first.

---

## 🗺️ Source Analysis

* **Source IP:** Identifies the external, threat-intel-listed address that successfully sent traffic into the network.
* **Allowed vs. Denied Flows:** `AllowedFlows` and `DeniedFlows` let analysts see how much of a source's total activity was actually let through versus blocked.
* **Data Volume:** `BytesIn` quantifies how much data was received from the matched source.
* **Target Fan-Out:** `Targets` identifies how many distinct internal hosts the source reached — higher values suggest broader reconnaissance or multi-host targeting.
* **Threat-Intel Context:** `MaxConfidence`, `ThreatTypes`, and `Tags` carry the feed's own assessment of the source directly into the triage table, so severity can be judged without leaving the workbook.
* **Ports Used:** `Ports` lists the destination ports the source interacted with, helping distinguish targeted service abuse (e.g. RDP, SMB) from broad scanning.

---

## ⚠️ Key Security Anomalies Detected

* **Single Source Dominating Allowed Volume:** A source responsible for a disproportionate share of total allowed flows and target fan-out compared to all other matches is the clearest signal in this dataset and should be the first line investigated.
* **High-Confidence, Multi-Target Matches:** Sources with both a high `MaxConfidence` score and a high `Targets` count represent confirmed, actively-exploited exposure rather than a passive listing, and warrant immediate triage.
* **Related Infrastructure Clusters:** Multiple matched sources sharing a narrow IP range and geographic location are more consistent with a single threat actor's infrastructure than unrelated, coincidental matches.

---

**NOTE:** The source data for this visualization required joining two independent tables — `NTANetAnalytics` for actual network behavior and `ThreatIntelIndicators` for external threat context — rather than relying on a single log source. This demonstrates how correlating disparate data sources can surface higher-confidence findings than either source could produce alone: a threat-intel match on its own only proves an IP is *known-bad*, while this join proves that IP's traffic was *actually allowed into the environment*.

---

## Technical Architecture & Workflow

1. **Ingestion:** Network flow telemetry and threat-intelligence indicators are collected in **Microsoft Sentinel / Log Analytics** through the `NTANetAnalytics` and `ThreatIntelIndicators` data sources.
2. **Data Extraction:** Used **Kusto Query Language (KQL)** to build a deduplicated, active threat-intel watchlist, join it against allowed inbound network flows, enrich matched source IPs with geographic information, and aggregate allowed-flow volume and target fan-out.
3. **Visualization:** Configured a **Microsoft Sentinel Workbook** using geographic map and table visualizations to transform the correlated telemetry into an analyst-friendly, prioritized threat-intel triage dashboard.

---

## Skills Demonstrated

* **Microsoft Sentinel:** Building and configuring security workbooks and visualizations.
* **KQL & Data Analysis:** Deduplicating and filtering threat-intel indicators, joining across independent log sources, filtering, aggregating, and transforming network flow telemetry.
* **Security Data Enrichment:** Using `geo_info_from_ip_address()` to add geographic context to matched threat-intel source IPs.
* **Threat Intelligence Correlation:** Combining internal network telemetry with external threat-intel feeds to distinguish confirmed exposure from passive listing.
* **Threat Hunting & Investigation:** Identifying high-volume, high-confidence, and multi-target matches as prioritization signals.
* **Data Visualization:** Translating correlated network and threat-intel telemetry into geographic and source-level security dashboards.
