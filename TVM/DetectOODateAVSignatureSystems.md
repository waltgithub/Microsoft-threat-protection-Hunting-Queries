# Find Vulnerable Systems Without the Latest Defender AV Signature

This is a sample query to find systems without the latest x versions of av signature files, which can be used to track compliance.
The goal is to determine which systems are not protected by having one of the latest signature Microsoft releases updates signature files multiple times per day.
For example, by changing the SigVersionCount to "2", the query will return a list of systems without the latest two signature file versions.

## Query

```
// *Disclaimer*
// This is a sample query to find systems without the latest x versions of av signature files, which can be used to track compliance.
// The goal is to determine which systems are not protected by having one of the latest signature files.
// For example, by changing the SigVersionCount to "2", the query will return a list of systems without the latest two signature file versions.
let SigVersionCount = 3; // The latest 'X' versions of signatures to filter out
let AVSigData = (
    DeviceTvmSecureConfigurationAssessment
    | where ConfigurationId == "scid-2011" and isnotempty(Context)
    | extend avdata=parsejson(Context)
    | extend AVSigVersion = tostring(avdata[0][0]) //  Given this is a dynamic array, we can just take the 0th result from the 0th member
    | summarize arg_max(Timestamp, AVSigVersion) by DeviceId, DeviceName // This ensures we get the latest check-in AV signature version
);
AVSigData
| summarize max(Timestamp) by AVSigVersion // Get the most recent timestamps for each AV version.
| top SigVersionCount by max_Timestamp desc // Filter to only the X most recent versions
| join kind=rightanti AVSigData on AVSigVersion // Filter AVSigData to remove anything matching this version
| order by AVSigVersion //Sort by the AVSigVersion >
```
## Category

This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.

| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution |  |  |
| Persistence |  |  | 
| Privilege escalation |  |  |
| Defense evasion |  |  | 
| Credential Access |  |  | 
| Discovery |  |  | 
| Lateral movement |  |  | 
| Collection |  |  | 
| Command and control |  |  | 
| Exfiltration |  |  | 
| Impact |  |  |
| Vulnerability | v |  |
| Misconfiguration |v  |  |
| Malware, component |  |  |


## Contributor info

**Contributor:** Walter Meclazcke

**GitHub alias:** waltgithub

**Organization:** Microsoft

**Contributor:** Michael Melone

**GitHub alias:** mjmelone

**Organization:** Microsoft

