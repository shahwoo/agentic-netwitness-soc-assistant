export const decisionOutcomeMap = {
    approve: {
        nextStep: { label: "Ready for Containment Execution", tone: "good" },
        resultLabel: "Endpoint isolation approved",
        toast: "Endpoint isolation approved",
    },
    investigate: {
        nextStep: { label: "Additional Investigation Required", tone: "warn" },
        resultLabel: "Further investigation requested",
        toast: "Sent to the Investigation Agent",
    },
    reject: {
        nextStep: { label: "Workflow Blocked", tone: "bad" },
        resultLabel: "Containment rejected",
        toast: "Containment rejected",
    },
};
export const agentStageData = {
    parsing: {
        title: "Parsing & Normalisation",
        pct: 100,
        lastRun: "7/19/2026, 5:13:02 PM",
        headStatus: { label: "Completed", tone: "good" },
        missingFields: "None",
        nextStep: { label: "Ready for Triage", tone: "good" },
        warning: null,
        ai: {
            available: true,
            text: "The alert was successfully normalised using the NetWitness endpoint metadata attached to this ticket. Five indicators of compromise were extracted, including the payload hash, the command-and-control IP address and the WannaCry kill-switch domain, with no required fields missing. Raw process-level event records were not available, so the parser relied on the alert metadata and the encoded PowerShell command captured at intake. The available data is sufficient for triage, although conclusions that depend on raw process telemetry should be treated with caution.",
        },
    },
    triage: {
        title: "Triage",
        pct: 100,
        lastRun: "7/19/2026, 5:20:41 PM",
        headStatus: { label: "Completed", tone: "good" },
        missingFields: "None",
        nextStep: { label: "Awaiting Analyst Approval", tone: "warn" },
        warning:
            "SOC analyst review is required before the workflow can continue.",
        decision: { host: "MSS-ECSVC", action: "Endpoint isolation" },
        ai: {
            available: true,
            text: "The alert was classified as Critical with 94% confidence based on a confirmed malicious file hash, active command-and-control communication and encoded PowerShell execution on a production endpoint. Host MSS-ECSVC is the primary affected asset and shows strong indicators of WannaCry ransomware activity. Immediate endpoint isolation is recommended, but SOC analyst approval is required before containment can proceed. No conflicting evidence was found during triage, though the scope of lateral movement to related hosts remains unconfirmed.",
        },
    },
    "threat-intelligence": {
        title: "Threat Intelligence Enrichment",
        pct: 100,
        lastRun: "7/19/2026, 5:28:16 PM",
        headStatus: { label: "Completed", tone: "good" },
        missingFields: "None",
        nextStep: { label: "Ready for Investigation", tone: "good" },
        warning: null,
        ai: {
            available: true,
            text: "Threat Intelligence Enrichment confirmed that the observed file hash, command-and-control IP address and kill-switch domain are associated with the WannaCry ransomware family, with all three connected providers in agreement. Two indicators returned outright malicious verdicts and one was flagged suspicious, giving high confidence in the malicious classification of this alert. No conflicting verdicts were identified across VirusTotal, AlienVault OTX or AbuseIPDB. This enrichment is sufficient to support escalation to investigation without requiring additional lookups.",
        },
    },
    investigation: {
        title: "Investigation",
        pct: 100,
        lastRun: "7/19/2026, 5:41:07 PM",
        headStatus: { label: "Completed", tone: "good" },
        missingFields: "None",
        nextStep: { label: "Additional Investigation Required", tone: "warn" },
        warning:
            "SOC analyst approval is required before proceeding. Lateral movement scope and persistence mechanisms have not been fully validated.",
        ai: {
            available: true,
            text: "The investigation found strong evidence that a WannaCry ransomware payload executed on MSS-ECSVC and attempted outbound command-and-control communication to a known malicious IP and the WannaCry kill-switch domain. Encoded PowerShell execution from a user-writable directory matches MITRE ATT&CK technique T1059.001, Command and Scripting Interpreter. The available evidence supports a likely true-positive classification. Lateral movement scope and the involved svc-mssql account have not yet been fully validated, so the analyst should review SMB connections from MSS-ECSVC and confirm whether persistence mechanisms were created.",
        },
    },
    reporting: {
        title: "Reporting",
        pct: 100,
        lastRun: "7/19/2026, 5:52:30 PM",
        headStatus: { label: "Completed", tone: "good" },
        missingFields: "None",
        nextStep: { label: "Ready for Analyst Review", tone: "warn" },
        warning:
            "SOC analyst approval is required before proceeding. Some findings depend on lateral-movement evidence that has not yet been fully validated.",
        ai: {
            available: true,
            text: "The Reporting Agent generated the executive summary, technical findings, evidence references and recommendations for this ticket using the available investigation results. The report concludes that MSS-ECSVC was compromised by WannaCry ransomware with confirmed command-and-control activity and recommends immediate containment followed by forensic review of related hosts. No required report sections are missing, although some findings remain dependent on lateral-movement evidence that has not yet been fully validated. The report is ready for SOC analyst review and approval before export.",
        },
    },
};
export const stageDocData = {
    parsing: {
        json: {
            slug: "parsed_alert_data",
            name: "Parsed Alert Data",
            description: "Structured and normalised alert information.",
        },
        reports: [
            {
                id: "default",
                name: "Parsing Summary",
                fileSlug: "parsing_summary",
                icon: "search",
                color: "#36b7c9",
                description:
                    "Formatted summary of the parsing results, extracted entities, mapped fields and warnings.",
            },
        ],
        entities: [
            ["Host", "MSS-ECSVC"],
            ["User", "svc-mssql"],
            ["File hash (SHA-256)", "a4f8…91c2"],
            ["IP address", "185.159.82.47"],
            ["Domain", "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"],
        ],
        normalised: [
            ["alert_id → source.alert.id", "NW-458921"],
            ["severity → event.severity", "9"],
            ["host_name → asset.hostname", "MSS-ECSVC"],
            ["file_hash → file.hash.sha256", "a4f8…91c2"],
        ],
        warnings: ["No missing required fields were detected during parsing."],
        limitations: [
            "Raw NetWitness process-level event records were not attached to this ticket; parsing relied on alert metadata and the encoded PowerShell command captured at intake.",
        ],
    },
    triage: {
        json: {
            slug: "triage_data",
            name: "Triage Data",
            description: "Structured output generated by the Triage Agent.",
        },
        reports: [
            {
                id: "default",
                name: "Triage Assessment",
                fileSlug: "triage_assessment",
                icon: "list",
                color: "#c9973d",
                description:
                    "Formatted severity assessment, classification, confidence and triage rationale.",
            },
        ],
        severity: "Critical",
        confidence: "High (94%)",
        classification: "Malware · Ransomware",
        rationale:
            "Critical severity was assigned because a malicious file hash, active command-and-control communication and encoded PowerShell execution were all confirmed on a production endpoint, consistent with known WannaCry ransomware behaviour.",
        recommendedAction: "Endpoint isolation of MSS-ECSVC",
        approvalStatus:
            "Awaiting analyst approval before containment can proceed.",
    },
    "threat-intelligence": {
        json: {
            slug: "threat_intelligence_data",
            name: "Threat Intelligence Data",
            description:
                "Structured enrichment results, IOC reputation data and provider responses.",
        },
        reports: [
            {
                id: "default",
                name: "Threat Intelligence Enrichment Report",
                fileSlug: "threat_intelligence_enrichment_report",
                icon: "search",
                color: "#36c5d3",
                description:
                    "Formatted summary of IOC findings, reputation results, malicious indicators and enrichment conclusions.",
            },
        ],
        iocs: [
            ["a4f8…91c2", "SHA-256 hash", "Malicious"],
            ["185.159.82.47", "IP address", "Malicious"],
            [
                "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
                "Domain",
                "Suspicious",
            ],
        ],
        providers: [
            ["VirusTotal", "Malicious — 66/70 vendors flagged"],
            [
                "AlienVault OTX",
                "Malicious — matched 50 threat-intelligence pulses",
            ],
            [
                "AbuseIPDB",
                "Suspicious — flagged for encoded PowerShell delivery",
            ],
        ],
        conclusion:
            "All three connected providers agree the observed indicators are associated with the WannaCry ransomware family, giving high confidence in the malicious classification of this alert.",
    },
    investigation: {
        json: {
            slug: "investigation_data",
            name: "Investigation Data",
            description:
                "Structured investigation findings, evidence, timeline and classifications.",
        },
        reports: [
            {
                id: "default",
                name: "Investigation Report",
                fileSlug: "investigation_report",
                icon: "clipboard",
                color: "#d9636f",
                description:
                    "Formatted investigation findings, evidence analysis, incident timeline and recommendations.",
            },
        ],
        verdict: "Likely true positive",
        scenario:
            "A WannaCry ransomware payload (msssecsvc.exe) executed on MSS-ECSVC and attempted outbound command-and-control communication to a known malicious IP address and the WannaCry kill-switch domain.",
        evidence: [
            "Malicious file hash confirmed as malicious by 66 security vendors (99% confidence).",
            "Outbound traffic matched 50 threat-intelligence pulses to known command-and-control infrastructure (95% confidence).",
            "Encoded PowerShell command executed from a user-writable directory (89% confidence).",
        ],
        timeline: [
            ["05:13 PM", "Alert parsed and normalised into the case schema."],
            ["05:20 PM", "Triage classified the case as Critical."],
            [
                "05:28 PM",
                "Threat Intelligence Enrichment completed — 12 indicators, WannaCry confirmed.",
            ],
            ["05:41 PM", "Investigation completed — likely true positive."],
        ],
        iocs: [
            ["a4f8…91c2", "SHA-256 hash", "Malicious"],
            ["185.159.82.47", "IP address", "Malicious"],
            [
                "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
                "Domain",
                "Suspicious",
            ],
        ],
        mitre: [["T1059.001", "Command and Scripting Interpreter: PowerShell"]],
        gaps: [
            "Lateral movement scope for related hosts has not been fully validated.",
            "Persistence mechanisms have not yet been confirmed or ruled out.",
        ],
        nextAction:
            "Review SMB connections from MSS-ECSVC and confirm whether persistence mechanisms were created.",
    },
    reporting: {
        json: {
            slug: "reporting_data",
            name: "Reporting Data",
            description:
                "Structured data used to generate the reporting documents.",
        },
        executiveSummary:
            "MSS-ECSVC was compromised by WannaCry ransomware. Malicious payload execution and command-and-control communication were confirmed with high confidence. Immediate containment and forensic review of related hosts are recommended.",
        technicalFindings: [
            "Malicious file hash a4f8…91c2 confirmed across 3 threat-intelligence providers.",
            "Outbound command-and-control communication to 185.159.82.47 matched 50 threat-intelligence pulses.",
            "Encoded PowerShell execution from a user-writable directory on MSS-ECSVC.",
            "MITRE ATT&CK T1059.001 — Command and Scripting Interpreter: PowerShell.",
        ],
        socReview:
            "Reviewed by the Reporting Agent using validated investigation results. Recommendations require analyst sign-off before this report is approved for export.",
        finalConclusion:
            "High-confidence WannaCry ransomware compromise on MSS-ECSVC with confirmed command-and-control activity.",
        validationWarnings: [
            "Some findings remain dependent on lateral-movement evidence that has not yet been fully validated.",
        ],
        reports: [
            {
                id: "executive-summary",
                name: "Executive Summary",
                fileSlug: "executive_summary",
                icon: "document",
                color: "#4f6fe0",
                description:
                    "High-level overview of the incident and key findings.",
            },
            {
                id: "technical-findings",
                name: "Technical Findings",
                fileSlug: "technical_findings",
                icon: "list",
                color: "#3fa968",
                description:
                    "Detailed technical analysis, evidence, and indicators.",
            },
            {
                id: "soc-review",
                name: "SOC Analyst Review",
                fileSlug: "soc_analyst_review",
                icon: "person",
                color: "#7c5ce6",
                description:
                    "Analyst assessment, decisions and recommendations.",
            },
            {
                id: "final-report",
                name: "Final Incident Report",
                fileSlug: "final_incident_report",
                icon: "clipboard",
                color: "#c99a3d",
                description:
                    "Comprehensive report combining all approved sections.",
            },
        ],
    },
};
