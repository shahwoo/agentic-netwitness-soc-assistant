# SOC Analyst Review

## 1. Review Metadata

| Field | Value |
|---|---|
| Incident ID | INC-0001 |
| Alert ID | ALERT-0001 |
| Report Status | missing_information_required |
| Review Status | Pending |
| Approval Status | Pending Analyst Decision |

---

## 2. Validation Checklist

| Check | Status |
|---|---|
| Incident ID present | Pass |
| Alert ID present | Pass |
| Severity present | Pass |
| Confidence present | Pass |
| Classification present | Pass |
| Evidence present | Fail |
| IOCs present | Pass |
| LLM output quality acceptable | Pass |
| All IOCs linked to evidence or marked Not linked | Pass |
| Containment approval status recorded | Pass |

---

## 3. Evidence Quality Checks

- Confirm that each major finding has evidence references.
- Confirm that missing facts are listed as evidence gaps.
- Confirm that no unsupported IOCs, users, hosts, or timelines were created by the Reporting Agent.
- Confirm that RAG context is used only for policy/procedure guidance, not incident facts.
- Validate whether suspicious PowerShell execution completed successfully.
- Validate whether credential exposure, mailbox rule abuse, OAuth abuse, or session misuse occurred.
- Validate whether similar phishing emails were delivered to other recipients.
- Validate whether the `Not linked` IOC requires additional NetWitness evidence.
- Confirm whether the LLM narrative was accepted, partially replaced by fallback, or requires analyst correction.

---

## 4. Missing Information

| Missing Field |
|---|
| affected_users |
| evidence |

---

## 5. Analyst Corrections

| Field | Analyst Update |
|---|---|
| Severity |  |
| Confidence |  |
| Classification |  |
| Executive Summary |  |
| Recommended Actions |  |
| Evidence Gaps |  |

---

## 6. Approval Decision

| Field | Value |
|---|---|
| Approval Required | Yes |
| Approval Status | Pending Analyst Decision |
| Analyst Decision | Pending Analyst Decision |
| Analyst Comments | Awaiting SOC analyst decision. |

---

## 7. Learning Loop Feedback

Learning updates should not be stored in ChromaDB unless a SOC analyst approves them.

| Learning Item | Analyst Decision |
|---|---|
| Update report writing SOP | Pending |
| Update phishing playbook | Pending |
| Store prior case summary | Pending |
| Store false positive pattern | Pending |

---

## 8. Sign-Off

| Field | Value |
|---|---|
| Reviewed By |  |
| Review Completed At |  |
| Final Decision |  |
| Digital Sign-Off |  |
