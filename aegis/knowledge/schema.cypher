// =============================================================================
// AegisThreat Neo4j Knowledge Graph Schema
// =============================================================================
// This schema models:
//   1. MITRE ATT&CK techniques, tactics, and their relationships
//   2. Enterprise asset topology (hosts, services, dependencies)
//   3. Detection coverage mapping
//   4. Historical attack cases and threat actor profiles
//
// Usage:
//   cypher-shell -u neo4j -p <password> -f schema.cypher
// =============================================================================

// ── Constraints ──────────────────────────────────────────────────────────────

CREATE CONSTRAINT technique_id IF NOT EXISTS
FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE;

CREATE CONSTRAINT tactic_id IF NOT EXISTS
FOR (t:Tactic) REQUIRE t.tactic_id IS UNIQUE;

CREATE CONSTRAINT asset_id IF NOT EXISTS
FOR (a:Asset) REQUIRE a.asset_id IS UNIQUE;

CREATE CONSTRAINT threat_actor_id IF NOT EXISTS
FOR (ta:ThreatActor) REQUIRE ta.actor_id IS UNIQUE;

CREATE CONSTRAINT ioc_value IF NOT EXISTS
FOR (i:IOC) REQUIRE i.value IS UNIQUE;

CREATE CONSTRAINT detection_rule_id IF NOT EXISTS
FOR (d:DetectionRule) REQUIRE d.rule_id IS UNIQUE;

CREATE CONSTRAINT attack_case_id IF NOT EXISTS
FOR (c:AttackCase) REQUIRE c.case_id IS UNIQUE;

CREATE CONSTRAINT mitigation_id IF NOT EXISTS
FOR (m:Mitigation) REQUIRE m.mitigation_id IS UNIQUE;

CREATE CONSTRAINT software_id IF NOT EXISTS
FOR (s:Software) REQUIRE s.software_id IS UNIQUE;

// ── Indexes ──────────────────────────────────────────────────────────────────

CREATE INDEX technique_name_idx IF NOT EXISTS FOR (t:Technique) ON (t.name);
CREATE INDEX asset_hostname_idx IF NOT EXISTS FOR (a:Asset) ON (a.hostname);
CREATE INDEX asset_ip_idx IF NOT EXISTS FOR (a:Asset) ON (a.ip_address);
CREATE INDEX ioc_type_idx IF NOT EXISTS FOR (i:IOC) ON (i.ioc_type);
CREATE INDEX alert_rule_name_idx IF NOT EXISTS FOR (d:DetectionRule) ON (d.name);
CREATE INDEX attack_case_date_idx IF NOT EXISTS FOR (c:AttackCase) ON (c.occurred_at);

// ── Full-Text Indexes ────────────────────────────────────────────────────────

CREATE FULLTEXT INDEX technique_descriptions IF NOT EXISTS
FOR (t:Technique) ON EACH [t.name, t.description];

// ── Node Labels: ATT&CK Framework ───────────────────────────────────────────

// Tactic: The 15 ATT&CK tactics (e.g. Initial Access, Execution, ...)
// (:Tactic {tactic_id, name, short_name, description, order})

// Technique: ATT&CK techniques and sub-techniques
// (:Technique {
//   technique_id,    // e.g. "T1059.001" or "T1059"
//   name,            // e.g. "PowerShell"
//   description,     // Full description
//   tactic,          // Parent tactic short name
//   is_subtechnique, // boolean
//   parent_id,       // For sub-techniques, the parent technique ID
//   platforms,       // ["Windows", "Linux", "macOS", ...]
//   data_sources,    // ["Process Monitoring", "Command Execution", ...]
//   detection_tips,  // Free-text detection guidance
//   version          // ATT&CK version (e.g. "v15")
// })

// ── Node Labels: Enterprise Assets ──────────────────────────────────────────

// Asset: Any device, server, or endpoint in the enterprise
// (:Asset {
//   asset_id,        // UUID
//   hostname,        // e.g. "dc01.corp.local"
//   ip_address,      // e.g. "10.0.1.15"
//   asset_type,      // "server", "workstation", "network_device", "cloud_instance"
//   os,              // "Windows Server 2022", "Ubuntu 22.04"
//   criticality,     // 1-5 (5 = crown jewel)
//   business_function, // "Domain Controller", "Payment Processing", "HR Portal"
//   owner_team,      // "Infrastructure", "DevOps", "Finance"
//   max_tolerable_downtime_minutes, // MTD
//   user_count       // Number of users dependent on this asset
// })

// Service: A logical service running on an asset
// (:Service {
//   service_id,      // UUID
//   name,            // "Active Directory", "PostgreSQL", "nginx"
//   port,            // 389, 5432, 443
//   protocol,        // "TCP", "UDP"
//   criticality      // 1-5
// })

// Application: Business application
// (:Application {
//   app_id,          // UUID
//   name,            // "SAP ERP", "Salesforce", "Custom CRM"
//   tier,            // "tier1" (critical), "tier2", "tier3"
//   data_classification // "public", "internal", "confidential", "restricted"
// })

// User: Human or service account
// (:User {
//   username,        // "jdoe", "svc_backup"
//   user_type,       // "human", "service", "admin"
//   department,      // "Engineering", "Finance"
//   privilege_level  // "standard", "elevated", "domain_admin"
// })

// ── Node Labels: Threat Intelligence ────────────────────────────────────────

// ThreatActor: APT group or threat actor
// (:ThreatActor {
//   actor_id,        // e.g. "APT29"
//   name,            // "Cozy Bear"
//   aliases,         // ["The Dukes", "CozyDuke"]
//   motivation,      // "espionage", "financial", "destructive"
//   target_industries, // ["government", "technology", "healthcare"]
//   first_seen,      // date
//   last_seen,       // date
//   confidence       // 0-1 attribution confidence
// })

// IOC: Indicator of Compromise
// (:IOC {
//   value,           // The indicator value (hash, IP, domain, URL)
//   ioc_type,        // "ipv4", "domain", "url", "sha256", "email", "registry_key"
//   first_seen,      // datetime
//   last_seen,       // datetime
//   source,          // "MISP", "OSINT", "VirusTotal", "Internal"
//   severity,        // "low", "medium", "high", "critical"
//   confidence       // 0-1
// })

// Software: Malware or tool
// (:Software {
//   software_id,     // e.g. "S0066"
//   name,            // "Mimikatz", "Cobalt Strike"
//   software_type,   // "malware", "tool", "exploit"
//   description
// })

// ── Node Labels: Detection & Response ────────────────────────────────────────

// DetectionRule: A SIEM/EDR detection rule
// (:DetectionRule {
//   rule_id,         // e.g. "det-117"
//   name,            // "Suspicious PowerShell Execution"
//   source,          // "Splunk", "SentinelOne", "Suricata"
//   severity,        // "low", "medium", "high", "critical"
//   enabled,         // boolean
//   false_positive_rate // 0-1
// })

// Mitigation: An ATT&CK mitigation technique
// (:Mitigation {
//   mitigation_id,   // e.g. "M1032"
//   name,            // "Multi-factor Authentication"
//   description,
//   cost,            // "low", "medium", "high"
//   effectiveness    // 0-1
// })

// ── Node Labels: Operational ────────────────────────────────────────────────

// AttackCase: A historical attack case (real or synthetic)
// (:AttackCase {
//   case_id,         // UUID
//   name,            // "Incident 2026-001: APT29 Phishing Campaign"
//   severity,        // "low", "medium", "high", "critical"
//   occurred_at,     // datetime
//   resolved_at,     // datetime
//   resolution,      // "contained", "remediated", "false_positive", "ongoing"
//   analyst_notes    // Free-text
// })

// ── Relationships: ATT&CK Structure ─────────────────────────────────────────

// Technique → Tactic (belongs to)
// (:Technique)-[:BELONGS_TO]->(:Tactic)

// Technique → Technique (sub-technique)
// (:Technique)-[:SUB_TECHNIQUE_OF]->(:Technique)

// Technique → Technique (precondition / dependency)
// (:Technique)-[:REQUIRES {confidence: 0.8, description: ""}]->(:Technique)

// Technique → Technique (commonly follows)
// (:Technique)-[:FOLLOWED_BY {weight: 0.7, typical_lag_minutes: 15}]->(:Technique)

// Technique → Technique (is variant of)
// (:Technique)-[:VARIANT_OF]->(:Technique)

// ── Relationships: Asset Topology ───────────────────────────────────────────

// Asset connectivity
// (:Asset)-[:CONNECTS_TO {protocol: "TCP", port: 443, direction: "outbound"}]->(:Asset)

// Asset → Service (hosts)
// (:Asset)-[:HOSTS]->(:Service)

// Service → Application (supports)
// (:Service)-[:SUPPORTS]->(:Application)

// Application → Application (depends on)
// (:Application)-[:DEPENDS_ON {criticality: 4}]->(:Application)

// Asset → User (belongs to / used by)
// (:Asset)-[:USED_BY]->(:User)

// Asset → NetworkSegment
// (:Asset)-[:IN_SEGMENT]->(:NetworkSegment)

// ── Relationships: Threat Intelligence ──────────────────────────────────────

// ThreatActor → Technique (uses)
// (:ThreatActor)-[:USES {first_seen: date, last_seen: date, prevalence: 0.8}]->(:Technique)

// ThreatActor → Software (uses tool/malware)
// (:ThreatActor)-[:DEPLOYS]->(:Software)

// IOC → ThreatActor (indicates)
// (:IOC)-[:INDICATES {confidence: 0.9}]->(:ThreatActor)

// IOC → Technique (associated with)
// (:IOC)-[:ASSOCIATED_WITH]->(:Technique)

// Software → Technique (implements)
// (:Software)-[:IMPLEMENTS]->(:Technique)

// ── Relationships: Detection & Coverage ─────────────────────────────────────

// DetectionRule → Technique (detects)
// (:DetectionRule)-[:DETECTS {confidence: 0.85, typical_tpr: 0.9}]->(:Technique)

// Asset → DetectionRule (has rule enabled)
// (:Asset)-[:HAS_DETECTION]->(:DetectionRule)

// Mitigation → Technique (counters / mitigates)
// (:Mitigation)-[:COUNTERS]->(:Technique)

// ── Relationships: Operational ──────────────────────────────────────────────

// AttackCase → Technique (included in)
// (:AttackCase)-[:INCLUDES {step: 1, confidence: 1.0}]->(:Technique)

// AttackCase → Asset (affected)
// (:AttackCase)-[:AFFECTED {impact: "compromised", data_loss: false}]->(:Asset)

// AttackCase → ThreatActor (attributed to)
// (:AttackCase)-[:ATTRIBUTED_TO {confidence: 0.7}]->(:ThreatActor)

// ── Seed Data: ATT&CK Tactics ───────────────────────────────────────────────
// (Partial — full import via attck_loader.py)

MERGE (ta:Tactic {tactic_id: "TA0001"}) SET ta.name = "Initial Access", ta.short_name = "initial-access", ta.order = 1;
MERGE (ta:Tactic {tactic_id: "TA0002"}) SET ta.name = "Execution", ta.short_name = "execution", ta.order = 2;
MERGE (ta:Tactic {tactic_id: "TA0003"}) SET ta.name = "Persistence", ta.short_name = "persistence", ta.order = 3;
MERGE (ta:Tactic {tactic_id: "TA0004"}) SET ta.name = "Privilege Escalation", ta.short_name = "privilege-escalation", ta.order = 4;
MERGE (ta:Tactic {tactic_id: "TA0005"}) SET ta.name = "Defense Evasion", ta.short_name = "defense-evasion", ta.order = 5;
MERGE (ta:Tactic {tactic_id: "TA0006"}) SET ta.name = "Credential Access", ta.short_name = "credential-access", ta.order = 6;
MERGE (ta:Tactic {tactic_id: "TA0007"}) SET ta.name = "Discovery", ta.short_name = "discovery", ta.order = 7;
MERGE (ta:Tactic {tactic_id: "TA0008"}) SET ta.name = "Lateral Movement", ta.short_name = "lateral-movement", ta.order = 8;
MERGE (ta:Tactic {tactic_id: "TA0009"}) SET ta.name = "Collection", ta.short_name = "collection", ta.order = 9;
MERGE (ta:Tactic {tactic_id: "TA0010"}) SET ta.name = "Exfiltration", ta.short_name = "exfiltration", ta.order = 10;
MERGE (ta:Tactic {tactic_id: "TA0011"}) SET ta.name = "Command & Control", ta.short_name = "command-and-control", ta.order = 11;

// ── Seed Data: Commonly Referenced Techniques ───────────────────────────────

MERGE (t:Technique {technique_id: "T1566"})  SET t.name = "Phishing", t.tactic = "initial-access";
MERGE (t:Technique {technique_id: "T1189"})  SET t.name = "Drive-by Compromise", t.tactic = "initial-access";
MERGE (t:Technique {technique_id: "T1190"})  SET t.name = "Exploit Public-Facing Application", t.tactic = "initial-access";
MERGE (t:Technique {technique_id: "T1078"})  SET t.name = "Valid Accounts", t.tactic = "initial-access";
MERGE (t:Technique {technique_id: "T1059"})  SET t.name = "Command & Scripting Interpreter", t.tactic = "execution";
MERGE (t:Technique {technique_id: "T1203"})  SET t.name = "Exploitation for Client Execution", t.tactic = "execution";
MERGE (t:Technique {technique_id: "T1547"})  SET t.name = "Boot or Logon Autostart Execution", t.tactic = "persistence";
MERGE (t:Technique {technique_id: "T1068"})  SET t.name = "Exploitation for Privilege Escalation", t.tactic = "privilege-escalation";
MERGE (t:Technique {technique_id: "T1562"})  SET t.name = "Impair Defenses", t.tactic = "defense-evasion";
MERGE (t:Technique {technique_id: "T1003"})  SET t.name = "OS Credential Dumping", t.tactic = "credential-access";
MERGE (t:Technique {technique_id: "T1110"})  SET t.name = "Brute Force", t.tactic = "credential-access";
MERGE (t:Technique {technique_id: "T1083"})  SET t.name = "File & Directory Discovery", t.tactic = "discovery";
MERGE (t:Technique {technique_id: "T1021"})  SET t.name = "Remote Services", t.tactic = "lateral-movement";
MERGE (t:Technique {technique_id: "T1560"})  SET t.name = "Archive Collected Data", t.tactic = "collection";
MERGE (t:Technique {technique_id: "T1071"})  SET t.name = "Application Layer Protocol", t.tactic = "command-and-control";
MERGE (t:Technique {technique_id: "T1048"})  SET t.name = "Exfiltration Over Alternative Protocol", t.tactic = "exfiltration";
MERGE (t:Technique {technique_id: "T1485"})  SET t.name = "Data Destruction", t.tactic = "impact";
MERGE (t:Technique {technique_id: "T1486"})  SET t.name = "Data Encrypted for Impact", t.tactic = "impact";

// ── Seed Data: Key Technique Relationships ──────────────────────────────────

// Phishing chain
MATCH (a:Technique {technique_id: "T1566"}), (b:Technique {technique_id: "T1059"})
MERGE (a)-[:FOLLOWED_BY {weight: 0.85}]->(b);

// Brute force → credential dump → lateral movement (common path)
MATCH (a:Technique {technique_id: "T1110"}), (b:Technique {technique_id: "T1078"})
MERGE (a)-[:FOLLOWED_BY {weight: 0.90}]->(b);

MATCH (a:Technique {technique_id: "T1078"}), (b:Technique {technique_id: "T1003"})
MERGE (a)-[:FOLLOWED_BY {weight: 0.70}]->(b);

MATCH (a:Technique {technique_id: "T1003"}), (b:Technique {technique_id: "T1021"})
MERGE (a)-[:FOLLOWED_BY {weight: 0.80}]->(b);

// C2 → Exfil
MATCH (a:Technique {technique_id: "T1071"}), (b:Technique {technique_id: "T1048"})
MERGE (a)-[:FOLLOWED_BY {weight: 0.75}]->(b);
