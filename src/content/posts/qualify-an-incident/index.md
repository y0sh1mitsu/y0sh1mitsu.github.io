---
title: "From Alert to Insight: The Art of Incident Qualification"
published: 2025-05-26
description: 'A short guide for those wishing to qualify an incident'
image: './illustration.jpg'
tags: [DFIR]
category: ''
draft: false 
---

# Introduction

During my career in incident response, I have had the opportunity to qualify a wide range of security incidents, from isolated malware infections to large-scale compromises. Through these experiences, and with the support of colleagues, I have gained valuable insights and practical advice that continue to shape my approach. This post shares those insights with practitioners facing similar challenges.

A well-executed incident qualification sets the tone for the entire response process. It clarifies the initial scope and improves evidence collection and technical analysis. A correct qualification helps align teams, reduces redundant work, and allows for faster containment and remediation.

One important mindset during incident qualification is to avoid accepting initial input without verification. In many investigations, early reports from users or stakeholders are incomplete, misunderstood, or sometimes incorrect. A useful reference here is the medical drama House MD, where Dr. House insists that "everybody lies." In cybersecurity, this usually results from stress, assumptions, or missing context rather than bad intent. Still, it often distorts the first version of events.

![](./house-doctor.gif)


# Aquire Context 

The first step usually involves gathering contextual information. Begin by asking for the date and time when the first suspicion appeared.

Make sure to agree on a consistent time reference, such as UTC. This is especially important if the client operates across multiple time zones. Then ask how the incident was detected. The answer might be an EDR alert, a curious system administrator, or a Managed Security Service Provider (MSSP). This gives early insight into how much visibility and detection capability the organization has.

Next, ask what has been observed since the first detection. This question is essential. In some cases, the attacker may still be active and attempting to escalate privileges. Accurate and timely information at this stage can make the difference between fast containment and a much larger compromise.

It is also important to ask about business impact. Find out what the company does, and what tools or systems are needed for employees to do their work. This can include business applications, communication tools, or access to shared files.  If the incident affects multiple environments, but one involves operational technology that is halting a factory and incurring substantial financial loss, then investigative efforts must prioritize containment and recovery in that area. The prioritization of DFIR tasks is often dictated by business continuity needs.

An often overlooked but critical question involves recent changes in the affected perimeter. Were there updates, migrations, or AV changes? This helps filter out potential false positives * **Insert your favorite antivirus update that has triggered false alarms on an entire network** * and flags risks like compromised software supply chains. Incidents like SolarWinds and 3CX have shown that legitimate updates can be used as backdoors by Threat Actors. Changes like these can also result in assets being unintentionally exposed to the internet during a migration.

Also ask to list any remedial actions taken by the customer: Assets physically turned off, network link cut, deployment of RMM tools, etc...


![](./S7Owqd.gif)
*When you can't investigate on RAM dump for the 7786678th time because everything has been turned off* 


# Ask about the perimeter impacted

Once the contextual information is gathered, the next focus is the assets identified by the client as impacted. At this stage, it's critical to capture technical and environmental metadata that will support both collection and triage phases. The following information should be requested:

- **Asset Name:** to establish a list across impacted systems.
- **Operating System:** essential for evaluating compatibility with potential forensic tools or EDR deployment. Unsupported OS versions can delay investigation.
- **Role:** whether it's a file server, print server, workstation, etc. This helps prioritize based on criticality.
- **Geolocation:** useful for correlating timestamps if multiple time zones are involved, or if deploying on-site responders is considered.
- **Physical or Virtual:** impacts both how to collect (and the possibility of snapshot collection in case of VMs) and how to isolate.
- **Antivirus Presence and Vendor:** helps assess protection gaps, identify false positives, or show possible threat actor activity on the console.
- **IP Address:** to enable quick lookup in logs, SIEM, or network maps.

Next, determine whether logging from these assets is centralized. This is crucial. Too often, responders encounter assets with local log rotation set to just one hour, rendering retrospective analysis impossible. In the case of long-term compromises like APTs, an organization might discover that they can’t confirm the initial access date because logs beyond a certain point no longer exist.

It is equally important to ask whether the impacted systems are tied to an authentication service, especially in environments where identity is a common attack vector. Determine the type (e.g., Active Directory, local accounts, federated identity, SAML, etc.), how many domains exist, and what trust relationships are configured. This influences the logs to request (Kerberos, VPN, AD events, etc.) and helps map out lateral movement potential. In the context of cloud investigation, always asking for the type of license can give an idea of which logs are available and for how long.

Also, gather details on the security controls in place on the impacted perimeter. This includes the presence of multi-factor authentication (MFA), endpoint detection and response (EDR) deployment, hardening practices, allowlisting, and segmentation. These elements are key to quickly assessing the maturity of the environment and the capabilities of the threat actor. For example, an attacker who manages to bypass EDR and MFA likely demonstrates a higher level of sophistication than one who fails at the first hurdle. Understanding which defenses were in place and whether they were effective or circumvented allows responders to estimate the adversary’s skill level and adjust investigation depth and containment urgency accordingly.

Another key topic is resilience. Are the systems backed up? If yes, are those backups tested and isolated from impacted domains? It’s not uncommon to discover backups that are either untested, outdated, or encrypted because they were part of the same trust zone targeted by ransomware. The answer here directly informs both containment and reconstruction strategies, including the establishment of a trustworthy pivot date (the earliest point at which systems can be considered uncompromised).

![](./angry-nervos.gif)
*When the CISO discovers that the backup plan isn't functional*

Finally, a description of the surrounding network is required:

- Firewall presence and configuration / logging
- Proxy logging
- DMZ & VLAN segmentation...

Ask about the Internet exposure, contrary to popular belief, phishing is not the primary cause of compromise in most cases observed during field operations. Many initial accesses stem from vulnerable perimeter assets: outdated Citrix, Ivanti, or Fortinet appliances, exposed RDP endpoints, etc. Understanding the exposure and protections in place around these assets often provides crucial context in tracing the initial breach path.

A quick win here is to ask for the external IP address of the impacted perimeter. This enables rapid verification using platforms like Censys or Shodan to determine what services and ports are publicly exposed, which can reveal misconfigurations or forgotten services vulnerable to exploitation.

Another key area to explore is the historical context of the perimeter in question. Ask whether there have been prior incidents affecting the same assets or environment. Sometimes an earlier event, poorly scoped, misclassified, or superficially investigated, can turn out to be the initial foothold of a threat actor who later resurfaces with elevated access and a clearer understanding of the environment. There are numerous real-world examples where credentials, defensive posture, or internal mappings were resold or reused in subsequent attacks.

Similarly, ask for the results of any recent perimeter penetration tests. Unfortunately, penetration test results are often underutilized by customers. A vulnerability may have been reported as critical, but not fixed due to time or resource constraints. Identifying these known weaknesses, especially those that have not been corrected, can shed light on how an attacker gained access to the system, and which weaknesses can still be exploited.

# Conclusion

There is no single model for qualifying security incidents. While frameworks and checklists are useful for avoiding blind spots, the process itself must remain flexible and context-driven. With experience, the flow of questions and validations becomes more natural. Patterns become easier to recognize, and your instincts improve as you learn how to read between the lines.

Each case refines your approach. Over time, incident qualification becomes more intuitive, almost like muscle memory. The goal is not to ask every possible question, but to identify the most relevant ones based on the situation. Knowing what to ask, when to ask it, and how to verify the answers is what enables a fast, reliable, and focused response.

The ultimate aim is simple. Build the most accurate and complete understanding of the situation, even when chaos is unfolding around you. That is the foundation for every effective response.