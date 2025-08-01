# AI Red Team Rules of Engagement (ROE) Checklist

---

## Pre-Engagement Authorization

###  Legal and Contractual Requirements

#### **Written Authorization**
- [ ] **Signed engagement agreement** from system owner/legal entity
- [ ] **Scope definition document** approved by stakeholders
- [ ] **Statement of Work (SOW)** with clear deliverables
- [ ] **Non-disclosure agreement (NDA)** executed by all team members
- [ ] **Insurance verification** for professional liability coverage
- [ ] **Legal review completion** of all engagement documents

#### **Regulatory Compliance**
- [ ] **Data protection laws** (GDPR, CCPA, PIPEDA) compliance verified
- [ ] **Industry regulations** (HIPAA, SOX, PCI-DSS) requirements reviewed
- [ ] **Export control regulations** for AI technology assessed
- [ ] **Local jurisdiction laws** for security testing confirmed
- [ ] **International legal considerations** for cross-border testing

#### **Stakeholder Approvals**
- [ ] **Executive sponsor** identified and approval documented
- [ ] **Technical system owner** authorization obtained
- [ ] **Legal department** sign-off received
- [ ] **Compliance team** approval documented
- [ ] **Risk management** assessment completed

---

## Scope Definition and Boundaries

###  Target System Identification

#### **AI Systems in Scope**
- [ ] **Chat interfaces** clearly identified (URLs, applications, platforms)
- [ ] **API endpoints** documented with base URLs and versions
- [ ] **AI models** specified by name, version, and deployment
- [ ] **Integration points** mapped for tool calling and function execution
- [ ] **User access levels** defined (standard user, premium, API tier)

#### **Testing Boundaries**
- [ ] **Permitted attack vectors** explicitly listed
- [ ] **Prohibited activities** clearly documented
- [ ] **Geographic restrictions** specified if applicable
- [ ] **Time boundaries** established (testing hours, duration)
- [ ] **Data handling limitations** defined

#### **Out-of-Scope Systems**
- [ ] **Infrastructure components** explicitly excluded
- [ ] **Network equipment** marked as off-limits
- [ ] **Other applications** on same infrastructure excluded
- [ ] **Production databases** specifically protected
- [ ] **User accounts** other than test accounts prohibited

---

## Testing Permissions and Restrictions

###  Permitted Testing Activities

#### **AI-Specific Testing**
- [ ] **Prompt injection attacks** authorized for safety testing
- [ ] **Jailbreaking attempts** permitted for guardrail validation
- [ ] **Content policy testing** approved within ethical boundaries
- [ ] **Model behavior analysis** allowed for consistency assessment
- [ ] **Context manipulation** permitted for conversation testing
- [ ] **Multi-turn attack sequences** authorized for persistence testing

#### **API Security Testing**
- [ ] **Authentication bypass testing** permitted on designated endpoints
- [ ] **Rate limiting assessment** authorized with specified thresholds
- [ ] **Parameter injection testing** approved for input validation
- [ ] **Token manipulation** allowed for authorization testing
- [ ] **API enumeration** permitted for endpoint discovery
- [ ] **Error message analysis** authorized for information disclosure

#### **Documentation and Evidence**
- [ ] **Screenshot capture** permitted for evidence collection
- [ ] **Conversation logging** authorized for analysis
- [ ] **Response recording** approved for validation
- [ ] **Network traffic capture** allowed for API testing
- [ ] **Metadata collection** permitted for technical analysis

###  Prohibited Activities

#### **Harmful Content Generation**
- [ ] **Illegal content creation** strictly prohibited
- [ ] **Child exploitation material** absolutely forbidden
- [ ] **Terrorist content** generation not permitted
- [ ] **Real person defamation** explicitly banned
- [ ] **Doxxing or harassment** content prohibited
- [ ] **Copyright infringement** content not allowed

#### **System Disruption**
- [ ] **Denial of service attacks** explicitly forbidden
- [ ] **Resource exhaustion** beyond agreed limits prohibited
- [ ] **Service degradation** causing user impact banned
- [ ] **Data corruption** or deletion strictly forbidden
- [ ] **System modification** beyond test scope prohibited

#### **Data and Privacy Violations**
- [ ] **Personal data extraction** of real users forbidden
- [ ] **Unauthorized data access** strictly banned
- [ ] **Data exfiltration** beyond test datasets forbidden
- [ ] **Privacy violation** of actual users prohibited

---

## Rate Limiting and Resource Management

###  Usage Restrictions

#### **API Rate Limits**
- [ ] **Maximum requests per minute** defined: ______
- [ ] **Daily request quota** established: ______
- [ ] **Token usage limits** specified: ______
- [ ] **Concurrent connection limits** set: ______
- [ ] **Burst request policy** documented
- [ ] **Rate limit escalation procedure** defined

#### **Chat Interface Limits**
- [ ] **Messages per conversation** limited to: ______
- [ ] **Conversations per day** restricted to: ______
- [ ] **File upload size limits** specified: ______
- [ ] **Image/document upload frequency** limited
- [ ] **Session duration limits** established

#### **Resource Consumption**
- [ ] **Computational resource limits** defined
- [ ] **Storage usage restrictions** specified
- [ ] **Bandwidth consumption limits** established
- [ ] **Cost thresholds** for expensive operations set
- [ ] **Monitoring alerts** configured for usage spikes

---

## Safety and Ethical Guidelines

###  Harm Prevention Measures

#### **Content Safety**
- [ ] **Harm threshold definitions** established
- [ ] **Content review process** for generated outputs
- [ ] **Immediate escalation triggers** identified
- [ ] **Content disposal procedures** defined
- [ ] **Screenshot redaction policies** established

#### **Testing Ethics**
- [ ] **Minimal harm principle** acknowledged and agreed
- [ ] **Proportional response** methodology confirmed
- [ ] **Educational purpose** as primary objective stated
- [ ] **Responsible disclosure** commitment documented
- [ ] **No malicious intent** declaration signed

#### **Research Integrity**
- [ ] **Objective analysis** commitment established
- [ ] **Bias mitigation** strategies implemented
- [ ] **Reproducible methodology** documented
- [ ] **Peer review process** for findings established
- [ ] **Publication ethics** guidelines followed

---

## Communication and Escalation

###  Contact Information and Procedures

#### **Primary Contacts**
- [ ] **Red team lead** contact details documented
- [ ] **Client technical contact** information confirmed
- [ ] **Legal contact** for urgent issues identified
- [ ] **Executive sponsor** escalation path established
- [ ] **Security incident contact** verified

#### **Communication Channels**
- [ ] **Daily status updates** method agreed upon
- [ ] **Secure communication** channels established
- [ ] **Emergency contact procedures** documented
- [ ] **After-hours escalation** process defined
- [ ] **Documentation sharing** methods secured

#### **Escalation Triggers**
- [ ] **Critical vulnerability discovery** escalation defined
- [ ] **Safety mechanism failure** response procedure
- [ ] **Harmful content generation** immediate escalation
- [ ] **System damage** emergency procedures
- [ ] **Legal concern** identification response

###  Incident Response Procedures

#### **Immediate Response (0-1 hour)**
- [ ] **Stop testing** on affected systems
- [ ] **Notify red team lead** immediately
- [ ] **Document incident** with timestamps
- [ ] **Preserve evidence** in secure location
- [ ] **Assess immediate risk** to ongoing operations

#### **Short-term Response (1-4 hours)**
- [ ] **Escalate to client** technical contact
- [ ] **Brief executive sponsor** on high-severity issues
- [ ] **Implement containment** measures if needed
- [ ] **Begin root cause** analysis
- [ ] **Coordinate with legal** if required

#### **Follow-up Actions (4-24 hours)**
- [ ] **Document lessons learned** for future engagements
- [ ] **Update ROE** if necessary
- [ ] **Resume testing** with modified approach if appropriate
- [ ] **Conduct team debrief** on incident handling
- [ ] **Review and update** escalation procedures

---

## Data Handling and Evidence Management

###  Information Security Requirements

#### **Data Classification**
- [ ] **Test data classification** levels established
- [ ] **Evidence handling** procedures documented
- [ ] **Retention policies** for findings specified
- [ ] **Disposal requirements** for sensitive data defined
- [ ] **Access controls** for evidence repository implemented

#### **Storage and Transmission**
- [ ] **Encrypted storage** for all test evidence required
- [ ] **Secure transmission** methods for sensitive findings
- [ ] **Access logging** for evidence repository enabled
- [ ] **Backup procedures** for critical evidence established
- [ ] **Chain of custody** documentation maintained

#### **Privacy Protection**
- [ ] **Personal data anonymization** procedures defined
- [ ] **Data minimization** principles applied
- [ ] **Consent requirements** for data usage verified
- [ ] **Right to deletion** procedures established
- [ ] **Cross-border data transfer** compliance ensured

---

## Quality Assurance and Validation

###  Testing Standards and Validation

#### **Methodology Compliance**
- [ ] **Standard testing procedures** followed consistently
- [ ] **Peer review process** for significant findings
- [ ] **Documentation standards** maintained throughout
- [ ] **Reproducibility requirements** met for all findings
- [ ] **Quality gates** established for deliverables

#### **Evidence Standards**
- [ ] **Screenshot quality** standards defined
- [ ] **Conversation log completeness** requirements specified
- [ ] **Metadata collection** standards established
- [ ] **Chain of evidence** documentation maintained
- [ ] **Validation testing** for all claimed vulnerabilities

#### **Reporting Requirements**
- [ ] **Executive summary** format agreed upon
- [ ] **Technical detail** level specified
- [ ] **Remediation guidance** depth established
- [ ] **Timeline requirements** for deliverables confirmed
- [ ] **Review and approval** process documented

---

## Post-Engagement Responsibilities

###  Cleanup and Knowledge Transfer

#### **System Restoration**
- [ ] **Test account cleanup** procedures defined
- [ ] **Temporary configuration** removal required
- [ ] **Evidence preservation** while removing test artifacts
- [ ] **System state validation** post-engagement
- [ ] **Documentation** of any persistent changes

#### **Knowledge Transfer**
- [ ] **Technical briefing** sessions scheduled
- [ ] **Remediation workshop** planning confirmed
- [ ] **Tool and technique** documentation transfer
- [ ] **Training recommendations** provided
- [ ] **Future assessment** planning discussed

#### **Ongoing Responsibilities**
- [ ] **Responsible disclosure** timeline for public findings
- [ ] **Confidentiality maintenance** for proprietary information
- [ ] **Update notifications** for evolving attack techniques
- [ ] **Consultation availability** for remediation questions
- [ ] **Follow-up assessment** scheduling if required

---

## Signatures and Approvals

###  Acknowledgment and Agreement

#### **Red Team Acknowledgment**
- [ ] **Red Team Lead** signature and date: ________________
- [ ] **Team members** have read and agreed to ROE
- [ ] **All team members** have signed individual acknowledgments
- [ ] **Insurance verification** completed for all team members
- [ ] **Background check** requirements met if specified

#### **Client Approvals**
- [ ] **System Owner** signature and date: ________________
- [ ] **Legal Representative** signature and date: ________________
- [ ] **Executive Sponsor** signature and date: ________________
- [ ] **Technical Contact** signature and date: ________________
- [ ] **Risk Management** signature and date: ________________

#### **Final Verification**
- [ ] **All sections** of ROE checklist completed
- [ ] **Exception documentation** attached if any items not applicable
- [ ] **Emergency contact** information verified and current
- [ ] **Engagement timeline** confirmed by all parties
- [ ] **ROE document version** control maintained

---

**Document Version**: 1.0  
**Engagement ID**: ________________  
**Effective Date**: ________________  
**Expiration Date**: ________________  
**Review Required By**: ________________

---

**Classification**: Confidential  
**Distribution**: Red Team, Client Stakeholders Only  
**Retention**: As per contractual agreement
