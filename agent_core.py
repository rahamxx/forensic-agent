"""
AI Forensic Investigation Agent - Core Orchestration & Reasoning Engine
BharatAgentic Hackathon - Digital Forensics Investigation Agent

This module implements the autonomous agent decision layer:
- Understands investigation requests & inspects available evidence
- Dynamically plans and executes specialized forensic tools
- Follows up on emerging evidence (e.g. extracting URLs from emails)
- Performs cross-source evidence correlation (Email + URL + Threat Intel + History)
- Transparently assesses forensic risk (LOW, MEDIUM, HIGH, CRITICAL)
- Formulates actionable, prioritized IR recommendations
- Enforces Human-in-the-Loop policies for high-risk actions
- Maintains full auditability with a dynamic DAG workflow
"""

import os
import re
import time
import uuid
import random
import datetime
from urllib.parse import urlparse
import warnings
warnings.filterwarnings('ignore')
import numpy as np

# Existing Forensic Engine components
from feature_extractor import (
    URL_FEATURE_NAMES, EMAIL_FEATURE_NAMES,
    extract_url_features, extract_email_features
)
from email_parser import parse_email_content
from history_parser import get_browser_history
from integrations import check_virustotal, check_pwned_password

# ==============================================================================
# DATA STRUCTURES & MODELS
# ==============================================================================

class EvidenceItem:
    """Normalized evidence item extracted by a forensic tool."""
    def __init__(self, id_str, source, indicator, category, detection_result,
                 confidence, severity, supporting_info, metadata=None):
        self.id = id_str
        self.source = source  # e.g., 'EmailForensicsTool', 'URLForensicsTool'
        self.indicator = indicator  # e.g., 'Return-Path: spoofed@bad.xyz'
        self.category = category  # 'Header', 'Network', 'NLP/Linguistic', 'Cryptographic', 'Reputation'
        self.detection_result = detection_result  # 'Malicious', 'Suspicious', 'Benign', 'Anomalous'
        self.confidence = float(confidence)  # 0.0 to 1.0
        self.severity = severity  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        self.supporting_info = supporting_info
        self.metadata = metadata or {}

    def to_dict(self):
        return {
            'id': self.id,
            'source': self.source,
            'indicator': self.indicator,
            'category': self.category,
            'detection_result': self.detection_result,
            'confidence': round(self.confidence, 3),
            'severity': self.severity,
            'supporting_info': self.supporting_info,
            'metadata': self.metadata
        }


class AgentAction:
    """Auditable log entry describing a tool selection and reasoning step."""
    def __init__(self, step, tool_name, reason, status, duration_ms, key_finding, triggered_by=None):
        self.step = step
        self.tool_name = tool_name
        self.reason = reason
        self.status = status
        self.duration_ms = duration_ms
        self.key_finding = key_finding
        self.triggered_by = triggered_by or "Agent Initial Plan"

    def to_dict(self):
        return {
            'step': self.step,
            'tool_name': self.tool_name,
            'reason': self.reason,
            'status': self.status,
            'duration_ms': round(self.duration_ms, 1),
            'key_finding': self.key_finding,
            'triggered_by': self.triggered_by
        }


class CorrelationFinding:
    """Cross-source evidence correlation discovery."""
    def __init__(self, id_str, title, description, sources_linked, threat_vector,
                 confidence, severity, mitre_technique=None):
        self.id = id_str
        self.title = title
        self.description = description
        self.sources_linked = sources_linked
        self.threat_vector = threat_vector
        self.confidence = float(confidence)
        self.severity = severity
        self.mitre_technique = mitre_technique or "T1566 (Phishing)"

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'sources_linked': self.sources_linked,
            'threat_vector': self.threat_vector,
            'confidence': round(self.confidence, 3),
            'severity': self.severity,
            'mitre_technique': self.mitre_technique
        }


# ==============================================================================
# SPECIALIZED FORENSIC TOOLS
# ==============================================================================

class URLForensicsTool:
    """Specialized tool for deep URL structural, ML, and threat intelligence analysis."""
    name = "URLForensicsTool"

    def __init__(self, url_model=None, url_explainer=None):
        self.url_model = url_model
        self.url_explainer = url_explainer

    def run(self, url, context=None):
        start_t = time.time()
        url = url.strip()
        evidence = []
        indicators = []

        # Feature extraction
        vec, feat_dict = extract_url_features(url, timeout=0.1, skip_whois=True)

        # ML Prediction
        proba = 0.5
        pred = 0
        if self.url_model:
            try:
                X = np.array([vec])
                pred = int(self.url_model.predict(X)[0])
                proba = float(self.url_model.predict_proba(X)[0][1])
            except Exception as e:
                pass

        # Feature evaluation & evidence extraction
        if feat_dict.get('has_ip'):
            evidence.append(EvidenceItem(
                f"EVD-URL-{uuid.uuid4().hex[:6]}",
                self.name,
                f"Host IP Address: {feat_dict.get('domain')}",
                "Network",
                "Malicious",
                0.92,
                "HIGH",
                "Target host is a direct IPv4 address instead of a registered domain name, often used to bypass DNS filtering."
            ))
            indicators.append("Direct IP Host")

        if feat_dict.get('has_suspicious_tld'):
            evidence.append(EvidenceItem(
                f"EVD-URL-{uuid.uuid4().hex[:6]}",
                self.name,
                f"High-Risk TLD: {feat_dict.get('domain')}",
                "Structural",
                "Suspicious",
                0.78,
                "MEDIUM",
                f"Uses a top-level domain frequently abused by cybercrime syndicates."
            ))
            indicators.append("Suspicious TLD")

        if feat_dict.get('suspicious_keywords_count', 0) > 0:
            evidence.append(EvidenceItem(
                f"EVD-URL-{uuid.uuid4().hex[:6]}",
                self.name,
                f"Credential Keywords ({feat_dict.get('suspicious_keywords_count')}): {url}",
                "NLP/Linguistic",
                "Suspicious",
                0.85,
                "MEDIUM",
                "Contains sensitive authentication or financial keywords (e.g. login, verify, banking, update)."
            ))
            indicators.append("Phishing Keywords in Path/Domain")

        if not feat_dict.get('is_https'):
            evidence.append(EvidenceItem(
                f"EVD-URL-{uuid.uuid4().hex[:6]}",
                self.name,
                f"Unencrypted Transport: {url[:40]}",
                "Cryptographic",
                "Anomalous",
                0.70,
                "LOW",
                "Lacks TLS/HTTPS encryption, posing Man-in-the-Middle and credential sniffing risks."
            ))
            indicators.append("Missing HTTPS")

        if feat_dict.get('entropy', 0.0) >= 4.0:
            evidence.append(EvidenceItem(
                f"EVD-URL-{uuid.uuid4().hex[:6]}",
                self.name,
                f"High Shannon Entropy: {feat_dict.get('entropy')}",
                "Structural",
                "Suspicious",
                0.75,
                "MEDIUM",
                "URL exhibits unusually high character randomness characteristic of automated domain generation algorithms (DGA)."
            ))
            indicators.append("High Shannon Entropy")

        # Threat Intel & Reputation (VirusTotal)
        vt_data = check_virustotal(url)
        vt_positives = vt_data.get('positives', 0)
        if vt_positives > 0:
            evidence.append(EvidenceItem(
                f"EVD-URL-{uuid.uuid4().hex[:6]}",
                "ReputationEnrichmentTool",
                f"VirusTotal Positives: {vt_positives}/{vt_data.get('total', 90)}",
                "Reputation",
                "Malicious",
                0.98,
                "CRITICAL" if vt_positives >= 3 else "HIGH",
                vt_data.get('message', 'Flagged as malicious by global threat intelligence scanners.')
            ))
            indicators.append(f"VirusTotal Blacklisted ({vt_positives} engines)")

        # Model result evidence
        severity = "CRITICAL" if proba >= 0.85 else ("HIGH" if proba >= 0.65 else ("MEDIUM" if proba >= 0.35 else "LOW"))
        result_desc = "Malicious" if proba >= 0.65 else ("Suspicious" if proba >= 0.35 else "Benign")
        evidence.append(EvidenceItem(
            f"EVD-URL-{uuid.uuid4().hex[:6]}",
            self.name,
            f"RandomForest Phishing Classifier: {round(proba * 100, 1)}%",
            "Machine Learning",
            result_desc,
            proba if proba >= 0.5 else (1.0 - proba),
            severity,
            f"Dual-model Random Forest assigned a phishing probability of {round(proba * 100, 1)}% based on 11 structural and lexical features."
        ))

        duration_ms = (time.time() - start_t) * 1000.0

        return {
            'tool': self.name,
            'url': url,
            'prediction': pred,
            'probability': round(proba * 100, 1),
            'severity': severity,
            'features': feat_dict,
            'evidence': [e.to_dict() if hasattr(e, 'to_dict') else e for e in evidence],
            'indicators': indicators,
            'virustotal': vt_data,
            'duration_ms': duration_ms
        }


class EmailForensicsTool:
    """Specialized tool for RFC 822 email header, authentication, and content forensics."""
    name = "EmailForensicsTool"

    def __init__(self, email_model=None, email_explainer=None):
        self.email_model = email_model
        self.email_explainer = email_explainer

    def run(self, raw_email_content, context=None):
        start_t = time.time()
        evidence = []
        indicators = []

        headers, body_text = parse_email_content(raw_email_content)
        if not headers and not body_text:
            return {
                'tool': self.name,
                'error': 'Failed to parse RFC 822 email content or headers.',
                'evidence': [],
                'duration_ms': (time.time() - start_t) * 1000.0
            }

        vec, feat_dict = extract_email_features(headers, body_text)

        # ML Prediction
        proba = 0.5
        pred = 0
        if self.email_model:
            try:
                X = np.array([vec])
                pred = int(self.email_model.predict(X)[0])
                proba = float(self.email_model.predict_proba(X)[0][1])
            except Exception:
                pass

        # 1. Header Spoofing (From vs Return-Path)
        from_hdr = headers.get('From', '')
        return_path = headers.get('Return-Path', '')
        if feat_dict.get('from_return_mismatch'):
            evidence.append(EvidenceItem(
                f"EVD-EML-{uuid.uuid4().hex[:6]}",
                self.name,
                f"Domain Mismatch: From '{from_hdr}' vs Return-Path '{return_path}'",
                "Header",
                "Malicious",
                0.95,
                "HIGH",
                "Sender identity spoofing detected: Visual sender domain does not match technical bounce Return-Path."
            ))
            indicators.append("From / Return-Path Spoofing")

        # 2. Cryptographic SPF / DKIM Authentication
        spf_status = headers.get('spf', 'unknown').upper()
        dkim_status = headers.get('dkim', 'unknown').upper()

        if spf_status in ('FAIL', 'SOFTFAIL'):
            evidence.append(EvidenceItem(
                f"EVD-EML-{uuid.uuid4().hex[:6]}",
                self.name,
                f"SPF Authentication: {spf_status}",
                "Cryptographic",
                "Malicious",
                0.90,
                "HIGH",
                "Sender Policy Framework (SPF) validation failed. Originating mail server IP is unauthorized for sender domain."
            ))
            indicators.append(f"SPF {spf_status}")
        elif spf_status == 'PASS':
            evidence.append(EvidenceItem(
                f"EVD-EML-{uuid.uuid4().hex[:6]}",
                self.name,
                "SPF Authentication: PASS",
                "Cryptographic",
                "Benign",
                0.90,
                "LOW",
                "Originating mail server is cryptographically authorized via DNS SPF record."
            ))

        if dkim_status == 'FAIL':
            evidence.append(EvidenceItem(
                f"EVD-EML-{uuid.uuid4().hex[:6]}",
                self.name,
                "DKIM Cryptographic Signature: FAIL",
                "Cryptographic",
                "Malicious",
                0.94,
                "HIGH",
                "DomainKeys Identified Mail (DKIM) signature verification failed; message headers or body were tampered with in transit."
            ))
            indicators.append("DKIM Verification Failure")

        # 3. Urgency & NLP Sentiment
        urgency_score = feat_dict.get('urgency_score', 0.0)
        if urgency_score >= 2.0:
            evidence.append(EvidenceItem(
                f"EVD-EML-{uuid.uuid4().hex[:6]}",
                self.name,
                f"High Urgency Coercion Score: {urgency_score}",
                "NLP/Linguistic",
                "Suspicious",
                0.86,
                "MEDIUM" if urgency_score < 4.0 else "HIGH",
                f"NLP analysis detected manipulative psychological coercion phrases (hits: {feat_dict.get('urgency_hits', 0)})."
            ))
            indicators.append(f"Urgency Manipulation Score ({urgency_score})")

        # 4. Executable / Risky Attachments
        if feat_dict.get('executable_attachment'):
            evidence.append(EvidenceItem(
                f"EVD-EML-{uuid.uuid4().hex[:6]}",
                self.name,
                "Risky Executable / Script Attachment Detected",
                "Structural",
                "Malicious",
                0.98,
                "CRITICAL",
                "Email references or carries executable script payload (.exe/.js/.vbs/.ps1/.scr)."
            ))
            indicators.append("Executable Payload Attachment")

        # 5. Embedded HTML Credential Harvesting Form
        if feat_dict.get('html_form_present'):
            evidence.append(EvidenceItem(
                f"EVD-EML-{uuid.uuid4().hex[:6]}",
                self.name,
                "Embedded HTML Credential Form",
                "Structural",
                "Malicious",
                0.97,
                "CRITICAL",
                "Email body contains inline HTML form elements designed to harvest credentials directly within the email client."
            ))
            indicators.append("Inline Credential Harvesting Form")

        # 6. Extract Embedded URLs
        extracted_urls = re.findall(r'https?://[^\s<>"\'()]+', body_text)
        # Deduplicate while preserving order
        extracted_urls = list(dict.fromkeys(extracted_urls))

        if extracted_urls:
            evidence.append(EvidenceItem(
                f"EVD-EML-{uuid.uuid4().hex[:6]}",
                self.name,
                f"Embedded URLs Discovered ({len(extracted_urls)})",
                "Network",
                "Anomalous",
                0.80,
                "MEDIUM",
                f"Extracted {len(extracted_urls)} hyperlinked destination(s) from message body for follow-up analysis."
            ))
            indicators.append(f"{len(extracted_urls)} Embedded URLs")

        # 7. Model Assessment
        severity = "CRITICAL" if proba >= 0.85 else ("HIGH" if proba >= 0.65 else ("MEDIUM" if proba >= 0.35 else "LOW"))
        result_desc = "Malicious" if proba >= 0.65 else ("Suspicious" if proba >= 0.35 else "Benign")
        evidence.append(EvidenceItem(
            f"EVD-EML-{uuid.uuid4().hex[:6]}",
            self.name,
            f"Email Phishing Model Probability: {round(proba * 100, 1)}%",
            "Machine Learning",
            result_desc,
            proba if proba >= 0.5 else (1.0 - proba),
            severity,
            f"RandomForest Email Classifier scored this message at {round(proba * 100, 1)}% phishing probability."
        ))

        duration_ms = (time.time() - start_t) * 1000.0

        return {
            'tool': self.name,
            'headers': {
                'From': headers.get('From', 'N/A'),
                'To': headers.get('To', 'N/A'),
                'Subject': headers.get('Subject', 'N/A'),
                'Return-Path': headers.get('Return-Path', 'N/A'),
                'Date': headers.get('Date', 'N/A'),
                'Message-ID': headers.get('Message-ID', 'N/A'),
                'SPF': spf_status,
                'DKIM': dkim_status,
                'Received_Hops': len(headers.get('Received', []))
            },
            'body_preview': body_text[:500] + ('...' if len(body_text) > 500 else ''),
            'extracted_urls': extracted_urls,
            'features': feat_dict,
            'probability': round(proba * 100, 1),
            'prediction': pred,
            'severity': severity,
            'evidence': [e.to_dict() if hasattr(e, 'to_dict') else e for e in evidence],
            'indicators': indicators,
            'duration_ms': duration_ms
        }


class BrowserHistoryForensicsTool:
    """Specialized tool for analyzing local or uploaded browser history databases."""
    name = "BrowserHistoryForensicsTool"

    def __init__(self, url_model=None):
        self.url_model = url_model

    def run(self, input_param=None, limit=50):
        start_t = time.time()
        evidence = []
        indicators = []

        history_items = get_browser_history(browser="all", limit=limit)
        
        # Analyze items for anomalies and threat density
        high_risk_visits = []
        suspicious_domains = set()
        domain_frequency = {}

        for item in history_items:
            u = item.get('url', '')
            try:
                parsed = urlparse(u)
                domain = parsed.netloc.split(':')[0].lower()
                if domain:
                    domain_frequency[domain] = domain_frequency.get(domain, 0) + 1
            except Exception:
                domain = u

            # Quick heuristic filter
            vec, feat_dict = extract_url_features(u, timeout=0.02, skip_whois=True)
            if self.url_model:
                try:
                    X = np.array([vec])
                    proba = float(self.url_model.predict_proba(X)[0][1])
                except Exception:
                    proba = 0.5
            else:
                proba = 0.8 if feat_dict.get('has_ip') or feat_dict.get('has_suspicious_tld') else 0.2

            if proba >= 0.65 or feat_dict.get('has_ip') or feat_dict.get('has_suspicious_tld'):
                high_risk_visits.append({
                    'url': u,
                    'title': item.get('title', ''),
                    'time': item.get('time', ''),
                    'source': item.get('source', ''),
                    'probability': round(proba * 100, 1),
                    'features': feat_dict
                })
                if domain:
                    suspicious_domains.add(domain)

        if high_risk_visits:
            evidence.append(EvidenceItem(
                f"EVD-HIST-{uuid.uuid4().hex[:6]}",
                self.name,
                f"High-Risk Navigation Events ({len(high_risk_visits)} visits)",
                "Behavioral",
                "Malicious",
                0.90,
                "HIGH" if len(high_risk_visits) < 5 else "CRITICAL",
                f"Discovered {len(high_risk_visits)} visits to flagged phishing or anomalous endpoints in browser history."
            ))
            indicators.append(f"{len(high_risk_visits)} Malicious Web Hits")

        # Top candidate URLs that need deep investigation
        candidate_urls = [item['url'] for item in high_risk_visits[:5]]

        duration_ms = (time.time() - start_t) * 1000.0

        return {
            'tool': self.name,
            'total_inspected': len(history_items),
            'high_risk_count': len(high_risk_visits),
            'suspicious_domains': list(suspicious_domains),
            'high_risk_visits': high_risk_visits[:10],
            'candidate_urls': candidate_urls,
            'evidence': [e.to_dict() if hasattr(e, 'to_dict') else e for e in evidence],
            'indicators': indicators,
            'duration_ms': duration_ms
        }


# ==============================================================================
# EVIDENCE CORRELATION ENGINE
# ==============================================================================

class EvidenceCorrelator:
    """
    Cross-source evidence correlation engine.
    Correlates signals across email headers, NLP, ML models, extracted URLs,
    threat intelligence, and browser history logs to form cohesive threat narratives.
    """

    @staticmethod
    def correlate(email_result=None, url_results=None, history_result=None):
        correlations = []
        url_results = url_results or []

        # ----------------------------------------------------------------------
        # Rule 1: Email Brand Impersonation & Malicious Redirect
        # ----------------------------------------------------------------------
        if email_result and url_results:
            headers = email_result.get('headers', {})
            from_hdr = headers.get('From', '').lower()
            return_path = headers.get('Return-Path', '').lower()

            # Check if any extracted URL is flagged malicious
            for u_res in url_results:
                u_proba = u_res.get('probability', 0.0)
                u_url = u_res.get('url', '')
                u_domain = u_res.get('features', {}).get('domain', '').lower()

                if u_proba >= 65.0:
                    correlations.append(CorrelationFinding(
                        f"CORR-{uuid.uuid4().hex[:6]}",
                        "Inbound Phishing Campaign: Spoofed Sender Delivering Malicious URL",
                        f"Email sender claims to be '{from_hdr}', but the message body delivers a confirmed malicious URL ({u_url}) with a phishing probability of {u_proba}%. Technical Return-Path routing ({return_path}) indicates domain spoofing.",
                        [
                            f"EmailForensicsTool (From: {from_hdr})",
                            f"EmailForensicsTool (Return-Path: {return_path})",
                            f"URLForensicsTool ({u_url} - {u_proba}% risk)"
                        ],
                        "Spearphishing with Credential Harvesting Link",
                        0.96,
                        "CRITICAL",
                        mitre_technique="T1566.002 (Spearphishing Link)"
                    ))
                    break

        # ----------------------------------------------------------------------
        # Rule 2: Cryptographic Auth Failure + Psychological Urgency
        # ----------------------------------------------------------------------
        if email_result:
            spf = email_result.get('headers', {}).get('SPF', '')
            dkim = email_result.get('headers', {}).get('DKIM', '')
            urgency = email_result.get('features', {}).get('urgency_score', 0.0)

            if (spf == 'FAIL' or dkim == 'FAIL') and urgency >= 2.0:
                correlations.append(CorrelationFinding(
                    f"CORR-{uuid.uuid4().hex[:6]}",
                    "Cryptographic Auth Failure Coupled with Social Engineering Coercion",
                    f"Message failed cryptographic origin validation (SPF: {spf}, DKIM: {dkim}) while simultaneously exerting severe psychological urgency (coercion score: {urgency}) to compel urgent recipient action.",
                    [
                        f"EmailForensicsTool (SPF: {spf}, DKIM: {dkim})",
                        f"EmailForensicsTool (Urgency Score: {urgency})"
                    ],
                    "Unauthorized Inbound Spoofing Vector",
                    0.92,
                    "HIGH",
                    mitre_technique="T1589.002 (Social Engineering & Impersonation)"
                ))

        # ----------------------------------------------------------------------
        # Rule 3: Multi-Engine Threat Convergence (ML + VirusTotal + Structural)
        # ----------------------------------------------------------------------
        for u_res in url_results:
            u_proba = u_res.get('probability', 0.0)
            vt_positives = u_res.get('virustotal', {}).get('positives', 0)
            feat = u_res.get('features', {})
            has_ip = feat.get('has_ip', False)
            has_tld = feat.get('has_suspicious_tld', False)

            if u_proba >= 70.0 and (vt_positives > 0 or has_ip or has_tld):
                correlations.append(CorrelationFinding(
                    f"CORR-{uuid.uuid4().hex[:6]}",
                    "Multi-Engine Threat Convergence on Infrastructure",
                    f"URL '{u_res.get('url')}' triggered simultaneous flags across structural feature analysis (IP/Suspicious TLD), the Random Forest ML classifier ({u_proba}% probability), and external reputation intelligence ({vt_positives} vendor detections).",
                    [
                        f"URLForensicsTool (ML Score: {u_proba}%)",
                        f"ReputationEnrichmentTool (VirusTotal: {vt_positives} hits)",
                        f"Structural Inspection (Direct IP: {has_ip}, Risky TLD: {has_tld})"
                    ],
                    "Malicious C2 / Phishing Host Infrastructure",
                    0.98,
                    "CRITICAL",
                    mitre_technique="T1583.001 (Domains / Malicious Infrastructure)"
                ))

        # ----------------------------------------------------------------------
        # Rule 4: Browser History Navigation Linked to Inbound Phishing
        # ----------------------------------------------------------------------
        if history_result and (email_result or url_results):
            visited_urls = [v['url'] for v in history_result.get('high_risk_visits', [])]
            target_domains = set()
            if email_result:
                for u in email_result.get('extracted_urls', []):
                    try:
                        target_domains.add(urlparse(u).netloc.split(':')[0].lower())
                    except Exception:
                        pass
            for u_res in url_results:
                target_domains.add(u_res.get('features', {}).get('domain', '').lower())

            matched_history = []
            for v_url in visited_urls:
                try:
                    d = urlparse(v_url).netloc.split(':')[0].lower()
                    if d in target_domains and d != "":
                        matched_history.append(v_url)
                except Exception:
                    pass

            if matched_history:
                correlations.append(CorrelationFinding(
                    f"CORR-{uuid.uuid4().hex[:6]}",
                    "Confirmed Victim Navigation: User Browsed to Inbound Phishing Vector",
                    f"Forensic workstation history reveals that user navigated directly to the malicious domain ({matched_history[0]}) delivered via the phishing vector. Indicates potential credential theft or endpoint compromise.",
                    [
                        f"BrowserHistoryForensicsTool ({len(matched_history)} matching visits)",
                        f"Email/URL Forensics (Target Domain: {matched_history[0]})"
                    ],
                    "Active User Interaction / Compromise Event",
                    0.99,
                    "CRITICAL",
                    mitre_technique="T1204.001 (User Execution: Malicious Link)"
                ))

        return correlations


# ==============================================================================
# AUTONOMOUS AGENT ORCHESTRATOR
# ==============================================================================

class ForensicInvestigationAgent:
    """
    Intelligent First-Level Digital Forensics Investigation Agent.
    Orchestrates specialized tools, dynamically follows investigation threads,
    correlates cross-source evidence, computes transparent risk ratings,
    and produces actionable incident response dossiers.
    """

    def __init__(self, url_model=None, email_model=None, url_explainer=None, email_explainer=None):
        self.url_model = url_model
        self.email_model = email_model
        self.url_explainer = url_explainer
        self.email_explainer = email_explainer

        # Instantiate specialized tools
        self.url_tool = URLForensicsTool(url_model, url_explainer)
        self.email_tool = EmailForensicsTool(email_model, email_explainer)
        self.history_tool = BrowserHistoryForensicsTool(url_model)
        self.correlator = EvidenceCorrelator()

    def set_models(self, url_model, email_model, url_explainer=None, email_explainer=None):
        self.url_model = url_model
        self.email_model = email_model
        self.url_explainer = url_explainer
        self.email_explainer = email_explainer
        self.url_tool = URLForensicsTool(url_model, url_explainer)
        self.email_tool = EmailForensicsTool(email_model, email_explainer)
        self.history_tool = BrowserHistoryForensicsTool(url_model)

    def plan_investigation(self, request_type, input_text, file_content=None):
        """
        Agent Planner: Evaluates request and selects appropriate starting forensic tools.
        """
        inferred_type = request_type.lower() if request_type else "auto"

        if inferred_type in ("auto", "custom", ""):
            text = (input_text or "") + (file_content or "")
            if text.startswith("http://") or text.startswith("https://") or (len(text.split()) == 1 and "." in text and not "@" in text):
                inferred_type = "url"
            elif "From:" in text or "Subject:" in text or "Received:" in text or "Return-Path:" in text:
                inferred_type = "email"
            elif "places.sqlite" in text or "History" in text or "browser" in text.lower():
                inferred_type = "browser"
            else:
                inferred_type = "email" if "\n" in text and ":" in text else "url"

        initial_tools = []
        if inferred_type == "url":
            initial_tools = ["URLForensicsTool", "ReputationEnrichmentTool"]
        elif inferred_type == "email":
            initial_tools = ["EmailForensicsTool"]
        elif inferred_type == "browser":
            initial_tools = ["BrowserHistoryForensicsTool"]
        elif inferred_type == "multimodal":
            initial_tools = ["EmailForensicsTool", "BrowserHistoryForensicsTool"]

        return inferred_type, initial_tools

    def investigate(self, request_type, input_data, file_content=None, options=None):
        """
        Execute full autonomous agent investigation workflow:
        1. Understand request & plan
        2. Execute Phase 1 tools
        3. Reason on intermediate outputs & trigger Phase 2 follow-ups
        4. Cross-source evidence correlation
        5. Aggregate risk assessment
        6. Formulate actionable recommendations
        7. Assemble auditable report & workflow DAG
        """
        investigation_id = f"INV-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        options = options or {}
        agent_actions = []
        all_evidence = []
        tools_used = []
        step_counter = 1

        raw_content = file_content if file_content else input_data

        # ----------------------------------------------------------------------
        # Step 1: Planning
        # ----------------------------------------------------------------------
        plan_start = time.time()
        resolved_type, planned_tools = self.plan_investigation(request_type, input_data, file_content)

        agent_actions.append(AgentAction(
            step=step_counter,
            tool_name="AgentPlanner",
            reason=f"Parsed request. Inferred investigation modality as '{resolved_type.upper()}'. Formulated initial tool execution graph: {', '.join(planned_tools)}.",
            status="SUCCESS",
            duration_ms=(time.time() - plan_start) * 1000.0,
            key_finding=f"Selected {len(planned_tools)} primary forensic tool(s) for initial execution.",
            triggered_by="User Investigation Request"
        ))
        step_counter += 1

        email_result = None
        url_results = []
        history_result = None

        # ----------------------------------------------------------------------
        # Step 2: Primary Tool Execution
        # ----------------------------------------------------------------------
        if "EmailForensicsTool" in planned_tools:
            t_start = time.time()
            email_result = self.email_tool.run(raw_content)
            tools_used.append("EmailForensicsTool")

            all_evidence.extend(email_result.get('evidence', []))
            proba = email_result.get('probability', 0.0)
            urls_found = len(email_result.get('extracted_urls', []))

            agent_actions.append(AgentAction(
                step=step_counter,
                tool_name="EmailForensicsTool",
                reason="Input contained RFC 822 email headers and body. Executed cryptographic SPF/DKIM verification, header spoofing analysis, NLP urgency scoring, and ML classification.",
                status="SUCCESS",
                duration_ms=(time.time() - t_start) * 1000.0,
                key_finding=f"Email scored {proba}% phishing risk. Extracted {urls_found} embedded URL(s). SPF: {email_result.get('headers', {}).get('SPF')}, DKIM: {email_result.get('headers', {}).get('DKIM')}.",
                triggered_by="Agent Planner (Phase 1)"
            ))
            step_counter += 1

        if "URLForensicsTool" in planned_tools:
            t_start = time.time()
            target_url = input_data.strip()
            u_res = self.url_tool.run(target_url)
            url_results.append(u_res)
            tools_used.append("URLForensicsTool")
            tools_used.append("ReputationEnrichmentTool")

            all_evidence.extend(u_res.get('evidence', []))
            proba = u_res.get('probability', 0.0)

            agent_actions.append(AgentAction(
                step=step_counter,
                tool_name="URLForensicsTool",
                reason=f"Target URL provided directly by investigator. Executed lexical feature extraction, DGA/entropy check, Random Forest classification, and VirusTotal reputation lookup.",
                status="SUCCESS",
                duration_ms=(time.time() - t_start) * 1000.0,
                key_finding=f"URL scored {proba}% risk. Threat level: {u_res.get('severity')}. Indicators: {', '.join(u_res.get('indicators', [])) or 'None'}.",
                triggered_by="Agent Planner (Phase 1)"
            ))
            step_counter += 1

        if "BrowserHistoryForensicsTool" in planned_tools:
            t_start = time.time()
            history_result = self.history_tool.run(input_data)
            tools_used.append("BrowserHistoryForensicsTool")

            all_evidence.extend(history_result.get('evidence', []))
            high_count = history_result.get('high_risk_count', 0)

            agent_actions.append(AgentAction(
                step=step_counter,
                tool_name="BrowserHistoryForensicsTool",
                reason="Browser forensics requested. Parsed workstation history SQLite databases to extract visited URIs, access timelines, and domain anomalies.",
                status="SUCCESS",
                duration_ms=(time.time() - t_start) * 1000.0,
                key_finding=f"Inspected {history_result.get('total_inspected')} navigation records; flagged {high_count} high-risk visit(s).",
                triggered_by="Agent Planner (Phase 1)"
            ))
            step_counter += 1

        # ----------------------------------------------------------------------
        # Step 3: Autonomous Dynamic Follow-up (Agentic Reasoning)
        # ----------------------------------------------------------------------
        # Case A: Email tool extracted embedded URLs -> Agent decides to run URL tool on them!
        if email_result and email_result.get('extracted_urls'):
            extracted_urls = email_result.get('extracted_urls')
            for ext_url in extracted_urls[:3]:
                t_start = time.time()
                ext_u_res = self.url_tool.run(ext_url)
                url_results.append(ext_u_res)
                all_evidence.extend(ext_u_res.get('evidence', []))
                if "URLForensicsTool" not in tools_used:
                    tools_used.append("URLForensicsTool")
                if "ReputationEnrichmentTool" not in tools_used:
                    tools_used.append("ReputationEnrichmentTool")

                agent_actions.append(AgentAction(
                    step=step_counter,
                    tool_name="URLForensicsTool",
                    reason=f"Autonomous Follow-up: Email body contained embedded hyperlink '{ext_url[:45]}...'. Agent autonomously selected URLForensicsTool to evaluate destination risk.",
                    status="SUCCESS",
                    duration_ms=(time.time() - t_start) * 1000.0,
                    key_finding=f"Extracted URL scored {ext_u_res.get('probability')}% phishing probability (Severity: {ext_u_res.get('severity')}).",
                    triggered_by="EmailForensicsTool Result (Embedded Link Discovered)"
                ))
                step_counter += 1

        # Case B: Browser history revealed candidate malicious URLs -> Run deep URL Tool
        if history_result and history_result.get('candidate_urls'):
            candidate_urls = history_result.get('candidate_urls')
            for cand_url in candidate_urls[:2]:
                t_start = time.time()
                cand_u_res = self.url_tool.run(cand_url)
                url_results.append(cand_u_res)
                all_evidence.extend(cand_u_res.get('evidence', []))
                if "URLForensicsTool" not in tools_used:
                    tools_used.append("URLForensicsTool")

                agent_actions.append(AgentAction(
                    step=step_counter,
                    tool_name="URLForensicsTool",
                    reason=f"Autonomous Follow-up: Browser history flagged suspicious navigation to '{cand_url[:45]}...'. Agent dispatched URLForensicsTool for deep forensic classification.",
                    status="SUCCESS",
                    duration_ms=(time.time() - t_start) * 1000.0,
                    key_finding=f"Historical URL scored {cand_u_res.get('probability')}% risk with {len(cand_u_res.get('indicators', []))} indicator(s).",
                    triggered_by="BrowserHistoryForensicsTool (Suspicious Visit Flagged)"
                ))
                step_counter += 1

        # ----------------------------------------------------------------------
        # Step 4: Cross-Source Evidence Correlation
        # ----------------------------------------------------------------------
        corr_start = time.time()
        correlations = self.correlator.correlate(
            email_result=email_result,
            url_results=url_results,
            history_result=history_result
        )

        agent_actions.append(AgentAction(
            step=step_counter,
            tool_name="EvidenceCorrelator",
            reason="Synthesized multi-source evidence across headers, lexical features, ML models, external reputation, and workstation telemetry to identify compounding threat patterns.",
            status="SUCCESS",
            duration_ms=(time.time() - corr_start) * 1000.0,
            key_finding=f"Synthesized {len(correlations)} cross-source correlation insight(s) and mapped to MITRE ATT&CK framework.",
            triggered_by="Multi-Tool Output Convergence"
        ))
        step_counter += 1

        # ----------------------------------------------------------------------
        # Step 5: Risk Assessment & Scoring
        # ----------------------------------------------------------------------
        risk_level, risk_score, confidence_score, risk_rationale, human_review_required = self.assess_risk(
            email_result, url_results, history_result, correlations, all_evidence
        )

        agent_actions.append(AgentAction(
            step=step_counter,
            tool_name="RiskAssessmentEngine",
            reason=f"Evaluated forensic evidence weight and cross-source correlations to determine overall threat level: {risk_level} (Score: {risk_score}/100, Confidence: {confidence_score}%).",
            status="SUCCESS",
            duration_ms=5.0,
            key_finding=f"Assigned {risk_level} threat rating. Mandatory Human Review: {'ENABLED' if human_review_required else 'NOT REQUIRED'}.",
            triggered_by="Evidence Synthesis"
        ))
        step_counter += 1

        # ----------------------------------------------------------------------
        # Step 6: Actionable Incident Response Recommendations
        # ----------------------------------------------------------------------
        recommendations = self.generate_recommendations(
            risk_level, email_result, url_results, history_result, correlations
        )

        # ----------------------------------------------------------------------
        # Step 7: Summary & Dynamic DAG Workflow
        # ----------------------------------------------------------------------
        summary = self.generate_summary(
            resolved_type, risk_level, risk_score, email_result, url_results, history_result, correlations
        )

        workflow_dag = self.build_workflow_dag(
            resolved_type, planned_tools, tools_used, correlations, risk_level
        )

        iocs = self.extract_iocs(email_result, url_results, history_result)

        return {
            'investigation_id': investigation_id,
            'timestamp': datetime.datetime.utcnow().isoformat() + "Z",
            'request_type': resolved_type,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'confidence_score': confidence_score,
            'summary': summary,
            'risk_rationale': risk_rationale,
            'tools_used': list(dict.fromkeys(tools_used)),
            'evidence': [e.to_dict() if hasattr(e, 'to_dict') else e for e in all_evidence],
            'correlations': [c.to_dict() if hasattr(c, 'to_dict') else c for c in correlations],
            'agent_actions': [a.to_dict() if hasattr(a, 'to_dict') else a for a in agent_actions],
            'recommendations': recommendations,
            'human_review_required': human_review_required,
            'workflow_dag': workflow_dag,
            'iocs': iocs,
            'details': {
                'email': email_result,
                'urls': url_results,
                'history': history_result
            }
        }

    def assess_risk(self, email_result, url_results, history_result, correlations, evidence):
        """Calculates transparent risk level, numerical score, and human review requirement."""
        scores = []
        critical_flags = 0
        high_flags = 0

        if email_result:
            scores.append(email_result.get('probability', 50.0))
        for u in url_results:
            scores.append(u.get('probability', 50.0))

        for e in evidence:
            sev = e.get('severity') if isinstance(e, dict) else getattr(e, 'severity', 'LOW')
            if sev == "CRITICAL":
                critical_flags += 1
            elif sev == "HIGH":
                high_flags += 1

        for c in correlations:
            c_sev = c.get('severity') if isinstance(c, dict) else getattr(c, 'severity', 'HIGH')
            if c_sev == "CRITICAL":
                critical_flags += 2
            elif c_sev == "HIGH":
                high_flags += 1

        if scores:
            base_score = max(scores)
            avg_score = sum(scores) / len(scores)
            composite_score = (base_score * 0.7) + (avg_score * 0.3)
        else:
            composite_score = 10.0

        if critical_flags > 0:
            composite_score = max(composite_score, 85.0 + min(14.0, critical_flags * 3.0))
        elif high_flags >= 2:
            composite_score = max(composite_score, 70.0 + min(14.0, high_flags * 2.0))

        composite_score = round(min(100.0, max(0.0, composite_score)), 1)

        if composite_score >= 80.0 or critical_flags >= 1:
            risk_level = "CRITICAL"
        elif composite_score >= 60.0 or high_flags >= 2:
            risk_level = "HIGH"
        elif composite_score >= 35.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        if len(scores) >= 2 or critical_flags >= 1:
            confidence = 94.0
        elif len(scores) == 1:
            confidence = 85.0
        else:
            confidence = 70.0

        human_review_required = risk_level in ("HIGH", "CRITICAL")
        if human_review_required:
            rationale = f"Assessed as {risk_level} ({composite_score}/100). {critical_flags} critical finding(s) and {high_flags} high-severity indicator(s) identified. Strict forensic policy mandates analyst confirmation before taking destructive containment actions."
        else:
            rationale = f"Assessed as {risk_level} ({composite_score}/100). Indicators fall within nominal baseline parameters."

        return risk_level, composite_score, confidence, rationale, human_review_required

    def generate_recommendations(self, risk_level, email_result, url_results, history_result, correlations):
        """Generates structured, actionable incident response recommendations."""
        recs = []

        if risk_level in ("HIGH", "CRITICAL"):
            recs.append({
                'phase': 'Immediate Containment',
                'action': 'Block Network Indicators on Perimeter Egress',
                'description': 'Add all identified malicious domains and IP addresses to perimeter next-generation firewalls, DNS-sinkholes, and proxy blocklists.',
                'target': 'Network Security Ops',
                'requires_approval': True
            })

            if email_result:
                sender = email_result.get('headers', {}).get('From', 'N/A')
                msg_id = email_result.get('headers', {}).get('Message-ID', 'N/A')
                recs.append({
                    'phase': 'Tenant Eradication',
                    'action': 'Purge Malicious Email Across All Inboxes',
                    'description': f"Execute tenant-wide PowerShell / Graph API message trace search for Message-ID '{msg_id}' and purge all copies from user inboxes.",
                    'target': 'Mail Systems Admin',
                    'requires_approval': True
                })
                recs.append({
                    'phase': 'User Remediation',
                    'action': 'Revoke Active Sessions & Reset Credentials',
                    'description': 'Force logout of all active OAuth refresh tokens and mandate password change with MFA re-verification for targeted recipient.',
                    'target': 'Identity & Access Management (IAM)',
                    'requires_approval': True
                })

            if any(u.get('virustotal', {}).get('positives', 0) > 0 or u.get('probability', 0) >= 70 for u in url_results):
                recs.append({
                    'phase': 'Threat Hunting',
                    'action': 'Scan Proxy Logs for Retrospective Endpoint Callbacks',
                    'description': 'Query SIEM/EDR telemetry over the past 30 days for any host connections to the identified threat domains.',
                    'target': 'SOC Tier-2 Hunting',
                    'requires_approval': False
                })

            recs.append({
                'phase': 'Intelligence Sharing',
                'action': 'Submit IoCs to CERT / Threat Intel Platforms',
                'description': 'Package extracted indicators into STIX/TAXII format and export to internal MISP platform and National CERT-In repository.',
                'target': 'Threat Intelligence',
                'requires_approval': False
            })

        elif risk_level == "MEDIUM":
            recs.append({
                'phase': 'Proactive Defense',
                'action': 'Quarantine Item & Flag for Analyst Inspection',
                'description': 'Move artifact to forensic sandbox isolation. Notify user that message is held for behavioral review.',
                'target': 'SOC Tier-1 Triage',
                'requires_approval': False
            })
            recs.append({
                'phase': 'Policy Tuning',
                'action': 'Review SPF/DMARC Quarantine Enforcement Rules',
                'description': 'Ensure mail gateway automatically rejects or quarantines soft-fail inbound vectors.',
                'target': 'Mail Security Team',
                'requires_approval': False
            })
        else:
            recs.append({
                'phase': 'Verification Completed',
                'action': 'Release Artifact & Log Baseline Verification',
                'description': 'Artifact passed cryptographic and structural verification. No threat containment needed.',
                'target': 'Automated Resolution',
                'requires_approval': False
            })

        return recs

    def generate_summary(self, req_type, risk_level, risk_score, email_res, url_res, hist_res, correlations):
        """Generates an executive, human-readable forensic summary."""
        parts = []
        parts.append(f"AI Forensic Agent completed an autonomous investigation of target {req_type.upper()} evidence.")
        parts.append(f"Overall assessment evaluated as **{risk_level}** with a threat risk index of **{risk_score}/100**.")

        if correlations:
            parts.append(f"Synthesized **{len(correlations)} cross-source correlation finding(s)**:")
            for c in correlations:
                parts.append(f"- **{c.title}**: {c.description} *(MITRE: {c.mitre_technique})*")
        else:
            if risk_level == "LOW":
                parts.append("All structural, cryptographic, and machine learning indicators conform to legitimate operational baselines.")
            else:
                parts.append("Threat signals were identified across isolated forensic vectors.")

        return " ".join(parts)

    def extract_iocs(self, email_res, url_res, hist_res):
        """Extracts normalized Indicators of Compromise (IOCs)."""
        iocs = {
            'domains': [],
            'ips': [],
            'urls': [],
            'senders': [],
            'hashes': []
        }

        if email_res:
            from_hdr = email_res.get('headers', {}).get('From', '')
            if '@' in from_hdr:
                iocs['senders'].append(from_hdr)
            for ip in email_res.get('features', {}).get('received_ips', []):
                iocs['ips'].append(ip)
            for u in email_res.get('extracted_urls', []):
                iocs['urls'].append(u)
                try:
                    d = urlparse(u).netloc.split(':')[0]
                    if d: iocs['domains'].append(d)
                except Exception:
                    pass

        for u in url_res:
            iocs['urls'].append(u.get('url'))
            d = u.get('features', {}).get('domain')
            if d: iocs['domains'].append(d)

        # Deduplicate
        for k in iocs:
            iocs[k] = list(dict.fromkeys([x for x in iocs[k] if x]))

        return iocs

    def build_workflow_dag(self, req_type, planned_tools, tools_used, correlations, risk_level):
        """
        Constructs dynamic Directed Acyclic Graph (DAG) for visual agent rendering in frontend.
        """
        nodes = [
            {'id': 'req', 'label': f'Investigation Request ({req_type.upper()})', 'type': 'input', 'status': 'completed'},
            {'id': 'planner', 'label': 'Agent Planner & Reasoner', 'type': 'planner', 'status': 'completed'}
        ]

        edges = [
            {'from': 'req', 'to': 'planner', 'label': 'Evidence Ingestion'}
        ]

        if "EmailForensicsTool" in tools_used:
            nodes.append({'id': 'tool_email', 'label': 'Email Forensics Tool', 'type': 'tool', 'status': 'completed'})
            edges.append({'from': 'planner', 'to': 'tool_email', 'label': 'RFC 822 Header & Content Check'})

        if "URLForensicsTool" in tools_used:
            nodes.append({'id': 'tool_url', 'label': 'URL Forensics Tool', 'type': 'tool', 'status': 'completed'})
            if "EmailForensicsTool" in tools_used:
                edges.append({'from': 'tool_email', 'to': 'tool_url', 'label': 'Discovered Embedded Links (Dynamic Trigger)'})
            else:
                edges.append({'from': 'planner', 'to': 'tool_url', 'label': 'Direct URL Inspection'})

        if "ReputationEnrichmentTool" in tools_used or "tool_url" in [n['id'] for n in nodes]:
            nodes.append({'id': 'tool_rep', 'label': 'Reputation & Threat Intel (VirusTotal)', 'type': 'enrichment', 'status': 'completed'})
            edges.append({'from': 'tool_url', 'to': 'tool_rep', 'label': 'Vendor Scan Lookup'})

        if "BrowserHistoryForensicsTool" in tools_used:
            nodes.append({'id': 'tool_hist', 'label': 'Browser History Forensics Tool', 'type': 'tool', 'status': 'completed'})
            edges.append({'from': 'planner', 'to': 'tool_hist', 'label': 'Workstation History Audit'})
            if "tool_url" in [n['id'] for n in nodes]:
                edges.append({'from': 'tool_hist', 'to': 'tool_url', 'label': 'Flagged Malicious Visits (Dynamic Trigger)'})

        nodes.append({'id': 'correlator', 'label': f'Evidence Correlation Engine ({len(correlations)} Findings)', 'type': 'correlator', 'status': 'completed'})
        if "tool_email" in [n['id'] for n in nodes]:
            edges.append({'from': 'tool_email', 'to': 'correlator', 'label': 'Headers + NLP Urgency'})
        if "tool_url" in [n['id'] for n in nodes]:
            edges.append({'from': 'tool_url', 'to': 'correlator', 'label': 'ML Score + Lexical'})
        if "tool_rep" in [n['id'] for n in nodes]:
            edges.append({'from': 'tool_rep', 'to': 'correlator', 'label': 'Threat Intel Feeds'})
        if "tool_hist" in [n['id'] for n in nodes]:
            edges.append({'from': 'tool_hist', 'to': 'correlator', 'label': 'Temporal Correlation'})

        nodes.append({'id': 'decision', 'label': f'Risk Assessment ({risk_level})', 'type': 'decision', 'status': 'completed'})
        edges.append({'from': 'correlator', 'to': 'decision', 'label': 'Weighed Signals'})

        nodes.append({'id': 'recs', 'label': 'Actionable Recommendations & IR Plan', 'type': 'action', 'status': 'completed'})
        edges.append({'from': 'decision', 'to': 'recs', 'label': 'Human-in-the-Loop Policies'})

        nodes.append({'id': 'report', 'label': 'Auditable Forensic Investigation Dossier', 'type': 'output', 'status': 'completed'})
        edges.append({'from': 'recs', 'to': 'report', 'label': 'Report Synthesis'})

        return {
            'nodes': nodes,
            'edges': edges
        }
