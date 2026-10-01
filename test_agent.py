"""
Test script to verify AI Forensic Investigation Agent capabilities.
"""
import os
import joblib
from agent_core import ForensicInvestigationAgent

def main():
    print("==================================================")
    print("Testing AI Forensic Investigation Agent")
    print("==================================================")

    # Load models
    url_model = joblib.load('models/url_phishing_model.pkl')
    email_model = joblib.load('models/email_phishing_model.pkl')
    print("Loaded ML models successfully.")

    agent = ForensicInvestigationAgent(url_model=url_model, email_model=email_model)

    # Test 1: Apple ID Phishing Email with Malicious Link
    print("\n[TEST 1] Investigating Phishing Email with Embedded Link...")
    with open('sample_emails/phishing_appleid_locked.eml', 'r', encoding='utf-8') as f:
        email_content = f.read()

    res1 = agent.investigate(request_type="email", input_data=email_content)
    print(f"Investigation ID: {res1['investigation_id']}")
    print(f"Risk Level:       {res1['risk_level']} (Score: {res1['risk_score']}/100)")
    print(f"Human Review:     {res1['human_review_required']}")
    print(f"Tools Used:       {res1['tools_used']}")
    print(f"Evidence Count:   {len(res1['evidence'])}")
    print(f"Correlations:     {len(res1['correlations'])}")
    print(f"Agent Actions:    {len(res1['agent_actions'])}")
    for act in res1['agent_actions']:
        print(f"  Step {act['step']}: [{act['tool_name']}] -> {act['key_finding']}")
    for corr in res1['correlations']:
        print(f"  [CORRELATION] {corr['title']}")
    assert res1['risk_level'] in ("HIGH", "CRITICAL"), "Test 1 failed: Expected HIGH or CRITICAL"
    assert "URLForensicsTool" in res1['tools_used'], "Test 1 failed: Agent should have dynamically triggered URL tool"

    # Test 2: Direct Malicious URL
    print("\n[TEST 2] Investigating Direct Malicious URL...")
    test_url = "http://secure-login.paypal-billing-update.xyz/login.php?session=991823&token=chase_auth"
    res2 = agent.investigate(request_type="url", input_data=test_url)
    print(f"Investigation ID: {res2['investigation_id']}")
    print(f"Risk Level:       {res2['risk_level']} (Score: {res2['risk_score']}/100)")
    print(f"Tools Used:       {res2['tools_used']}")
    print(f"Correlations:     {len(res2['correlations'])}")
    assert res2['risk_level'] in ("HIGH", "CRITICAL"), "Test 2 failed: Expected HIGH or CRITICAL"

    # Test 3: Legitimate GitHub Security Email
    print("\n[TEST 3] Investigating Legitimate Authenticated Email...")
    with open('sample_emails/legit_github_security.eml', 'r', encoding='utf-8') as f:
        legit_content = f.read()
    res3 = agent.investigate(request_type="email", input_data=legit_content)
    print(f"Investigation ID: {res3['investigation_id']}")
    print(f"Risk Level:       {res3['risk_level']} (Score: {res3['risk_score']}/100)")
    print(f"Human Review:     {res3['human_review_required']}")
    assert res3['risk_level'] == "LOW", f"Test 3 failed: Expected LOW, got {res3['risk_level']}"
    assert res3['human_review_required'] is False, "Test 3 failed: Legitimate should not require human review"

    # Test 4: Browser History Forensics
    print("\n[TEST 4] Investigating Browser History Forensics...")
    res4 = agent.investigate(request_type="browser", input_data="Investigate local browser history for phishing and anomalies")
    print(f"Investigation ID: {res4['investigation_id']}")
    print(f"Risk Level:       {res4['risk_level']} (Score: {res4['risk_score']}/100)")
    print(f"Tools Used:       {res4['tools_used']}")
    print(f"Agent Actions:    {len(res4['agent_actions'])}")
    for act in res4['agent_actions']:
        print(f"  Step {act['step']}: [{act['tool_name']}] -> {act['key_finding']}")
    assert "BrowserHistoryForensicsTool" in res4['tools_used']

    print("\n==================================================")
    print("[SUCCESS] All AI Forensic Agent Core Unit Tests Passed!")
    print("==================================================")

if __name__ == '__main__':
    main()
