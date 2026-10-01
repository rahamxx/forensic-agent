"""
Unit test suite for AI Forensic Investigation Agent API Endpoints.
Uses Flask's test_client to verify response structures, status codes, and error handling.
"""
import json
from app import app, load_or_train_models

def main():
    print("==================================================")
    print("Testing AI Forensic Investigation Agent API")
    print("==================================================")

    # Initialize models
    load_or_train_models()
    client = app.test_client()

    # 1. Test Scenarios endpoint
    print("\n[API TEST 1] GET /api/agent/scenarios")
    resp = client.get('/api/agent/scenarios')
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.get_json()
    assert 'scenarios' in data and len(data['scenarios']) >= 4, "Expected at least 4 scenarios"
    print(f"  Passed! Found {len(data['scenarios'])} preset demo scenarios:")
    for s in data['scenarios']:
        print(f"    - {s['title']} ({s['category']})")

    # 2. Test Investigate endpoint with URL
    print("\n[API TEST 2] POST /api/agent/investigate (URL Payload)")
    url_payload = {
        'type': 'url',
        'input': 'http://secure-login.paypal-billing-update.xyz/login.php?session=991823&token=chase_auth'
    }
    resp = client.post('/api/agent/investigate', json=url_payload)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    res = resp.get_json()
    assert 'investigation_id' in res, "Missing investigation_id"
    assert 'risk_level' in res, "Missing risk_level"
    assert 'tools_used' in res, "Missing tools_used"
    assert 'workflow_dag' in res, "Missing workflow_dag"
    assert 'evidence' in res, "Missing evidence"
    assert 'correlations' in res, "Missing correlations"
    assert 'recommendations' in res, "Missing recommendations"
    print(f"  Passed! Investigation ID: {res['investigation_id']}, Risk: {res['risk_level']}")

    inv_id = res['investigation_id']

    # 3. Test Investigate endpoint with Email
    print("\n[API TEST 3] POST /api/agent/investigate (Email Payload)")
    with open('sample_emails/phishing_appleid_locked.eml', 'r', encoding='utf-8') as f:
        email_text = f.read()

    email_payload = {
        'type': 'email',
        'input': email_text
    }
    resp = client.post('/api/agent/investigate', json=email_payload)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    res_email = resp.get_json()
    assert res_email['risk_level'] in ("HIGH", "CRITICAL"), f"Expected high risk, got {res_email['risk_level']}"
    assert res_email['human_review_required'] is True, "Human review should be required for phishing"
    assert "URLForensicsTool" in res_email['tools_used'], "URLForensicsTool should be dynamically triggered"
    print(f"  Passed! Email Phishing Risk: {res_email['risk_level']} (Score: {res_email['risk_score']}/100)")
    print(f"  Tools dynamically orchestrated: {res_email['tools_used']}")

    # 4. Test Retrieve cached investigation
    print(f"\n[API TEST 4] GET /api/agent/investigation/{inv_id}")
    resp = client.get(f'/api/agent/investigation/{inv_id}')
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    cached = resp.get_json()
    assert cached['investigation_id'] == inv_id, "Cached investigation mismatch"
    print("  Passed! Retrieved cached investigation accurately.")

    # 5. Test Generate Dossier HTML
    print(f"\n[API TEST 5] GET /api/agent/report/{inv_id}")
    resp = client.get(f'/api/agent/report/{inv_id}')
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    assert "AI DIGITAL FORENSICS INVESTIGATION REPORT" in resp.text, "Report title missing"
    print(f"  Passed! Report HTML generated ({len(resp.text)} bytes).")

    # 6. Test Error Handling (Empty payload)
    print("\n[API TEST 6] Error Handling: Empty payload")
    resp = client.post('/api/agent/investigate', json={})
    assert resp.status_code == 400, f"Expected 400 for empty payload, got {resp.status_code}"
    print("  Passed! Gracefully returned 400 with helpful error message.")

    print("\n==================================================")
    print("[SUCCESS] All AI Forensic Agent API Tests Passed!")
    print("==================================================")

if __name__ == '__main__':
    main()
