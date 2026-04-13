import re

SQLI_PATTERNS = [
    ("union_select",        re.compile(r'(?i)union\s+select'),                             'CRITICAL'),
    ("information_schema",  re.compile(r'(?i)information_schema'),                         'CRITICAL'),
    ("drop_table",          re.compile(r'(?i)drop\s+table'),                               'CRITICAL'),
    ("always_true_bypass",  re.compile(r"(?i)(\' ?or ?1 ?= ?1|\" ?or ?1 ?= ?1|or 1=1)"), 'HIGH'),
    ("sleep_delay",         re.compile(r'(?i)(sleep\s*\(|waitfor\s+delay)'),               'HIGH'),
    ("comment_injection",   re.compile(r"(--\s|#\s|/\*)"),                                 'MEDIUM'),
    ("hex_encoding",        re.compile(r'0x[0-9a-fA-F]{4,}'),                             'MEDIUM'),
    ("single_quote",        re.compile(r"['\"]\s*(;|--|#|\/\*)"),                          'LOW'),
]

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def classify(uri, query):
    full_input = (uri or '') + '?' + (query or '')
    matches = []
    max_severity = "NONE"
    for name, pattern, severity in SQLI_PATTERNS:
        if pattern.search(full_input):
            matches.append({"pattern": name, "severity": severity})
            if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(max_severity, 0):
                max_severity = severity
    return {"detected": len(matches) > 0, "severity": max_severity, "matches": matches}

def test_union_select_is_critical():
    r = classify('/search', "name=' UNION SELECT 1,2,3--")
    assert r['detected'] == True
    assert r['severity'] == 'CRITICAL'
    print("PASSED: test_union_select_is_critical")

def test_or_bypass_is_high():
    r = classify('/login', "username=admin' OR 1=1--")
    assert r['detected'] == True
    assert r['severity'] == 'HIGH'
    print("PASSED: test_or_bypass_is_high")

def test_sleep_is_high():
    r = classify('/login', "password=' AND SLEEP(5)--")
    assert r['detected'] == True
    assert r['severity'] == 'HIGH'
    print("PASSED: test_sleep_is_high")

def test_normal_request_not_detected():
    r = classify('/search', 'name=John')
    assert r['detected'] == False
    print("PASSED: test_normal_request_not_detected")

def test_information_schema_is_critical():
    r = classify('/search', "name=' UNION SELECT table_name FROM information_schema.tables--")
    assert r['detected'] == True
    assert r['severity'] == 'CRITICAL'
    print("PASSED: test_information_schema_is_critical")

if __name__ == "__main__":
    test_union_select_is_critical()
    test_or_bypass_is_high()
    test_sleep_is_high()
    test_normal_request_not_detected()
    test_information_schema_is_critical()
    print("\nAll tests passed!")
