import json, base64, boto3, os, datetime, re, uuid, gzip, urllib.parse

SNS_TOPIC_ARN  = os.environ.get("SNS_TOPIC_ARN", "")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "sql-injection-findings")

sns      = boto3.client("sns", region_name="us-east-2")
dynamodb = boto3.resource("dynamodb", region_name="us-east-2")

SQLI_PATTERNS = [
    ("union_select",       re.compile(r'(?i)union\s+select'),                             'CRITICAL'),
    ("information_schema", re.compile(r'(?i)information_schema'),                         'CRITICAL'),
    ("drop_table",         re.compile(r'(?i)drop\s+table'),                               'CRITICAL'),
    ("always_true_bypass", re.compile(r"(?i)(\' ?or ?1 ?= ?1|\" ?or ?1 ?= ?1|or 1=1)"), 'HIGH'),
    ("sleep_delay",        re.compile(r'(?i)(sleep\s*\(|waitfor\s+delay)'),               'HIGH'),
    ("comment_injection",  re.compile(r"(--|#\s|/\*)"),                                   'MEDIUM'),
    ("hex_encoding",       re.compile(r'0x[0-9a-fA-F]{4,}'),                             'MEDIUM'),
    ("single_quote",       re.compile(r"['\"]\s*(;|--|#|\/\*)"),                          'LOW'),
]
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def classify(uri, query):
    full_input = urllib.parse.unquote_plus((uri or '') + '?' + (query or ''))
    matches, max_sev = [], "NONE"
    for name, pattern, severity in SQLI_PATTERNS:
        if pattern.search(full_input):
            matches.append({"pattern": name, "severity": severity})
            if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(max_sev, 0):
                max_sev = severity
    return {"detected": bool(matches), "severity": max_sev, "matches": matches}


def write_to_dynamodb(finding):
    try:
        table  = dynamodb.Table(DYNAMODB_TABLE)
        expiry = int((datetime.datetime.utcnow() + datetime.timedelta(days=7)).timestamp())
        table.put_item(Item={
            "id":         str(uuid.uuid4()),
            "timestamp":  finding["timestamp"],
            "source_ip":  finding["source_ip"],
            "uri":        finding["uri"],
            "query":      finding["query"],
            "severity":   finding["severity"],
            "patterns":   json.dumps(finding["patterns"]),
            "waf_action": finding["waf_action"],
            "expiry":     expiry,
        })
        print(f"[DynamoDB] Written: {finding['severity']} | {finding['source_ip']}")
    except Exception as e:
        print(f"[DynamoDB ERROR] {e}")


def process_waf_log(waf_log, detections):
    """Process a single WAF log entry."""
    http_req  = waf_log.get("httpRequest", {})
    uri       = http_req.get("uri", "")
    query     = http_req.get("args", "")
    source_ip = http_req.get("clientIp", "unknown")
    waf_action = waf_log.get("action", "ALLOW")

    result = classify(uri, query)
    if not result["detected"]:
        return

    finding = {
        "timestamp":  datetime.datetime.utcnow().isoformat(),
        "source_ip":  source_ip,
        "uri":        uri,
        "query":      query[:200],
        "severity":   result["severity"],
        "patterns":   result["matches"],
        "waf_action": waf_action,
    }
    detections.append(finding)
    print(f"[DETECTION] {result['severity']} | {source_ip} | {uri}")

    write_to_dynamodb(finding)

    if result["severity"] in ("HIGH", "CRITICAL") and SNS_TOPIC_ARN:
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"[{result['severity']}] SQL Injection Detected — {source_ip}",
                Message=json.dumps(finding, indent=2),
            )
        except Exception as e:
            print(f"[SNS ERROR] {e}")


def lambda_handler(event, context):
    detections = []
    records = event.get("Records", [])
    print(f"[INFO] Processing {len(records)} Kinesis record(s)")

    for record in records:
        try:
            raw_bytes = base64.b64decode(record["kinesis"]["data"])
        except Exception as e:
            print(f"[ERROR] base64 decode failed: {e}")
            continue

        # CloudWatch Subscription Filter compresses with gzip
        try:
            raw = gzip.decompress(raw_bytes).decode("utf-8")
        except (OSError, Exception):
            try:
                raw = raw_bytes.decode("utf-8")
            except Exception as e:
                print(f"[ERROR] decode failed: {e}")
                continue

        try:
            outer = json.loads(raw)
        except json.JSONDecodeError as e:
            print(f"[ERROR] JSON parse failed: {e} | raw[:100]={raw[:100]}")
            continue

        # CloudWatch Subscription Filter envelope:
        # { "messageType": "DATA_MESSAGE", "logEvents": [{"message": "<WAF JSON>"}] }
        if "logEvents" in outer:
            print(f"[INFO] CW envelope with {len(outer['logEvents'])} log events")
            for log_event in outer["logEvents"]:
                try:
                    waf_log = json.loads(log_event.get("message", "{}"))
                    process_waf_log(waf_log, detections)
                except Exception as e:
                    print(f"[ERROR] inner log parse: {e}")
        else:
            # Direct WAF JSON (e.g. from Firehose or direct Kinesis)
            process_waf_log(outer, detections)

    print(f"[INFO] Done. {len(detections)} detections from {len(records)} records")
    return {"statusCode": 200, "detections": len(detections)}
