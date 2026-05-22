from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import os
import httpx
import json
import hashlib
from datetime import datetime, timezone
from typing import List, Optional

app = FastAPI(title="Project Aegis MCP Server", version="0.2.0")

# --- Configuration ---
ES_URL = os.environ.get("ES_URL", "https://es01:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "changeme")
RULES_PATH = os.environ.get("AEGIS_RULES_PATH", "/app/rules/aegis_detection_rules.json")
ALERT_INDEX = os.environ.get("AEGIS_ALERT_INDEX", "aegis-alerts-default")

# --- Schemas ---
class QueryRequest(BaseModel):
    query: str
    index: str = "logs-*"
    size: int = 10

class QueryResponse(BaseModel):
    hits: list
    total: int

class RuleRunRequest(BaseModel):
    rule_ids: Optional[List[str]] = None
    index: Optional[str] = None
    size: int = Field(default=100, ge=1, le=1000)
    create_alerts: bool = True

class AlertSearchRequest(BaseModel):
    query: str = "*"
    size: int = Field(default=20, ge=1, le=200)

class EsStatus(BaseModel):
    cluster_name: Optional[str] = None
    license_type: Optional[str] = None
    license_status: Optional[str] = None
    simulation_events: int = 0
    aegis_alerts: int = 0


MCP_TOOL_DEFINITIONS = [
    {
        "name": "search_siem",
        "description": "Search Elasticsearch/Kibana SIEM data with a query_string query.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "index": {"type": "string", "default": "logs-*"},
                "size": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_security_status",
        "description": "Return Elastic cluster name, license, simulation event count, and Aegis alert count.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_detection_rules",
        "description": "List Aegis detection rules and MITRE mappings.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "run_detection_rules",
        "description": "Run Aegis detection rules and optionally create alerts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_ids": {"type": "array", "items": {"type": "string"}},
                "index": {"type": "string"},
                "size": {"type": "integer", "default": 100},
                "create_alerts": {"type": "boolean", "default": True},
            },
        },
    },
    {
        "name": "list_aegis_alerts",
        "description": "Search lab-managed Aegis alerts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "default": "*"},
                "size": {"type": "integer", "default": 20},
            },
        },
    },
    {
        "name": "get_attack_surface",
        "description": "Summarize hosts and users seen in simulation data.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_rules():
    try:
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return []
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Invalid rules file: {e}")


def alert_id(rule_id, event_id):
    raw = f"{rule_id}:{event_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


async def es_request(method, path, **kwargs):
    headers = {"Content-Type": "application/json"}
    headers.update(kwargs.pop("headers", {}))
    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        response = await client.request(
            method,
            f"{ES_URL}{path}",
            auth=(ES_USER, ES_PASSWORD),
            headers=headers,
            **kwargs,
        )

    if response.status_code >= 300:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    if not response.text:
        return {}
    return response.json()


async def es_count(index, query="*"):
    payload = {"query": {"query_string": {"query": query}}}
    try:
        data = await es_request("POST", f"/{index}/_count", json=payload)
    except HTTPException as e:
        if e.status_code == 404:
            return 0
        raise
    return data.get("count", 0)


async def ensure_alert_index():
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event": {"properties": {"kind": {"type": "keyword"}, "module": {"type": "keyword"}}},
                "rule": {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}},
                "kibana": {"properties": {"alert": {"properties": {"severity": {"type": "keyword"}}}}},
                "threat": {"properties": {"technique": {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}}}},
                "host": {"properties": {"name": {"type": "keyword"}, "hostname": {"type": "keyword"}}},
                "source": {"properties": {"ip": {"type": "ip"}}},
                "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
            }
        }
    }
    try:
        await es_request("PUT", f"/{ALERT_INDEX}", json=mapping)
    except HTTPException as e:
        if e.status_code != 400 or "resource_already_exists_exception" not in str(e.detail):
            raise


def build_alert(rule, hit):
    source = hit.get("_source", {})
    mitre = rule.get("mitre", {})
    return {
        "@timestamp": utc_now(),
        "event": {"kind": "signal", "module": "aegis", "action": "aegis-rule-match"},
        "message": f"{rule['name']} matched event {hit.get('_id')}",
        "rule": {
            "id": rule["id"],
            "name": rule["name"],
            "description": rule.get("description", ""),
            "risk_score": rule.get("risk_score", 0),
        },
        "kibana": {"alert": {"severity": rule.get("severity", "low"), "reason": rule.get("query", "")}},
        "threat": {
            "tactic": {"name": mitre.get("tactic")},
            "technique": {"id": mitre.get("technique_id"), "name": mitre.get("technique_name")},
        },
        "source_event": {
            "id": hit.get("_id"),
            "index": hit.get("_index"),
            "timestamp": source.get("@timestamp"),
        },
        "host": source.get("host", {}),
        "process": source.get("process", {}),
        "source": source.get("source", {}),
        "destination": source.get("destination", {}),
    }

# --- MCP Tooling Logic ---
# In a full MCP implementation, this would follow the Model Context Protocol spec.
# For this lab, we provide an "AI Gateway" that exposes SIEM tools to an agent.

@app.get("/health")
async def health():
    return {"status": "Aegis AI Gateway is online"}

@app.get("/mcp/tools")
async def list_mcp_tools():
    return {
        "tools": MCP_TOOL_DEFINITIONS,
        "rest_endpoints": {
            "search_siem": "POST /tools/search",
            "get_security_status": "GET /tools/security/status",
            "list_detection_rules": "GET /tools/rules",
            "run_detection_rules": "POST /tools/rules/run",
            "list_aegis_alerts": "POST /tools/alerts",
            "get_attack_surface": "GET /tools/get_attack_surface",
        },
    }

@app.post("/mcp")
async def mcp_json_rpc(payload: dict):
    request_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params", {})

    try:
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "project-aegis-ai-gateway", "version": "0.2.0"},
            }
        elif method == "tools/list":
            result = {"tools": MCP_TOOL_DEFINITIONS}
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            output = await call_mcp_tool(name, arguments)
            result = {"content": [{"type": "text", "text": json.dumps(output, ensure_ascii=False)}]}
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"Unsupported method: {method}"},
            }

        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except HTTPException as e:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": e.status_code, "message": str(e.detail)}}
    except Exception as e:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": str(e)}}


async def call_mcp_tool(name, arguments):
    if name == "search_siem":
        return (await search_siem(QueryRequest(**arguments))).model_dump()
    if name == "get_security_status":
        return (await get_security_status()).model_dump()
    if name == "list_detection_rules":
        return await list_detection_rules()
    if name == "run_detection_rules":
        return await run_detection_rules(RuleRunRequest(**arguments))
    if name == "list_aegis_alerts":
        return (await list_aegis_alerts(AlertSearchRequest(**arguments))).model_dump()
    if name == "get_attack_surface":
        return await get_attack_surface()
    raise HTTPException(status_code=404, detail=f"Unknown MCP tool: {name}")

@app.post("/tools/search", response_model=QueryResponse)
async def search_siem(request: QueryRequest):
    """
    Executes a raw Elasticsearch query. This tool can be used by an AI agent 
    to retrieve context from logs.
    """
    url = f"{ES_URL}/{request.index}/_search"
    
    # Payload for ES search
    # This allows the AI to send KQL-style queries or raw DSL
    payload = {
        "query": {
            "query_string": {
                "query": request.query
            }
        },
        "size": request.size,
        "sort": [{"@timestamp": "desc"}]
    }

    try:
        data = await es_request("POST", f"/{request.index}/_search", json=payload)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    hits = [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
    total = data.get("hits", {}).get("total", {}).get("value", 0)
    return QueryResponse(hits=hits, total=total)

@app.get("/tools/security/status", response_model=EsStatus)
async def get_security_status():
    root = await es_request("GET", "/")
    license_data = await es_request("GET", "/_license")
    simulation_events = await es_count("logs-aegis-simulation-*")
    aegis_alerts = await es_count(ALERT_INDEX)
    license_body = license_data.get("license", {})
    return EsStatus(
        cluster_name=root.get("cluster_name"),
        license_type=license_body.get("type"),
        license_status=license_body.get("status"),
        simulation_events=simulation_events,
        aegis_alerts=aegis_alerts,
    )

@app.get("/tools/rules")
async def list_detection_rules():
    rules = load_rules()
    return {"count": len(rules), "rules": rules}

@app.post("/tools/rules/run")
async def run_detection_rules(request: RuleRunRequest):
    rules = load_rules()
    if request.rule_ids:
        wanted = set(request.rule_ids)
        rules = [rule for rule in rules if rule.get("id") in wanted]

    await ensure_alert_index()
    results = []

    for rule in rules:
        index = request.index or rule.get("index", "logs-*")
        payload = {
            "query": {"query_string": {"query": rule["query"]}},
            "size": request.size,
            "sort": [{"@timestamp": "desc"}],
        }
        data = await es_request("POST", f"/{index}/_search", json=payload)
        hits = data.get("hits", {}).get("hits", [])
        created = 0

        if request.create_alerts and hits:
            actions = []
            for hit in hits:
                doc_id = alert_id(rule["id"], hit["_id"])
                actions.append(json.dumps({"index": {"_index": ALERT_INDEX, "_id": doc_id}}))
                actions.append(json.dumps(build_alert(rule, hit)))

            bulk_body = "\n".join(actions) + "\n"
            bulk_data = await es_request(
                "POST",
                "/_bulk",
                content=bulk_body,
                headers={"Content-Type": "application/x-ndjson"},
            )
            created = sum(1 for item in bulk_data.get("items", []) if item.get("index", {}).get("result") == "created")

        results.append({
            "rule_id": rule["id"],
            "name": rule["name"],
            "matches": len(hits),
            "alerts_created": created,
            "severity": rule.get("severity", "low"),
            "risk_score": rule.get("risk_score", 0),
        })

    return {
        "rules_evaluated": len(rules),
        "alert_index": ALERT_INDEX,
        "results": results,
    }

@app.post("/tools/alerts", response_model=QueryResponse)
async def list_aegis_alerts(request: AlertSearchRequest):
    payload = {
        "query": {"query_string": {"query": request.query}},
        "size": request.size,
        "sort": [{"@timestamp": "desc"}],
    }
    try:
        data = await es_request("POST", f"/{ALERT_INDEX}/_search", json=payload)
    except HTTPException as e:
        if e.status_code == 404:
            return QueryResponse(hits=[], total=0)
        raise

    hits = [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
    total = data.get("hits", {}).get("total", {}).get("value", 0)
    return QueryResponse(hits=hits, total=total)

@app.get("/tools/get_attack_surface")
async def get_attack_surface():
    """
    Returns a summary of unique hosts and users seen in the simulation index.
    Useful for an AI to understand the lab environment.
    """
    url = f"{ES_URL}/logs-aegis-simulation-*/_search"
    payload = {
        "size": 0,
        "aggs": {
            "hosts": {"terms": {"field": "host.hostname.keyword"}},
            "users": {"terms": {"field": "user.name.keyword"}}
        }
    }
    
    data = await es_request("POST", "/logs-aegis-simulation-*/_search", json=payload)

    hosts = [b["key"] for b in data.get("aggregations", {}).get("hosts", {}).get("buckets", [])]
    users = [b["key"] for b in data.get("aggregations", {}).get("users", {}).get("buckets", [])]

    return {"active_hosts": hosts, "active_users": users}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
