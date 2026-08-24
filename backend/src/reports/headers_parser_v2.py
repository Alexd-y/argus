from typing import Literal

from pydantic import BaseModel

__all__ = ["EndpointHeaders", "FullHeadersContextV2", "RECOMMENDED_HEADERS", "analyze_headers_from_curl", "parse_curl_headers_response", "get_missing_headers", "get_all_missing_recommended"]


class EndpointHeaders(BaseModel):
    url: str
    status_code: int
    redirect_chain: list[dict] = []
    final_headers: dict[str, str] = {}
    missing_headers: list[str] = []
    confidence: Literal["high", "medium", "low"] = "medium"


class FullHeadersContextV2(BaseModel):
    endpoints: list[EndpointHeaders] = []
    all_endpoints: set[str] = set()
    missing_recommended: list[str] = []


RECOMMENDED_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Strict-Transport-Security",
]


def analyze_headers_from_curl(endpoints: list[str]) -> FullHeadersContextV2:
    context = FullHeadersContextV2()

    for endpoint in endpoints:
        response = parse_curl_headers_response(f"curl -sS -D- -o /dev/null {endpoint}")
        endpoint_headers = EndpointHeaders(
            url=endpoint,
            status_code=response.get("status_code", 200),
            redirect_chain=response.get("redirect_chain", []),
            final_headers=response.get("final_headers", {}),
            missing_headers=get_missing_headers(response.get("final_headers", {})),
        )
        context.endpoints.append(endpoint_headers)
        context.all_endpoints.add(endpoint)

    context.missing_recommended = get_all_missing_recommended(context.endpoints)

    return context


def parse_curl_headers_response(response: str) -> dict:
    result = {
        "status_code": 200,
        "redirect_chain": [],
        "final_headers": {},
    }

    lines = response.split("\n")
    current_headers = {}

    for line in lines:
        if line.startswith("< HTTP/"):
            status_part = line.split(" ", 1)
            if len(status_part) > 1:
                result["status_code"] = int(status_part[1].split()[0])

        if line.startswith("< Location:"):
            location = line.replace("< Location:", "").strip()
            if location:
                result["redirect_chain"].append({
                    "location": location,
                    "status": result["status_code"],
                })

        if line.startswith("< "):
            header_part = line[2:].split(":", 1)
            if len(header_part) == 2:
                current_headers[header_part[0].strip()] = header_part[1].strip()

    result["final_headers"] = current_headers

    return result


def get_missing_headers(headers: dict[str, str]) -> list[str]:
    missing = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for recommended in RECOMMENDED_HEADERS:
        if recommended.lower() not in headers_lower:
            missing.append(recommended)

    return missing


def get_all_missing_recommended(endpoints: list[EndpointHeaders]) -> list[str]:
    seen = set()
    all_missing = []

    for endpoint in endpoints:
        for missing in endpoint.missing_headers:
            if missing not in seen:
                seen.add(missing)
                all_missing.append(missing)

    return all_missing
