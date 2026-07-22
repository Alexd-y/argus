"""WSDL 1.1 importer for the Web Workbench (WB-P10e, pure).

Turns a WSDL 1.1 document into synthetic
:class:`~src.web_workbench.imports.har.ImportedExchange` entries — one HTTP
``POST`` per SOAP binding operation with a resolvable service address — so a
SOAP endpoint can seed the workbench (scope, scanner targets, Repeater) the same
way HAR/OpenAPI/Postman/GraphQL imports do. Only the **request** side is
synthesised (``response=None``); the body is a SOAP envelope whose ``Body``
wraps the operation element with placeholder parts, and SOAP 1.1 vs 1.2 framing
(namespaces, ``Content-Type``, ``SOAPAction``) is chosen from the binding.

Pure (no I/O/network/DB), offline-testable, **fail-closed**
(:class:`WsdlImportError`) and **bounded** (operation/part counts capped). XML is
parsed with :mod:`defusedxml` so XXE / billion-laughs / external-DTD payloads
are refused (this importer consumes untrusted documents). Placeholder part
values are neutral (never fabricated secrets).
"""

from __future__ import annotations

from typing import Any, Final
from urllib.parse import urlsplit
from xml.sax.saxutils import escape, quoteattr

from defusedxml import ElementTree as DefusedET  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]

from src.web_workbench.imports.har import ImportedExchange, _ensure_host, _origin_form
from src.web_workbench.proxy.transport import NormalizedRequest

_SOAP11_BINDING_NS: Final[str] = "http://schemas.xmlsoap.org/wsdl/soap/"
_SOAP12_BINDING_NS: Final[str] = "http://schemas.xmlsoap.org/wsdl/soap12/"
_SOAP11_ENV_NS: Final[str] = "http://schemas.xmlsoap.org/soap/envelope/"
_SOAP12_ENV_NS: Final[str] = "http://www.w3.org/2003/05/soap-envelope"
#: Maximum number of operations imported in one call (DoS guard).
_MAX_OPERATIONS: Final[int] = 2_000
#: Maximum message parts rendered per envelope (fan-out guard).
_MAX_PARTS: Final[int] = 100
_DEFAULT_HTTP_VERSION: Final[str] = "HTTP/1.1"

_NUMERIC_XSD: Final[frozenset[str]] = frozenset(
    {"int", "integer", "long", "short", "decimal", "double", "float", "byte", "unsignedInt"}
)


class WsdlImportError(ValueError):
    """Raised when a WSDL document cannot be imported (fail-closed)."""


def _localname(tag: str) -> str:
    """Strip the ``{namespace}`` prefix from an ElementTree tag."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _namespace(tag: str) -> str:
    if tag.startswith("{"):
        return tag[1 : tag.index("}")]
    return ""


def _children(elem: Any, localname: str) -> list[Any]:
    return [child for child in elem if _localname(child.tag) == localname]


def _ref_local(value: str | None) -> str:
    """Return the local part of a possibly-prefixed QName reference (``tns:Foo``)."""
    if not value:
        return ""
    return value.rsplit(":", 1)[-1]


def _xml_name(raw: str) -> str:
    """Sanitise a WSDL name into a safe XML element name (defensive)."""
    cleaned = "".join(c for c in raw if c.isalnum() or c in "_.-")
    return cleaned


def _sample_value(type_local: str) -> str:
    if type_local in _NUMERIC_XSD:
        return "1"
    if type_local == "boolean":
        return "true"
    if type_local in ("date", "dateTime", "time"):
        return "2020-01-01T00:00:00Z"
    return "example"


def _parse_document(raw: bytes | str) -> Any:
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    try:
        root = DefusedET.fromstring(data)
    except DefusedXmlException as exc:
        raise WsdlImportError(f"WSDL rejected by XML hardening: {exc.__class__.__name__}") from exc
    except DefusedET.ParseError as exc:
        raise WsdlImportError(f"WSDL is not well-formed XML: {exc.__class__.__name__}") from exc
    if _localname(root.tag) != "definitions":
        raise WsdlImportError("WSDL root must be <definitions>")
    return root


def _index_messages(root: Any) -> dict[str, list[tuple[str, str, bool]]]:
    """Return ``message-localname -> [(name, type_or_element_local, is_element)]``."""
    messages: dict[str, list[tuple[str, str, bool]]] = {}
    for message in _children(root, "message"):
        name = message.get("name")
        if not name:
            continue
        parts: list[tuple[str, str, bool]] = []
        for part in _children(message, "part"):
            part_name = part.get("name") or ""
            element = part.get("element")
            if element:
                parts.append((part_name, _ref_local(element), True))
            else:
                parts.append((part_name, _ref_local(part.get("type")), False))
        messages[name] = parts
    return messages


def _index_porttypes(root: Any) -> dict[str, dict[str, str]]:
    """Return ``portType-localname -> {operation-name: input-message-localname}``."""
    porttypes: dict[str, dict[str, str]] = {}
    for porttype in _children(root, "portType"):
        pt_name = porttype.get("name")
        if not pt_name:
            continue
        operations: dict[str, str] = {}
        for operation in _children(porttype, "operation"):
            op_name = operation.get("name")
            if not op_name:
                continue
            inputs = _children(operation, "input")
            message_ref = _ref_local(inputs[0].get("message")) if inputs else ""
            operations[op_name] = message_ref
        porttypes[pt_name] = operations
    return porttypes


def _index_endpoints(root: Any) -> dict[str, str]:
    """Return ``binding-localname -> service address location`` (first wins)."""
    endpoints: dict[str, str] = {}
    for service in _children(root, "service"):
        for port in _children(service, "port"):
            binding_ref = _ref_local(port.get("binding"))
            if not binding_ref:
                continue
            for address in _children(port, "address"):
                if _namespace(address.tag) in (_SOAP11_BINDING_NS, _SOAP12_BINDING_NS):
                    location = address.get("location")
                    if location and binding_ref not in endpoints:
                        endpoints[binding_ref] = location
    return endpoints


def _binding_version(binding: Any) -> int | None:
    """Return 11 or 12 for a SOAP binding, or ``None`` if not a SOAP binding."""
    for child in _children(binding, "binding"):
        ns = _namespace(child.tag)
        if ns == _SOAP12_BINDING_NS:
            return 12
        if ns == _SOAP11_BINDING_NS:
            return 11
    return None


def _soap_action(operation: Any) -> str:
    for child in _children(operation, "operation"):
        if _namespace(child.tag) in (_SOAP11_BINDING_NS, _SOAP12_BINDING_NS):
            return child.get("soapAction") or ""
    return ""


def _render_parts(parts: list[tuple[str, str, bool]]) -> str:
    rendered: list[str] = []
    for part_name, type_or_element, is_element in parts[:_MAX_PARTS]:
        tag = _xml_name(type_or_element if is_element else part_name)
        if not tag:
            continue
        if is_element:
            rendered.append(f"<{tag}/>")
        else:
            rendered.append(f"<{tag}>{escape(_sample_value(type_or_element))}</{tag}>")
    return "".join(rendered)


def _build_envelope(
    version: int, target_ns: str, op_name: str, parts: list[tuple[str, str, bool]]
) -> str:
    env_ns = _SOAP12_ENV_NS if version == 12 else _SOAP11_ENV_NS
    op_tag = _xml_name(op_name)
    body_parts = _render_parts(parts)
    inner = f"<tns:{op_tag} xmlns:tns={quoteattr(target_ns)}>{body_parts}</tns:{op_tag}>"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f"<soapenv:Envelope xmlns:soapenv={quoteattr(env_ns)}>"
        f"<soapenv:Body>{inner}</soapenv:Body>"
        "</soapenv:Envelope>"
    )


def _headers_for(version: int, soap_action: str, host: str | None) -> tuple[tuple[str, str], ...]:
    if version == 12:
        content_type = "application/soap+xml; charset=utf-8"
        if soap_action:
            content_type += f'; action="{soap_action}"'
        headers: tuple[tuple[str, str], ...] = (("Content-Type", content_type),)
    else:
        headers = (
            ("Content-Type", "text/xml; charset=utf-8"),
            ("SOAPAction", f'"{soap_action}"'),
        )
    # Header-injection guard: SOAPAction/action come from the untrusted WSDL.
    headers = tuple((n, v) for n, v in headers if "\r" not in v and "\n" not in v)
    return _ensure_host(headers, host)


def import_wsdl(raw: bytes | str) -> list[ImportedExchange]:
    """Import a WSDL 1.1 document into synthetic SOAP POST exchanges.

    Raises :class:`WsdlImportError` on any structural problem. Operations beyond
    :data:`_MAX_OPERATIONS` are ignored. Only bindings that are SOAP bindings and
    have a resolvable service address are imported.
    """
    root = _parse_document(raw)
    target_ns = root.get("targetNamespace") or ""
    messages = _index_messages(root)
    porttypes = _index_porttypes(root)
    endpoints = _index_endpoints(root)

    exchanges: list[ImportedExchange] = []
    for binding in _children(root, "binding"):
        binding_name = binding.get("name")
        if not binding_name:
            continue
        version = _binding_version(binding)
        if version is None:
            continue
        location = endpoints.get(binding_name)
        if not location:
            continue
        split = urlsplit(location if "://" in location else f"https://{location}")
        if not split.netloc:
            continue
        target, host = _origin_form(split.geturl())
        operations = porttypes.get(_ref_local(binding.get("type")), {})

        for operation in _children(binding, "operation"):
            if len(exchanges) >= _MAX_OPERATIONS:
                return exchanges
            op_name = operation.get("name")
            if not op_name or not _xml_name(op_name):
                continue
            message_local = operations.get(op_name, "")
            parts = messages.get(message_local, [])
            envelope = _build_envelope(version, target_ns, op_name, parts)
            soap_action = _soap_action(operation)
            headers = _headers_for(version, soap_action, host)
            try:
                request = NormalizedRequest(
                    method="POST",
                    target=target,
                    http_version=_DEFAULT_HTTP_VERSION,
                    headers=headers,
                )
            except ValueError as exc:  # pragma: no cover - target validated above
                raise WsdlImportError(
                    f"invalid synthetic request head: {exc.__class__.__name__}"
                ) from exc
            exchanges.append(
                ImportedExchange(
                    url=split.geturl(),
                    request=request,
                    request_body=envelope.encode("utf-8"),
                    response=None,
                    response_body=b"",
                    started_at=None,
                    truncated=False,
                )
            )

    if not exchanges:
        raise WsdlImportError("no importable SOAP operations with a service address found")
    return exchanges


__all__ = [
    "WsdlImportError",
    "import_wsdl",
]
