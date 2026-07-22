"""Unit tests for the WSDL 1.1 importer (WB-P10e)."""

from __future__ import annotations

import pytest

from src.web_workbench.imports.har import ImportedExchange
from src.web_workbench.imports.wsdl import WsdlImportError, import_wsdl

_SOAP11_WSDL = """<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="http://example.com/stock"
             xmlns:xsd="http://www.w3.org/2001/XMLSchema"
             targetNamespace="http://example.com/stock">
  <message name="GetPriceRequest">
    <part name="symbol" type="xsd:string"/>
    <part name="quantity" type="xsd:int"/>
  </message>
  <message name="GetPriceResponse">
    <part name="price" type="xsd:double"/>
  </message>
  <portType name="StockPort">
    <operation name="GetPrice">
      <input message="tns:GetPriceRequest"/>
      <output message="tns:GetPriceResponse"/>
    </operation>
  </portType>
  <binding name="StockBinding" type="tns:StockPort">
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http" style="rpc"/>
    <operation name="GetPrice">
      <soap:operation soapAction="http://example.com/GetPrice"/>
      <input><soap:body use="literal"/></input>
    </operation>
  </binding>
  <service name="StockService">
    <port name="StockPort" binding="tns:StockBinding">
      <soap:address location="https://api.test/stock"/>
    </port>
  </service>
</definitions>
"""

_SOAP12_WSDL = """<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/"
             xmlns:tns="http://example.com/hello"
             xmlns:xsd="http://www.w3.org/2001/XMLSchema"
             targetNamespace="http://example.com/hello">
  <message name="SayHelloRequest">
    <part name="name" type="xsd:string"/>
  </message>
  <portType name="HelloPort">
    <operation name="SayHello">
      <input message="tns:SayHelloRequest"/>
    </operation>
  </portType>
  <binding name="HelloBinding" type="tns:HelloPort">
    <soap12:binding transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="SayHello">
      <soap12:operation soapAction="urn:sayHello"/>
      <input><soap12:body use="literal"/></input>
    </operation>
  </binding>
  <service name="HelloService">
    <port name="HelloPort" binding="tns:HelloBinding">
      <soap12:address location="https://soap.test/hello"/>
    </port>
  </service>
</definitions>
"""


def _body(ex: ImportedExchange) -> str:
    return ex.request_body.decode("utf-8")


# --------------------------------------------------------------------------- #
# SOAP 1.1                                                                    #
# --------------------------------------------------------------------------- #


def test_soap11_operation_imported() -> None:
    exchanges = import_wsdl(_SOAP11_WSDL)
    assert len(exchanges) == 1
    ex = exchanges[0]
    assert isinstance(ex, ImportedExchange)
    assert ex.request.method == "POST"
    assert ex.request.target == "/stock"
    assert ex.request.header("Host") == "api.test"
    assert ex.request.header("Content-Type") == "text/xml; charset=utf-8"
    assert ex.request.header("SOAPAction") == '"http://example.com/GetPrice"'
    assert ex.response is None


def test_soap11_envelope_contains_operation_and_parts() -> None:
    body = _body(import_wsdl(_SOAP11_WSDL)[0])
    assert 'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"' in body
    assert '<tns:GetPrice xmlns:tns="http://example.com/stock">' in body
    assert "<symbol>example</symbol>" in body
    assert "<quantity>1</quantity>" in body


# --------------------------------------------------------------------------- #
# SOAP 1.2                                                                    #
# --------------------------------------------------------------------------- #


def test_soap12_operation_imported() -> None:
    ex = import_wsdl(_SOAP12_WSDL)[0]
    assert ex.request.target == "/hello"
    assert ex.request.header("Host") == "soap.test"
    ct = ex.request.header("Content-Type") or ""
    assert ct.startswith("application/soap+xml; charset=utf-8")
    assert 'action="urn:sayHello"' in ct
    assert ex.request.header("SOAPAction") is None


def test_soap12_envelope_namespace() -> None:
    body = _body(import_wsdl(_SOAP12_WSDL)[0])
    assert 'xmlns:soapenv="http://www.w3.org/2003/05/soap-envelope"' in body
    assert "<name>example</name>" in body


# --------------------------------------------------------------------------- #
# Element-style (document) parts                                              #
# --------------------------------------------------------------------------- #


def test_element_part_rendered_as_empty_tag() -> None:
    wsdl = """<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="http://ex.com/d"
             targetNamespace="http://ex.com/d">
  <message name="DoReq"><part name="parameters" element="tns:DoRequest"/></message>
  <portType name="P"><operation name="Do"><input message="tns:DoReq"/></operation></portType>
  <binding name="B" type="tns:P">
    <soap:binding transport="t" style="document"/>
    <operation name="Do"><soap:operation soapAction="do"/><input><soap:body/></input></operation>
  </binding>
  <service name="S"><port name="P" binding="tns:B">
    <soap:address location="https://d.test/svc"/>
  </port></service>
</definitions>
"""
    body = _body(import_wsdl(wsdl)[0])
    assert "<DoRequest/>" in body


# --------------------------------------------------------------------------- #
# Robustness / security                                                       #
# --------------------------------------------------------------------------- #


def test_non_soap_binding_skipped() -> None:
    wsdl = _SOAP11_WSDL.replace(
        '<soap:binding transport="http://schemas.xmlsoap.org/soap/http" style="rpc"/>',
        '<http:binding verb="POST" xmlns:http="http://schemas.xmlsoap.org/wsdl/http/"/>',
    )
    with pytest.raises(WsdlImportError):
        import_wsdl(wsdl)


def test_binding_without_address_skipped() -> None:
    wsdl = _SOAP11_WSDL.replace('<soap:address location="https://api.test/stock"/>', "")
    with pytest.raises(WsdlImportError):
        import_wsdl(wsdl)


def test_xxe_payload_refused() -> None:
    xxe = """<?xml version="1.0"?>
<!DOCTYPE definitions [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="&xxe;">
</definitions>
"""
    with pytest.raises(WsdlImportError):
        import_wsdl(xxe)


def test_soap_action_header_injection_dropped() -> None:
    wsdl = _SOAP11_WSDL.replace(
        'soapAction="http://example.com/GetPrice"',
        'soapAction="a&#13;&#10;Injected: 1"',
    )
    ex = import_wsdl(wsdl)[0]
    # The injected CRLF value must be dropped, not forwarded as a header.
    assert ex.request.header("SOAPAction") is None


# --------------------------------------------------------------------------- #
# Fail-closed                                                                 #
# --------------------------------------------------------------------------- #


def test_not_well_formed_rejected() -> None:
    with pytest.raises(WsdlImportError):
        import_wsdl("<definitions><unclosed>")


def test_wrong_root_rejected() -> None:
    with pytest.raises(WsdlImportError):
        import_wsdl('<?xml version="1.0"?><notWsdl/>')


def test_no_operations_rejected() -> None:
    wsdl = """<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="http://x"/>
"""
    with pytest.raises(WsdlImportError):
        import_wsdl(wsdl)
