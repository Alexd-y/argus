"""Scope validator - checks domains, IPs, URLs against engagement scope rules."""

import ipaddress
import logging
import re

import tldextract
from netaddr import IPNetwork, IPAddress, AddrFormatError

from src.recon.schemas.scope import ScopeConfig, ScopeRule, ScopeValidationResult

logger = logging.getLogger(__name__)


class ScopeValidator:
    """Validates targets and findings against engagement scope configuration."""

    def __init__(self, scope_config: ScopeConfig) -> None:
        self._config = scope_config
        self._include_rules = [r for r in scope_config.rules if r.rule_type == "include"]
        self._exclude_rules = [r for r in scope_config.rules if r.rule_type == "exclude"]
        self._cidr_networks: list[tuple[ScopeRule, IPNetwork]] = []
        for rule in scope_config.rules:
            if rule.value_type == "cidr":
                try:
                    self._cidr_networks.append((rule, IPNetwork(rule.pattern)))
                except (AddrFormatError, ValueError):
                    logger.warning("Invalid CIDR in scope", extra={"pattern": rule.pattern})

    @property
    def config(self) -> ScopeConfig:
        return self._config

    def is_in_scope(self, value: str, value_type: str = "domain") -> ScopeValidationResult:
        """Check if a value is within the engagement scope."""
        if not self._include_rules:
            return ScopeValidationResult(
                is_in_scope=False, reason="No include rules defined in scope"
            )

        value = value.strip().lower()
        if not value:
            return ScopeValidationResult(is_in_scope=False, reason="Empty value")

        for rule in self._exclude_rules:
            if self._matches_rule(value, value_type, rule):
                return ScopeValidationResult(
                    is_in_scope=False,
                    matched_rule=rule,
                    reason=f"Excluded by rule: {rule.pattern}",
                )

        for rule in self._include_rules:
            if self._matches_rule(value, value_type, rule):
                return ScopeValidationResult(
                    is_in_scope=True,
                    matched_rule=rule,
                    reason=f"Matched include rule: {rule.pattern}",
                )

        return ScopeValidationResult(
            is_in_scope=False, reason=f"No matching include rule for: {value}"
        )

    def _matches_rule(self, value: str, value_type: str, rule: ScopeRule) -> bool:
        """Check if value matches a specific scope rule."""
        if rule.value_type == "domain":
            return self._match_domain(value, rule.pattern)
        elif rule.value_type == "ip":
            return self._match_ip(value, rule.pattern)
        elif rule.value_type == "cidr":
            return self._match_cidr(value, rule.pattern)
        elif rule.value_type == "regex":
            return self._match_regex(value, rule.pattern)
        return False

    def _match_domain(self, value: str, pattern: str) -> bool:
        """Match domain with optional wildcard subdomain support."""
        pattern = pattern.lower().strip()
        value = value.lower().strip().rstrip(".")

        if value == pattern:
            return True

        if self._config.wildcard_subdomains:
            if value.endswith(f".{pattern}"):
                return True

        if pattern.startswith("*."):
            base = pattern[2:]
            if value == base or value.endswith(f".{base}"):
                return True

        return False

    def _match_ip(self, value: str, pattern: str) -> bool:
        """Match exact IP address."""
        try:
            return str(ipaddress.ip_address(value)) == str(ipaddress.ip_address(pattern))
        except ValueError:
            return False

    def _match_cidr(self, value: str, pattern: str) -> bool:
        """Match IP against CIDR range."""
        try:
            ip = IPAddress(value)
            network = IPNetwork(pattern)
            return ip in network
        except (AddrFormatError, ValueError):
            return False

    def _match_regex(self, value: str, pattern: str) -> bool:
        """Match value against regex pattern."""
        try:
            return bool(re.search(pattern, value))
        except re.error:
            logger.warning("Invalid regex in scope rule", extra={"pattern": pattern})
            return False

    def validate_target(self, domain: str, target_type: str = "domain") -> ScopeValidationResult:
        """Validate a target before adding to engagement."""
        return self.is_in_scope(domain, target_type)

    def validate_url(self, url: str) -> ScopeValidationResult:
        """Validate URL by extracting hostname and checking domain scope."""
        extracted = tldextract.extract(url)
        if extracted.registered_domain:
            fqdn = extracted.fqdn
            return self.is_in_scope(fqdn, "domain")
        parts = url.split("://", 1)
        host_part = parts[-1].split("/", 1)[0].split(":")[0]
        try:
            ipaddress.ip_address(host_part)
            return self.is_in_scope(host_part, "ip")
        except ValueError:
            return self.is_in_scope(host_part, "domain")

    def filter_in_scope(self, values: list[str], value_type: str = "domain") -> list[str]:
        """Filter list, returning only in-scope values."""
        return [v for v in values if self.is_in_scope(v, value_type).is_in_scope]

    def filter_findings(self, findings: list[dict], key: str = "value") -> list[dict]:
        """Filter finding dicts, keeping only in-scope entries by a key field."""
        result = []
        for finding in findings:
            val = finding.get(key, "")
            if not val:
                result.append(finding)
                continue
            check = self.is_in_scope(val, "domain")
            if check.is_in_scope:
                result.append(finding)
        return result
