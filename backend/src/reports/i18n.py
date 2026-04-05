"""Report internationalization — static string translations for Jinja2 templates."""

from __future__ import annotations

TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        "table_of_contents": "Table of Contents",
        "executive_summary": "Executive Summary",
        "scope_and_objectives": "Scope and Objectives",
        "methodology": "Methodology",
        "findings_overview": "Findings Overview",
        "detailed_findings": "Detailed Findings",
        "risk_assessment": "Risk Assessment",
        "recommendations": "Recommendations",
        "remediation_plan": "Remediation Plan",
        "appendix": "Appendix",
        "severity": "Severity",
        "finding": "Finding",
        "description": "Description",
        "impact": "Impact",
        "remediation": "Remediation",
        "evidence": "Evidence",
        "affected_asset": "Affected Asset",
        "cvss_score": "CVSS Score",
        "cvss_vector": "CVSS Vector",
        "cwe_id": "CWE ID",
        "confidence": "Confidence",
        "status": "Status",
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Informational",
        "test_limitations": "Test Limitations",
        "wstg_coverage": "WSTG Test Coverage",
        "coverage_percentage": "Coverage",
        "covered": "Covered",
        "not_covered": "Not Covered",
        "partial": "Partial",
        "category": "Category",
        "limitation": "Limitation",
        "disclaimer": "Disclaimer",
        "confidential": "Confidential",
        "prepared_for": "Prepared for",
        "prepared_by": "Prepared by",
        "date": "Date",
        "version": "Version",
    },
    "ru": {
        "table_of_contents": "Содержание",
        "executive_summary": "Краткое резюме",
        "scope_and_objectives": "Область и цели",
        "methodology": "Методология",
        "findings_overview": "Обзор уязвимостей",
        "detailed_findings": "Детальные уязвимости",
        "risk_assessment": "Оценка рисков",
        "recommendations": "Рекомендации",
        "remediation_plan": "План устранения",
        "appendix": "Приложение",
        "severity": "Критичность",
        "finding": "Уязвимость",
        "description": "Описание",
        "impact": "Влияние",
        "remediation": "Исправление",
        "evidence": "Доказательства",
        "affected_asset": "Затронутый ресурс",
        "cvss_score": "Оценка CVSS",
        "cvss_vector": "Вектор CVSS",
        "cwe_id": "Идентификатор CWE",
        "confidence": "Уверенность",
        "status": "Статус",
        "critical": "Критический",
        "high": "Высокий",
        "medium": "Средний",
        "low": "Низкий",
        "informational": "Информационный",
        "test_limitations": "Ограничения тестирования",
        "wstg_coverage": "Покрытие WSTG",
        "coverage_percentage": "Покрытие",
        "covered": "Покрыто",
        "not_covered": "Не покрыто",
        "partial": "Частично",
        "category": "Категория",
        "limitation": "Ограничение",
        "disclaimer": "Дисклеймер",
        "confidential": "Конфиденциально",
        "prepared_for": "Подготовлено для",
        "prepared_by": "Подготовлено",
        "date": "Дата",
        "version": "Версия",
    },
}

SUPPORTED_LANGUAGES = frozenset(TRANSLATIONS.keys())


def get_translations(language: str = "en") -> dict[str, str]:
    """Get translation dictionary for a language. Falls back to English."""
    lang = language.lower().strip()[:2]
    return TRANSLATIONS.get(lang, TRANSLATIONS["en"])


def t(key: str, language: str = "en") -> str:
    """Translate a single key. Falls back to English, then to the key itself."""
    translations = get_translations(language)
    return translations.get(key, TRANSLATIONS["en"].get(key, key))
