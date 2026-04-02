"""Tests for the skills system (ENH-V3: Strix-style knowledge injection)."""

import pytest

from src.skills import (
    build_skills_prompt_block,
    get_available_skills,
    get_skills_for_category,
    load_skill,
    load_skills,
)


class TestGetAvailableSkills:
    def test_returns_dict_with_categories(self):
        skills = get_available_skills()
        assert isinstance(skills, dict)
        assert "vulnerabilities" in skills
        assert "technologies" in skills
        assert "recon" in skills

    def test_vulnerability_skills_complete(self):
        skills = get_available_skills()
        vuln_skills = skills["vulnerabilities"]
        expected = [
            "sql_injection", "xss", "ssrf", "csrf", "idor",
            "xxe", "rce", "authentication_jwt", "business_logic",
            "race_conditions", "path_traversal", "open_redirect",
            "mass_assignment", "file_upload", "information_disclosure",
            "subdomain_takeover",
        ]
        for name in expected:
            assert name in vuln_skills, f"Missing vulnerability skill: {name}"

    def test_technology_skills_present(self):
        skills = get_available_skills()
        assert "graphql" in skills["technologies"]
        assert "jwt" in skills["technologies"]

    def test_recon_skills_present(self):
        skills = get_available_skills()
        assert "subdomain_enum" in skills["recon"]
        assert "port_scanning" in skills["recon"]
        assert "js_analysis" in skills["recon"]


class TestLoadSkill:
    def test_load_existing_skill(self):
        content = load_skill("sql_injection")
        assert content is not None
        assert "SQL Injection" in content
        assert "sqlmap" in content

    def test_load_nonexistent_skill(self):
        content = load_skill("nonexistent_skill_xyz")
        assert content is None

    def test_strips_frontmatter(self):
        content = load_skill("xss")
        assert content is not None
        assert "---" not in content.split("\n")[0]
        assert "name:" not in content.split("\n")[0]

    def test_skill_has_substantial_content(self):
        content = load_skill("ssrf")
        assert content is not None
        assert len(content) > 500


class TestLoadSkills:
    def test_load_multiple(self):
        result = load_skills(["sql_injection", "xss", "ssrf"])
        assert len(result) == 3
        assert "sql_injection" in result
        assert "xss" in result
        assert "ssrf" in result

    def test_skip_missing(self):
        result = load_skills(["sql_injection", "nonexistent_xyz"])
        assert len(result) == 1
        assert "sql_injection" in result

    def test_empty_list(self):
        result = load_skills([])
        assert result == {}


class TestGetSkillsForCategory:
    def test_sqli_category(self):
        skills = get_skills_for_category("sqli")
        assert "sql_injection" in skills

    def test_xss_category(self):
        skills = get_skills_for_category("xss")
        assert "xss" in skills

    def test_auth_category(self):
        skills = get_skills_for_category("auth")
        assert "authentication_jwt" in skills
        assert "business_logic" in skills

    def test_unknown_category(self):
        skills = get_skills_for_category("unknown_category")
        assert skills == []


class TestBuildSkillsPromptBlock:
    def test_builds_xml_block(self):
        block = build_skills_prompt_block(["sql_injection"])
        assert "<specialized_knowledge>" in block
        assert "</specialized_knowledge>" in block
        assert '<skill name="sql_injection">' in block

    def test_empty_for_no_skills(self):
        block = build_skills_prompt_block([])
        assert block == ""

    def test_empty_for_nonexistent(self):
        block = build_skills_prompt_block(["nonexistent_xyz"])
        assert block == ""

    def test_multiple_skills_in_block(self):
        block = build_skills_prompt_block(["sql_injection", "xss"])
        assert '<skill name="sql_injection">' in block
        assert '<skill name="xss">' in block
