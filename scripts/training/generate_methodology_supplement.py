import json, yaml, os, random

random.seed(42)
methodology_dir = os.path.join('training_data', 'tool_knowledge', 'methodology')
output_path = os.path.join('training_data', 'methodology_supplement.jsonl')

def load_yaml(name):
    path = os.path.join(methodology_dir, name)
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

checklists = {
    'recon': load_yaml('recon_checklist.yaml'),
    'va': load_yaml('va_checklist.yaml'),
    'exploitation': load_yaml('exploitation_checklist.yaml'),
    'post': load_yaml('post_exploitation_checklist.yaml'),
}
workflows = {
    'internal': load_yaml('internal_pentest_workflow.yaml'),
    'web': load_yaml('web_pentest_workflow.yaml'),
    'ad': load_yaml('ad_attack_workflow.yaml'),
}

records = []

SYSTEM_PROMPTS = {
    'methodology_checklist': 'You are an ARGUS Security Analyst specializing in pentest methodology. Generate comprehensive, ordered checklists of security testing steps for a given phase and target type.',
    'validation_plan': 'You are an ARGUS Planner Agent. Create detailed validation plans that define how to confirm and verify security findings, including specific tools, commands, and expected outcomes.',
    'attack_chain_summary': 'You are an ARGUS Red Team Expert. Analyze multiple security findings and construct realistic attack chains that chain vulnerabilities together to achieve critical impact, mapping to MITRE ATT&CK TTPs.',
    'report_section': 'You are an ARGUS Reporter. Write professional, detailed pentest report sections summarizing findings, evidence, and recommendations in a format suitable for client delivery.',
}

def make_record(task_type, phase, user_msg, assistant_msg, source='methodology', argus_tools=None, cwe_ids=None, payload_families=None):
    meta = {'task': task_type, 'source': source, 'license': 'internal', 'argus_phase': phase}
    if argus_tools:
        meta['argus_tool_ids'] = argus_tools
    if cwe_ids:
        meta['cwe_ids'] = cwe_ids
    if payload_families:
        meta['argus_payload_families'] = payload_families
    return {
        'messages': [
            {'role': 'system', 'content': SYSTEM_PROMPTS[task_type]},
            {'role': 'user', 'content': user_msg},
            {'role': 'assistant', 'content': assistant_msg},
        ],
        'metadata': meta,
    }

# ===== METHODOLOGY CHECKLIST EXAMPLES =====

cl = checklists['recon']
records.append(make_record('methodology_checklist', 'recon',
    'Generate a complete reconnaissance methodology checklist for a web application pentest targeting example.com.',
    json.dumps({
        'phase': 'recon', 'target': 'example.com',
        'checklist': [
            {'order': s['order'], 'action': s['action'], 'tools': s.get('argus_tools', s.get('tools', [])),
             'verification': s['verification'], 'risk_level': s['risk_level']}
            for s in cl['steps']
        ],
        'phase_transition_conditions': list(cl['phase_transitions']['from_recon_to_va']['conditions']),
        'next_phase': 'vuln_analysis', 'estimated_duration': '20-40 minutes', 'risk_level': 'low'
    }, indent=2),
    argus_tools=['subfinder', 'httpx', 'nmap_tcp_top', 'ffuf_dir', 'gospider', 'katana']))

cl_va = checklists['va']
records.append(make_record('methodology_checklist', 'vuln_analysis',
    'Create a vulnerability analysis methodology checklist for a web application pentest after completing recon on api.example.com.',
    json.dumps({
        'phase': 'vuln_analysis', 'target': 'api.example.com',
        'checklist': [
            {'order': s['order'], 'action': s['action'], 'tools': s.get('argus_tools', s.get('tools', [])),
             'verification': s['verification'], 'risk_level': s['risk_level']}
            for s in cl_va['steps']
        ],
        'phase_transition_conditions': list(cl_va['phase_transitions']['from_va_to_exploitation']['conditions']),
        'next_phase': 'exploitation', 'estimated_duration': '30-60 minutes', 'risk_level': 'medium'
    }, indent=2),
    argus_tools=['nuclei', 'dalfox', 'sqlmap_safe', 'tplmap', 'jwt_tool', 'cors_probe', 'sslscan']))

cl_exp = checklists['exploitation']
records.append(make_record('methodology_checklist', 'exploitation',
    'Provide an exploitation phase checklist for an internal network pentest with confirmed SQL injection and SMB null session access.',
    json.dumps({
        'phase': 'exploitation', 'target': 'internal_network', 'context': 'sql_injection_and_smb_null_session',
        'checklist': [
            {'order': s['order'], 'action': s['action'], 'tools': s.get('argus_tools', s.get('tools', [])),
             'verification': s['verification'], 'risk_level': s['risk_level'], 'requires_approval': s.get('requires_approval', False)}
            for s in cl_exp['steps']
        ],
        'phase_transition_conditions': list(cl_exp['phase_transitions']['from_exploitation_to_post']['conditions']),
        'next_phase': 'post_exploitation', 'estimated_duration': '30-90 minutes', 'risk_level': 'high'
    }, indent=2),
    argus_tools=['sqlmap_confirm', 'hydra', 'crackmapexec', 'smbmap', 'kerbrute', 'commix', 'responder'],
    cwe_ids=[89, 287, 307, 78]))

cl_post = checklists['post']
records.append(make_record('methodology_checklist', 'post_exploitation',
    'Generate a post-exploitation checklist for an Active Directory environment after gaining initial access via cracked credentials.',
    json.dumps({
        'phase': 'post_exploitation', 'target': 'ad_environment', 'context': 'initial_access_via_cracked_creds',
        'checklist': [
            {'order': s['order'], 'action': s['action'], 'tools': s.get('argus_tools', s.get('tools', [])),
             'verification': s['verification'], 'risk_level': s['risk_level']}
            for s in cl_post['steps']
        ],
        'phase_transition_conditions': list(cl_post['phase_transitions']['from_post_to_reporting']['conditions']),
        'next_phase': 'reporting', 'estimated_duration': '20-60 minutes', 'risk_level': 'medium'
    }, indent=2),
    argus_tools=['hashcat', 'john', 'bloodhound_python', 'ldapsearch', 'crackmapexec', 'smbmap']))

# AD attack flow checklist
ad = workflows['ad']
records.append(make_record('methodology_checklist', 'exploitation',
    'Create an Active Directory attack methodology checklist covering enumeration, credential attacks, and lateral movement.',
    json.dumps({
        'phase': 'ad_attack', 'target': 'ad_environment', 'phases': ['recon', 'exploitation', 'post_exploitation'],
        'checklist': [
            {'phase': p['phase'], 'steps': [
                {'order': s['order'], 'action': s['action'], 'tools': s.get('tools', []),
                 'verification': s.get('verification', ''), 'cwe_ids': s.get('cwe_ids', [])}
                for s in p['steps']
            ]}
            for p in ad['attack_phases']
        ],
        'attack_chains': [
            {'name': c['name'], 'likelihood': c.get('likelihood', 'medium'),
             'steps': [{'step': st['step'], 'technique': st['technique'], 'description': st['description']} for st in c['steps']],
             'impact': c['impact']}
            for c in ad['common_attack_chains']
        ]
    }, indent=2),
    argus_tools=['crackmapexec', 'smbmap', 'enum4linux_ng', 'kerbrute', 'responder', 'ntlmrelayx', 'hashcat', 'impacket_examples']))

# Workflow checklists
for name, wf in [('internal', workflows['internal']), ('web', workflows['web'])]:
    target = wf['target_type']
    all_tools = []
    phase_names = []
    for phase_data in wf['workflow']:
        phase_names.append(phase_data['phase'])
        for step in phase_data['steps']:
            all_tools.extend(step.get('tools', []))
    all_tools = list(set(all_tools))
    records.append(make_record('methodology_checklist', phase_names[0],
        f'Generate a complete {name.replace("_", " ")} pentest methodology checklist for phases {" -> ".join(phase_names)}. Target type: {target}.',
        json.dumps({
            'workflow': name, 'target_type': target, 'phases': phase_names,
            'total_tools': len(all_tools),
            'estimated_duration': '2-4 hours' if name == 'internal' else '1-3 hours',
            'key_observations': [
                f'Scope covers {len(all_tools)} tools across {len(phase_names)} phases',
                f'Target type: {target}',
            ]
        }, indent=2),
        argus_tools=all_tools[:10]))

# ===== VALIDATION PLAN EXAMPLES =====

for step in cl['steps'][:4]:
    tool_str = ', '.join(step.get('argus_tools', step.get('tools', [])))
    records.append(make_record('validation_plan', 'recon',
        f"A pentester has completed a recon step: '{step['action']}'.\nTarget: web.example.com\nTools used: {tool_str}\nFinding: {step['expected_output']}\n\nCreate a validation plan to confirm this finding.",
        json.dumps({
            'plan_id': f'recon_validate_{step["order"]}', 'finding': step['action'],
            'validation_steps': [
                {'step': 1, 'action': f'Re-run {step["argus_tools"][0]} with verification flags', 'tool': step['argus_tools'][0] if step.get('argus_tools') else step.get('tools', ['unknown'])[0], 'expected_result': step['verification'], 'confidence': 'high'},
                {'step': 2, 'action': 'Cross-validate with secondary tool', 'tool': step['argus_tools'][1] if len(step.get('argus_tools', [])) > 1 else 'manual_review', 'expected_result': 'Consistent results across tools', 'confidence': 'medium'},
                {'step': 3, 'action': 'Verify no false positives', 'tool': 'manual_review', 'expected_result': 'Confirmed live assets with real responses', 'confidence': 'high'}
            ],
            'risk_level': step['risk_level'], 'approval_required': step.get('requires_approval', False)
        }, indent=2),
        argus_tools=step.get('argus_tools', step.get('tools', []))))

# XSS validation
records.append(make_record('validation_plan', 'vuln_analysis',
    'A pentester found reflected XSS on the search parameter of https://example.com/search?q=test. The parameter reflects user input in an HTML context. CSP header: default-src \'self\'. Create a validation plan.',
    json.dumps({
        'plan_id': 'va_validate_xss_search', 'finding': 'Reflected XSS in search parameter q',
        'validation_steps': [
            {'step': 1, 'action': 'Send OAST canary payload via dalfox', 'tool': 'dalfox', 'expected_result': 'OAST callback received confirming reflection', 'confidence': 'likely'},
            {'step': 2, 'action': 'Verify payload context (HTML, attribute, JavaScript)', 'tool': 'xsstrike', 'expected_result': 'Payload reflected in HTML body context', 'confidence': 'likely'},
            {'step': 3, 'action': 'Test CSP bypass', 'tool': 'dalfox', 'expected_result': 'Default-src self blocks inline scripts; test event handlers', 'confidence': 'medium'},
            {'step': 4, 'action': 'Capture browser screenshot of successful XSS', 'tool': 'playwright_xss_verify', 'expected_result': 'Visual evidence of JavaScript execution', 'confidence': 'confirmed'}
        ],
        'payload_families': ['xss', 'xss_dom', 'xss_contextual'],
        'risk_level': 'medium', 'approval_required': False,
        'cwe_ids': [79], 'owasp_wstg': ['WSTG-INPV-01', 'WSTG-INPV-02']
    }, indent=2),
    argus_tools=['dalfox', 'xsstrike', 'playwright_xss_verify'],
    cwe_ids=[79], payload_families=['xss']))

# SQLi validation
records.append(make_record('validation_plan', 'vuln_analysis',
    'A pentester suspects SQL injection in the username parameter of https://target.example.com/login. Error-based detection suggests MySQL backend. Create a validation plan.',
    json.dumps({
        'plan_id': 'va_validate_sqli_login', 'finding': 'SQL injection in login username parameter',
        'validation_steps': [
            {'step': 1, 'action': 'Run sqlmap in safe mode with low risk', 'tool': 'sqlmap_safe', 'expected_result': 'Confirm injection with boolean or error-based technique', 'confidence': 'suspected'},
            {'step': 2, 'action': 'Test UNION-based extraction if applicable', 'tool': 'sqlmap_confirm', 'expected_result': 'Database version and table enumeration', 'confidence': 'likely'},
            {'step': 3, 'action': 'Verify OAST callback for blind injection', 'tool': 'sqlmap_confirm', 'expected_result': 'Time-based or out-of-band confirmation', 'confidence': 'confirmed'},
            {'step': 4, 'action': 'Document evidence with screenshots', 'tool': 'puppeteer_screens', 'expected_result': 'Visual evidence of data extraction', 'confidence': 'confirmed'}
        ],
        'payload_families': ['sqli', 'sqli_safe'],
        'risk_level': 'high', 'approval_required': True,
        'cwe_ids': [89, 943], 'owasp_wstg': ['WSTG-INPV-05']
    }, indent=2),
    argus_tools=['sqlmap_safe', 'sqlmap_confirm', 'puppeteer_screens'],
    cwe_ids=[89], payload_families=['sqli']))

# Auth bypass validation
records.append(make_record('validation_plan', 'vuln_analysis',
    'During testing of https://api.example.com/admin, a pentester found that removing the Authorization header still returns admin data. This appears to be an authentication bypass. Create a validation plan.',
    json.dumps({
        'plan_id': 'va_validate_auth_bypass', 'finding': 'Authentication bypass on admin endpoint',
        'validation_steps': [
            {'step': 1, 'action': 'Reproduce with curl removing Authorization header', 'tool': 'manual_curl', 'expected_result': '200 OK with admin data without auth', 'confidence': 'likely'},
            {'step': 2, 'action': 'Test with invalid JWT token', 'tool': 'jwt_tool', 'expected_result': 'Server accepts tampered or empty JWT', 'confidence': 'confirmed'},
            {'step': 3, 'action': 'Test IDOR by changing user ID in token', 'tool': 'jwt_tool', 'expected_result': 'Access to other users data', 'confidence': 'confirmed'},
            {'step': 4, 'action': 'Check CORS and CSRF headers', 'tool': 'cors_probe', 'expected_result': 'CORS misconfiguration allowing cross-origin access', 'confidence': 'medium'}
        ],
        'payload_families': ['auth_bypass', 'idor', 'jwt_none_alg', 'cors_misconfig'],
        'risk_level': 'high', 'approval_required': False,
        'cwe_ids': [287, 639], 'owasp_wstg': ['WSTG-ATHN-01', 'WSTG-ATHZ-01']
    }, indent=2),
    argus_tools=['jwt_tool', 'cors_probe', 'nuclei'],
    cwe_ids=[287], payload_families=['auth_bypass', 'idor']))

# Post-exploitation validation
for step in cl_post['steps'][:3]:
    records.append(make_record('validation_plan', 'post_exploitation',
        f"During post-exploitation of an AD environment, a pentester completed: '{step['action']}'.\nTools: {', '.join(step.get('argus_tools', step.get('tools', [])))}\nExpected output: {step['expected_output']}\n\nCreate a validation plan to verify this finding.",
        json.dumps({
            'plan_id': f'post_validate_{step["order"]}', 'finding': step['action'],
            'validation_steps': [
                {'step': 1, 'action': f'Verify output with {step["argus_tools"][0]}', 'tool': step['argus_tools'][0], 'expected_result': step['verification'], 'confidence': 'high'},
                {'step': 2, 'action': 'Cross-reference with secondary tool', 'tool': step['argus_tools'][1] if len(step.get('argus_tools', [])) > 1 else 'manual_review', 'expected_result': 'Consistent findings across tools', 'confidence': 'medium'},
                {'step': 3, 'action': 'Document evidence', 'tool': 'puppeteer_screens', 'expected_result': 'Visual documentation', 'confidence': 'confirmed'}
            ],
            'risk_level': step['risk_level'], 'approval_required': step.get('requires_approval', False)
        }, indent=2),
        argus_tools=step.get('argus_tools', step.get('tools', []))))

# ===== ATTACK CHAIN SUMMARY EXAMPLES =====

wf_web = workflows['web']
for chain in wf_web['attack_chains']:
    tools_used = list(set([t for s in chain['steps'] for t in s.get('tools', [])]))
    ttps = [{'step': s.get('step', i+1), 'technique': s['technique'], 'description': s['description']} for i, s in enumerate(chain['steps'])]
    records.append(make_record('attack_chain_summary', 'exploitation',
        f"Analyze the following findings and construct an attack chain:\n\nAttack Chain: {chain['name']}\nFindings: {', '.join([s['description'] for s in chain['steps']])}\nTarget: web application\n\nCreate a detailed attack chain summary with TTP mappings.",
        json.dumps({
            'chain_name': chain['name'], 'target_type': 'web_app', 'phase': 'exploitation',
            'steps': ttps, 'tools_required': tools_used,
            'mitre_attack': [{'step': s.get('step', i+1), 'technique': s['technique']} for i, s in enumerate(chain['steps'])],
            'risk_level': 'high',
            'impact': 'full_system_compromise' if 'sql' in chain['name'].lower() or 'xss' in chain['name'].lower() else 'data_access',
            'remediation_priority': 'critical'
        }, indent=2),
        argus_tools=tools_used))

wf_int = workflows['internal']
for chain in wf_int['attack_chains']:
    tools_used = list(set([t for s in chain['steps'] for t in s.get('tools', [])]))
    ttps = [{'step': s.get('step', i+1), 'technique': s['technique'], 'description': s['description']} for i, s in enumerate(chain['steps'])]
    records.append(make_record('attack_chain_summary', 'exploitation',
        f"Construct an attack chain from the following findings in an internal network pentest:\n\nAttack Chain: {chain['name']}\nFindings: {', '.join([s['description'] for s in chain['steps']])}\nEnvironment: Active Directory domain\n\nMap each step to MITRE ATT&CK TTPs and identify required tools.",
        json.dumps({
            'chain_name': chain['name'], 'target_type': 'internal_network', 'phase': 'exploitation',
            'steps': ttps, 'tools_required': tools_used,
            'mitre_attack': [{'step': s.get('step', i+1), 'technique': s['technique']} for i, s in enumerate(chain['steps'])],
            'risk_level': 'critical', 'impact': 'domain_admin', 'remediation_priority': 'critical'
        }, indent=2),
        argus_tools=tools_used))

for chain in ad['common_attack_chains']:
    ttps = [{'step': s['step'], 'technique': s['technique'], 'description': s['description'], 'from_finding': s.get('from_finding', '')} for s in chain['steps']]
    records.append(make_record('attack_chain_summary', 'exploitation',
        f"Analyze the following Active Directory attack chain and provide a summary:\n\nChain: {chain['name']}\nLikelihood: {chain.get('likelihood', 'medium')}\nSteps: {', '.join([s['description'] for s in chain['steps']])}\nImpact: {chain['impact']}\n\nMap the chain to MITRE ATT&CK techniques and identify remediation priorities.",
        json.dumps({
            'chain_name': chain['name'], 'target_type': 'ad_environment',
            'likelihood': chain.get('likelihood', 'medium'),
            'steps': ttps, 'impact': chain['impact'], 'remediation_priority': 'critical',
            'mitre_attack': [{'step': s['step'], 'technique': s['technique']} for s in chain['steps']],
            'detection_opportunities': ['Monitor for unusual authentication patterns', 'Alert on pass-the-hash attempts', 'Detect LLMNR/NBT-NS poisoning']
        }, indent=2),
        argus_tools=['crackmapexec', 'smbmap', 'responder', 'hashcat', 'bloodhound_python']))

# Custom chain: SQLi to RCE
records.append(make_record('attack_chain_summary', 'exploitation',
    'A pentester found SQL injection in the login form and command injection in the admin panel. Construct a complete attack chain from these findings.\n\nFinding 1: SQL injection in https://target.example.com/login (username parameter, MySQL backend)\nFinding 2: Command injection in https://target.example.com/admin/exec (cmd parameter, Linux backend)',
    json.dumps({
        'chain_name': 'SQLi to RCE Chain', 'target_type': 'web_app', 'phase': 'exploitation',
        'steps': [
            {'step': 1, 'technique': 'T1190', 'description': 'Exploit SQL injection to extract admin credentials', 'from_finding': 'SQL injection in username parameter'},
            {'step': 2, 'technique': 'T1110', 'description': 'Crack extracted password hashes', 'from_finding': 'Hashed passwords from database'},
            {'step': 3, 'technique': 'T1078', 'description': 'Authenticate as admin using cracked credentials', 'from_finding': 'Valid admin credentials'},
            {'step': 4, 'technique': 'T1190', 'description': 'Exploit command injection in admin panel', 'from_finding': 'Command injection in exec endpoint'},
            {'step': 5, 'technique': 'T1059', 'description': 'Establish reverse shell from compromised server', 'from_finding': 'RCE confirmed via canary'}
        ],
        'tools_required': ['sqlmap_safe', 'sqlmap_confirm', 'hashcat', 'commix'],
        'payload_families': ['sqli', 'rce'],
        'risk_level': 'critical', 'impact': 'full_system_compromise', 'remediation_priority': 'critical',
        'remediation': ['Parameterize all SQL queries', 'Apply least privilege to application database user', 'Disable OS command execution in admin panel', 'Implement WAF with command injection rules']
    }, indent=2),
    argus_tools=['sqlmap_safe', 'sqlmap_confirm', 'hashcat', 'commix'],
    cwe_ids=[89, 78], payload_families=['sqli', 'rce']))

# ===== REPORT SECTION EXAMPLES =====

records.append(make_record('report_section', 'recon',
    'Write a reconnaissance findings section for a pentest report based on the following results:\n\nTarget: example.com\nSubdomains found: 47 via subfinder + amass\nLive hosts: 23 confirmed via httpx\nOpen ports: SSH(22), HTTP(80), HTTPS(443), MySQL(3306), RDP(3389) on main host\nTechnologies: nginx 1.18, PHP 8.1, jQuery 3.6, Laravel 10\nHidden directories: /admin, /api/v2, /backup, /.git\nDiscovered parameters: id, page, search, user_id on various endpoints',
    json.dumps({
        'section_type': 'findings_recon', 'title': 'Reconnaissance Findings',
        'executive_summary': 'Reconnaissance identified 47 subdomains with 23 live hosts running a Laravel application on nginx. Critical discoveries include an exposed .git directory, an admin panel, and a backup directory. Multiple database services are exposed.',
        'findings': [
            {'severity': 'critical', 'title': 'Exposed .git directory', 'description': 'The .git directory is publicly accessible, potentially exposing application source code and sensitive configuration.', 'cwe': 538, 'owasp': 'A01:2021', 'recommendation': 'Remove .git directory from public access and add to server blocklist.'},
            {'severity': 'high', 'title': 'Exposed admin panel', 'description': 'An admin panel at /admin is accessible without authentication.', 'cwe': 284, 'owasp': 'A01:2021', 'recommendation': 'Implement authentication and IP-based access controls on admin endpoints.'},
            {'severity': 'medium', 'title': 'Exposed MySQL service', 'description': 'MySQL is running on port 3306, potentially accessible from the network.', 'cwe': 668, 'owasp': 'A05:2021', 'recommendation': 'Bind MySQL to localhost only or restrict access via firewall rules.'},
            {'severity': 'info', 'title': 'Technology stack identified', 'description': 'nginx/1.18, PHP/8.1, Laravel/10, jQuery/3.6', 'recommendation': 'Keep all components updated to latest stable versions.'}
        ],
        'tools_used': ['subfinder', 'httpx', 'nmap_tcp_top', 'whatweb', 'ffuf_dir', 'paramspider'],
        'next_phase': 'vuln_analysis'
    }, indent=2),
    argus_tools=['subfinder', 'httpx', 'nmap_tcp_top', 'whatweb', 'ffuf_dir', 'paramspider']))

records.append(make_record('report_section', 'vuln_analysis',
    'Write a vulnerability analysis findings section based on these results:\n\n1. Reflected XSS in search parameter (confirmed via OAST callback)\n2. SQL injection in login form (error-based MySQL, confirmed via sqlmap)\n3. CORS misconfiguration allowing any origin (Access-Control-Allow-Origin: *)\n4. Missing security headers: CSP, X-Frame-Options, HSTS\n5. Exposed .git directory with config containing database credentials\n6. Weak TLS cipher: TLS 1.0 with RC4',
    json.dumps({
        'section_type': 'findings_vuln_analysis', 'title': 'Vulnerability Analysis Findings',
        'executive_summary': 'Vulnerability analysis identified 6 findings including 1 critical, 2 high, 2 medium, and 1 low severity. The most critical finding is an exposed .git directory containing database credentials. Two high-severity injection vulnerabilities (XSS and SQLi) were confirmed.',
        'findings': [
            {'severity': 'critical', 'title': 'Exposed .git directory with database credentials', 'cwe': 538, 'owasp': 'A01:2021', 'recommendation': 'Remove .git from public access, rotate all exposed credentials.'},
            {'severity': 'high', 'title': 'SQL injection in login form', 'cwe': 89, 'owasp': 'A03:2021', 'recommendation': 'Use parameterized queries and apply input validation.'},
            {'severity': 'high', 'title': 'Reflected XSS in search parameter', 'cwe': 79, 'owasp': 'A03:2021', 'recommendation': 'Implement output encoding and Content Security Policy.'},
            {'severity': 'medium', 'title': 'CORS misconfiguration (wildcard origin)', 'cwe': 942, 'owasp': 'A05:2021', 'recommendation': 'Restrict CORS to trusted origins only.'},
            {'severity': 'medium', 'title': 'Missing security headers (CSP, X-Frame-Options, HSTS)', 'cwe': 693, 'owasp': 'A05:2021', 'recommendation': 'Implement all recommended security headers.'},
            {'severity': 'low', 'title': 'Weak TLS configuration (TLS 1.0, RC4 cipher)', 'cwe': 326, 'owasp': 'A02:2021', 'recommendation': 'Disable TLS 1.0/1.1 and weak ciphers.'}
        ],
        'tools_used': ['dalfox', 'sqlmap_safe', 'cors_probe', 'nuclei', 'sslscan'],
        'next_phase': 'exploitation'
    }, indent=2),
    argus_tools=['dalfox', 'sqlmap_safe', 'cors_probe', 'nuclei', 'sslscan'],
    cwe_ids=[538, 89, 79, 942, 693, 326]))

records.append(make_record('report_section', 'exploitation',
    'Write an exploitation findings section for a pentest report:\n\n1. SQL injection confirmed: extracted users table (500 rows), admin credentials, database version MySQL 8.0.32\n2. Command injection confirmed: executed whoami via admin panel exec endpoint, confirmed www-data user\n3. Lateral movement: used cracked admin password to access SMB shares on 10.10.1.50\n4. Privilege escalation: found SUID binary /usr/bin/find allowing root access on web server',
    json.dumps({
        'section_type': 'findings_exploitation', 'title': 'Exploitation Findings',
        'executive_summary': 'Exploitation confirmed 4 critical vulnerabilities: SQL injection leading to data exfiltration (500+ user records), command injection providing web shell access, SMB lateral movement to internal network, and local privilege escalation to root',
        'findings': [
            {'severity': 'critical', 'title': 'SQL injection - data exfiltration', 'cwe': 89, 'description': 'Extracted users table with 500 rows, admin credentials, and database version.', 'recommendation': 'Parameterize queries, implement WAF, rotate all database credentials.'},
            {'severity': 'critical', 'title': 'Command injection - RCE', 'cwe': 78, 'description': 'Remote code execution as www-data user via admin exec endpoint.', 'recommendation': 'Remove OS command execution, implement input sanitization.'},
            {'severity': 'critical', 'title': 'SMB lateral movement', 'cwe': 287, 'description': 'Used cracked credentials to access internal SMB shares.', 'recommendation': 'Implement password policy, enable SMB signing, network segmentation.'},
            {'severity': 'critical', 'title': 'Local privilege escalation via SUID', 'cwe': 269, 'description': 'SUID bit on /usr/bin/find allows root access.', 'recommendation': 'Remove SUID bit from find binary, audit all SUID binaries.'}
        ],
        'attack_chains': [{'name': 'SQLi to root', 'steps': ['SQL injection to extract admin password', 'Admin login to access exec endpoint', 'Command injection for www-data shell', 'SUID find for root escalation']}],
        'tools_used': ['sqlmap_confirm', 'commix', 'crackmapexec', 'smbmap'],
        'next_phase': 'post_exploitation'
    }, indent=2),
    argus_tools=['sqlmap_confirm', 'commix', 'crackmapexec', 'smbmap'],
    cwe_ids=[89, 78, 287, 269]))

records.append(make_record('report_section', 'post_exploitation',
    'Write a post-exploitation and remediation section for:\n\n1. Cracked 34 of 50 NTLM hashes via hashcat (68% success rate)\n2. BloodHound shows path from user "svc_backup" to Domain Admin via 3-hop attack path\n3. Credential reuse: 12 of 34 cracked passwords work on other systems\n4. Evidence captured: screenshots of all confirmed findings\n5. All attack paths documented with MITRE ATT&CK mappings',
    json.dumps({
        'section_type': 'findings_post_exploitation', 'title': 'Post-Exploitation Findings and Remediation',
        'executive_summary': 'Post-exploitation analysis revealed severe credential weakness (68% crack rate), multiple attack paths to Domain Admin, and widespread credential reuse. The shortest path to Domain Admin is via svc_backup through 3 hops.',
        'findings': [
            {'severity': 'critical', 'title': 'Weak password policy - 68% hash crack rate', 'cwe': 521, 'description': '34/50 NTLM hashes cracked via hashcat.', 'recommendation': 'Enforce minimum 14-character passwords with complexity.'},
            {'severity': 'critical', 'title': 'Domain Admin attack path via svc_backup', 'cwe': 287, 'description': 'BloodHound shows 3-hop path: svc_backup -> local admin -> Domain Admin.', 'recommendation': 'Remove svc_backup from local admin groups, implement tiered administration.'},
            {'severity': 'high', 'title': 'Credential reuse across 12 systems', 'cwe': 521, 'description': '12 cracked passwords work on multiple systems.', 'recommendation': 'Implement unique passwords per service, deploy a password manager.'},
            {'severity': 'medium', 'title': 'Evidence collection complete', 'description': 'All findings documented with screenshots and tool output.', 'recommendation': 'Include in final deliverable.'}
        ],
        'remediation_priority': 'critical',
        'remediation_steps': [
            {'priority': 1, 'action': 'Reset all compromised credentials immediately', 'timeline': '24 hours'},
            {'priority': 2, 'action': 'Implement tiered administration model', 'timeline': '2 weeks'},
            {'priority': 3, 'action': 'Deploy LAPS for local admin password management', 'timeline': '1 week'},
            {'priority': 4, 'action': 'Enable SMB signing and enforce strong passwords', 'timeline': '1 week'},
            {'priority': 5, 'action': 'Implement network segmentation for Domain Controllers', 'timeline': '1 month'}
        ],
        'tools_used': ['hashcat', 'bloodhound_python', 'crackmapexec', 'puppeteer_screens']
    }, indent=2),
    argus_tools=['hashcat', 'bloodhound_python', 'crackmapexec', 'puppeteer_screens'],
    cwe_ids=[521, 287]))

# Shuffle and write
random.shuffle(records)
with open(output_path, 'w', encoding='utf-8') as f:
    for rec in records:
        f.write(json.dumps(rec, ensure_ascii=False) + '\n')

from collections import Counter
task_counts = Counter(r['metadata']['task'] for r in records)
phase_counts = Counter(r['metadata']['argus_phase'] for r in records)
print(f'Generated {len(records)} methodology supplement training examples')
print(f'\nBy task type:')
for task, count in task_counts.most_common():
    print(f'  {task}: {count}')
print(f'\nBy phase:')
for phase, count in phase_counts.most_common():
    print(f'  {phase}: {count}')
print(f'\nWritten to: {output_path}')