# OWASPAttackSimulator Scenario DSL

## Overview

The OWASPAttackSimulator Scenario DSL (Domain Specific Language) is a declarative YAML-based language for defining security testing scenarios. It supports infinite-step execution with loops, conditions, variables, and comprehensive attack patterns.

## Basic Structure

```yaml
version: "1"
name: "Scenario Name"
description: "Scenario description"
vars:
  base_url: "https://target.app"
  username: "{{ env:APP_USER }}"
  password: "{{ env:APP_PASS }}"

steps:
  - id: step1
    type: browser:navigate
    name: "Step Name"
    description: "Step description"
    inputs:
      url: "{{ vars.base_url }}/login"
    timeout: 30s
    retry_count: 3
```

## Step Types

### Browser Steps

#### `browser:navigate`
Navigate to a URL and wait for specific conditions.

```yaml
- id: open_login
  type: browser:navigate
  inputs:
    url: "{{ vars.base_url }}/login"
    wait: "networkidle"  # networkidle, domcontentloaded, load
  timeout: 30s
```

#### `browser:fill`
Fill form fields with values.

```yaml
- id: fill_form
  type: browser:fill
  inputs:
    selectors: |
      - sel: "#username"
        value: "{{ vars.username }}"
      - sel: "#password"
        value: "{{ vars.password }}"
  timeout: 10s
```

#### `browser:click`
Click on elements and wait for navigation.

```yaml
- id: submit_form
  type: browser:click
  inputs:
    selector: "button[type=submit]"
    wait: "networkidle"
  on_success: [capture_session]
  timeout: 30s
```

#### `browser:wait`
Wait for specific conditions.

```yaml
- id: wait_for_element
  type: browser:wait
  inputs:
    selector: "#dashboard"
    timeout: 10s
```

#### `browser:screenshot`
Take screenshots for documentation.

```yaml
- id: capture_screenshot
  type: browser:screenshot
  inputs:
    path: "screenshots/login_page.png"
    full_page: true
```

#### `browser:script`
Execute JavaScript in the browser context.

```yaml
- id: execute_script
  type: browser:script
  inputs:
    script: |
      document.querySelector('#token').value = '{{ vars.csrf_token }}';
      return document.title;
  timeout: 5s
```

### Session Steps

#### `session:update`
Update session data from browser or external sources.

```yaml
- id: capture_session
  type: session:update
  inputs:
    from: "browser"  # browser, file, manual
    save: "[cookies, headers, storage]"
  timeout: 5s
```

#### `session:save`
Save current session to file.

```yaml
- id: save_session
  type: session:save
  inputs:
    file: "sessions/current.json"
    include: "[cookies, headers, storage]"
```

#### `session:restore`
Restore session from file.

```yaml
- id: restore_session
  type: session:restore
  inputs:
    file: "sessions/previous.json"
```

### Network Steps

#### `net:request`
Make a single HTTP request.

```yaml
- id: api_request
  type: net:request
  inputs:
    method: "GET"
    url: "{{ vars.base_url }}/api/users"
    headers:
      Authorization: "Bearer {{ vars.token }}"
  guards:
    expect_status: "200"
  timeout: 10s
```

#### `net:mutate`
Generate request variations for testing.

```yaml
- id: mutate_request
  type: net:mutate
  inputs:
    base_request:
      method: "POST"
      url: "{{ vars.base_url }}/api/search"
      body: '{"query": "test"}'
    mutations:
      methods: "[GET, POST, PUT, DELETE]"
      headers:
        - "X-Forwarded-For: 127.0.0.1"
        - "User-Agent: OWASPAttackSimulator/1.0"
      bodies: "[json, xml, form]"
  timeout: 60s
```

#### `net:attack`
Perform comprehensive security testing.

```yaml
- id: attack_endpoint
  type: net:attack
  inputs:
    target:
      url: "{{ vars.base_url }}/api/profile"
      from_response: "$.endpoints[*].url"
    mutate:
      methods: "[GET, POST, PUT, DELETE]"
      bodies: "[json, xml, form, urlencoded]"
      payload_sets: "[xss.reflected, sqli.error, sqli.time, ssrf.basic]"
      max_variants_per_req: 12
    checks:
      enabled: "[xss, sqli, ssrf, xxe, headers, cors]"
    concurrency: 8
    rate_limit: "5/s"
  timeout: 300s
```

#### `net:check`
Perform security checks on responses.

```yaml
- id: security_check
  type: net:check
  inputs:
    checks:
      enabled: "[xss, sqli, ssrf, xxe, headers, cors]"
    thresholds:
      timing_delta: "100ms"
      response_size_min: 100
  timeout: 30s
```

### Crawl Steps

#### `crawl:run`
Run web crawling to discover endpoints.

```yaml
- id: crawl_site
  type: crawl:run
  inputs:
    seed_url: "{{ vars.base_url }}"
    max_depth: 3
    max_pages: 100
    respect_robots: true
    delay: "1s"
  timeout: 600s
```

#### `crawl:feed`
Feed discovered URLs to attack engine.

```yaml
- id: feed_urls
  type: crawl:feed
  inputs:
    source: "crawl_results"
    filter: "*.php"
    exclude: "[logout, admin]"
```

### Control Steps

#### `control:if`
Conditional execution based on expressions.

```yaml
- id: conditional_step
  type: control:if
  inputs:
    condition: "{{ last_response.status == 200 }}"
  children:
    - id: success_action
      type: net:request
      inputs:
        url: "{{ vars.base_url }}/success"
    - id: failure_action
      type: net:request
      inputs:
        url: "{{ vars.base_url }}/error"
```

#### `control:while`
Loop execution while condition is true.

```yaml
- id: infinite_loop
  type: control:while
  inputs:
    condition: "true"
    max_iterations: 1000
  children:
    - id: refresh_session
      type: browser:navigate
      inputs:
        url: "{{ vars.base_url }}/profile"
    - id: attack_cycle
      type: net:attack
      inputs:
        target:
          url: "{{ vars.base_url }}/api/data"
        mutate:
          payload_sets: "[xss.reflected, sqli.time]"
        sleep_after: "30s"
```

#### `control:foreach`
Iterate over data sets.

```yaml
- id: iterate_endpoints
  type: control:foreach
  inputs:
    data_set: "{{ last_response.body.json.endpoints }}"
    variable: "endpoint"
  children:
    - id: test_endpoint
      type: net:attack
      inputs:
        target:
          url: "{{ vars.endpoint.url }}"
        mutate:
          methods: "[GET, POST]"
          payload_sets: "[xss.reflected]"
```

### Plugin Steps

#### `plugin:call`
Execute custom plugin functions.

```yaml
- id: custom_attack
  type: plugin:call
  inputs:
    name: "jwt_kid_attack"
    action: "brute_force"
    parameters:
      token: "{{ vars.jwt_token }}"
      wordlist: "common_kids.txt"
      max_attempts: 1000
  timeout: 300s
```

## Variables and Expressions

### Variable Sources

- `{{ vars.* }}` - Scenario variables
- `{{ env:* }}` - Environment variables
- `{{ session.cookies.* }}` - Session cookies
- `{{ session.headers.* }}` - Session headers
- `{{ last_response.body.json.path }}` - JSONPath expressions
- `{{ last_response.headers.* }}` - Response headers

### Expression Examples

```yaml
vars:
  base_url: "https://target.app"
  user_id: "{{ env:USER_ID }}"
  csrf_token: "{{ session.headers.X-CSRF-Token }}"
  api_endpoints: "{{ last_response.body.json.endpoints[*].url }}"
  user_data: "{{ last_response.body.json.users[0] }}"
```

## Guards and Effects

### Guards
Conditions that must be met for step execution.

```yaml
guards:
  expect_status: "200"
  expect_header: "Content-Type: application/json"
  expect_body_contains: "success"
  expect_json_path: "$.status == 'ok'"
  max_response_time: "5s"
```

### Effects
Actions to perform after step completion.

```yaml
effects:
  save_cookies: true
  save_headers: true
  sleep_after: "10s"
  retry_on_failure: 3
  continue_on_error: false
```

## Timeouts and Retries

```yaml
timeout: 30s
retry_count: 3
retry_delay: "5s"
retry_condition: "status != 200"
```

## Error Handling

```yaml
on_success:
  - "next_step"
  - "save_results"

on_failure:
  - "log_error"
  - "retry_step"
  - "fallback_action"
```

## Complete Example

```yaml
version: "1"
name: "Login and Attack Scenario"
description: "Complete login flow with infinite attack loop"

vars:
  base_url: "https://target.app"
  username: "{{ env:APP_USER }}"
  password: "{{ env:APP_PASS }}"

steps:
  - id: open_login
    type: browser:navigate
    name: "Open Login Page"
    inputs:
      url: "{{ vars.base_url }}/login"
      wait: "networkidle"
    timeout: 30s

  - id: fill_credentials
    type: browser:fill
    name: "Fill Login Form"
    inputs:
      selectors: |
        - sel: "#username"
          value: "{{ vars.username }}"
        - sel: "#password"
          value: "{{ vars.password }}"
    timeout: 10s

  - id: submit_login
    type: browser:click
    name: "Submit Login"
    inputs:
      selector: "button[type=submit]"
      wait: "networkidle"
    on_success: [capture_session]
    timeout: 30s

  - id: capture_session
    type: session:update
    name: "Capture Session"
    inputs:
      from: "browser"
      save: "[cookies, headers, storage]"
    timeout: 5s

  - id: attack_loop
    type: control:while
    name: "Infinite Attack Loop"
    inputs:
      condition: "true"
    children:
      - id: refresh_session
        type: browser:navigate
        inputs:
          url: "{{ vars.base_url }}/profile"
          wait: "domcontentloaded"
        timeout: 30s

      - id: attack_api
        type: net:attack
        inputs:
          target:
            url: "{{ vars.base_url }}/api/profile"
          mutate:
            methods: "[GET, POST]"
            payload_sets: "[xss.reflected, sqli.time]"
            max_variants_per_req: 4
          checks:
            enabled: "[xss, sqli]"
        effects:
          sleep_after: "30s"
        timeout: 60s

metadata:
  author: "OWASPAttackSimulator"
  created: "2024-01-01"
  tags: "[login, attack, infinite]"
  risk_level: "high"
```

## Best Practices

1. **Use descriptive names** for steps and scenarios
2. **Set appropriate timeouts** for each step type
3. **Handle errors gracefully** with on_failure actions
4. **Use variables** for reusable values
5. **Document complex scenarios** with descriptions
6. **Test scenarios** in isolated environments first
7. **Monitor resource usage** during infinite loops
8. **Use rate limiting** to avoid overwhelming targets
9. **Validate inputs** with guards
10. **Save artifacts** for later analysis
