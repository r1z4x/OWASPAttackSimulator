# Variation Sets

The OWASPAttackSimulator now supports configurable variation sets that allow you to control which types of variations are applied during testing.

## Overview

Variation sets control how payloads are modified and tested. By default, all variations are applied, but you can now specify exactly which variations you want to include.

## Available Variation Types

- **method**: Tests different HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
- **header**: Tests payload injection in various HTTP headers
- **body**: Tests payload injection in request bodies with different content types
- **combination**: Tests combinations of variations (header + URL, URL + body)
- **encoded**: Tests URL-encoded, double-encoded, hex-encoded, and unicode-encoded payloads

## Usage

### CLI Usage

```bash
# Test with only method variations
./cli attack --target https://example.com --variation-set method

# Test with method and header variations
./cli attack --target https://example.com --variation-set method,header

# Test with all variations (default behavior)
./cli attack --target https://example.com

# Test with specific payload set and variations
./cli attack --target https://example.com --payload-set xss.reflected --variation-set body,encoded
```

### Programmatic Usage

```go
config := &attack.AttackConfig{
    Target:       "https://example.com",
    Method:       "GET",
    PayloadSets:  []string{"xss.reflected"},
    VariationSet: []string{"method", "header"}, // Only method and header variations
    Headers:      make(map[string]string),
}
```

## Examples

### Example 1: Basic Parameter Testing Only
```bash
./cli attack --target https://example.com --payload-set sqli.error
```
This will test SQL injection payloads without any variations - just basic parameter injection.

### Example 2: Method Variations Only
```bash
./cli attack --target https://example.com --payload-set xss.reflected --variation-set method
```
This will test XSS payloads with different HTTP methods but no other variations.

### Example 3: Body and Encoded Variations
```bash
./cli attack --target https://example.com --payload-set ssrf.basic --variation-set body,encoded
```
This will test SSRF payloads in request bodies and with various encodings, but not in headers or with method variations.

### Example 4: Comprehensive Testing (Default)
```bash
./cli attack --target https://example.com --payload-set all
```
This will test all payloads with all variations (equivalent to not specifying --variation-set).

## Benefits

1. **Reduced Request Count**: By selecting only specific variations, you can significantly reduce the number of requests sent
2. **Focused Testing**: Target specific attack vectors or bypass techniques
3. **Performance**: Faster scans when you know which variations are most relevant
4. **Rate Limiting**: Avoid overwhelming targets with too many requests

## Request Count Examples

For a single payload set with 10 payloads and 5 parameters:

- **No variations**: 50 requests (10 payloads × 5 parameters)
- **Method variations only**: ~400 requests (50 base + 7 methods × 3 payloads × 5 parameters)
- **Header variations only**: ~650 requests (50 base + 14 headers × 3 payloads × 5 parameters)
- **All variations**: ~2000+ requests (includes all variation types)

## Best Practices

1. **Start Simple**: Begin with no variations or just method variations
2. **Target Specific**: Use specific payload sets rather than "all" when possible
3. **Monitor Performance**: Watch for rate limiting and adjust variation sets accordingly
4. **Combine Strategically**: Use combinations that make sense for your target (e.g., body + encoded for API testing)

## Configuration in Scenarios

You can also configure variation sets in scenario files:

```yaml
steps:
  - name: "XSS Testing"
    target: "https://example.com"
    payload_sets: ["xss.reflected"]
    variation_set: ["method", "header"]
    workers: 5
    delay: 100
```
