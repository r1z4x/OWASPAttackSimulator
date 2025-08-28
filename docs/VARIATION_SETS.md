# Variation Sets and Mutator Variations

This documentation explains how OWASPAttackSimulator creates and uses various attack payload variations for comprehensive security testing.

## Overview

The system supports configurable variation sets that control which types of variations are applied during testing. By default, all variations are applied, but you can specify exactly which variations you want to include.

## Available Variation Types

### 1. Method Variations
Tests different HTTP methods for each payload:
- GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS

### 2. Header Variations
Tests payload injection in various HTTP headers:
- User-Agent, Referer, X-Forwarded-For, Authorization, etc.

### 3. Body Variations
Tests payload injection in request bodies with different content types:
- JSON, XML, form-data, raw text

### 4. Combination Variations
Tests combinations of variations:
- Header + URL: User-Agent and URL parameters simultaneously
- URL + Body: URL parameters and request body simultaneously

### 5. Encoded Variations
Tests various encoding techniques:
- URL Encoded: `%3Cscript%3Ealert(1)%3C/script%3E`
- Double URL Encoded: `%253Cscript%253Ealert(1)%253C/script%253E`
- Hex Encoded: `\x3cscript\x3ealert(1)\x3c/script\x3e`
- Unicode Encoded: `\u003cscript\u003ealert(1)\u003c/script\u003e`

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

### Configuration in Scenarios

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

## Request Count Examples

For a single payload set with 10 payloads and 5 parameters:

- **No variations**: 50 requests (10 payloads × 5 parameters)
- **Method variations only**: ~400 requests (50 base + 7 methods × 3 payloads × 5 parameters)
- **Header variations only**: ~650 requests (50 base + 14 headers × 3 payloads × 5 parameters)
- **All variations**: ~2000+ requests (includes all variation types)

## Engine Implementation

### Method Variations
```go
case "method_variation":
    // Method'u attack type'dan çıkar
    if strings.Contains(work.AttackType, "_method_") {
        parts := strings.Split(work.AttackType, "_method_")
        if len(parts) > 1 {
            req.Method = strings.ToUpper(parts[1])
        }
    }
    req.Params["id"] = work.Payload
```

### Combination Variations
```go
case "combination_header_url":
    // Header'lara payload ekle
    req.Headers["User-Agent"] = work.Payload
    req.Headers["Referer"] = work.Payload
    // URL parametrelerine de ekle
    req.Params["id"] = work.Payload

case "combination_url_body":
    // URL parametrelerine ekle
    req.Params["id"] = work.Payload
    // Body'ye ekle
    if strings.Contains(req.Headers["Content-Type"], "application/json") {
        req.Body = []byte(fmt.Sprintf(`{"data": "%s"}`, work.Payload))
    } else {
        req.Body = []byte(fmt.Sprintf("data=%s", work.Payload))
    }
```

## Debug Mode

Debug modunu etkinleştirerek tüm varyasyonları görebilirsiniz:

```bash
./cli attack --target "http://example.com" --payload-set "xss.reflected" --debug
```

Debug çıktısı şu bilgileri gösterir:
- Test edilen HTTP method
- Kullanılan payload
- Attack type ve varyasyon türü
- Request headers, parameters ve body
- Response detayları

## Performance Optimizations

### 1. Worker Thread'leri
Çok sayıda varyasyon test edildiği için worker thread sayısını artırın:
```bash
./cli attack --target "http://example.com" --workers 10 --payload-set "all"
```

### 2. Delay Ayarları
Rate limiting'i önlemek için delay kullanın:
```bash
./cli attack --target "http://example.com" --delay 100 --payload-set "all"
```

### 3. Belirli Payload Setleri
Tüm varyasyonları test etmek yerine belirli saldırı türlerine odaklanın:
```bash
./cli attack --target "http://example.com" --payload-set "xss.reflected,sqli.error"
```

## Benefits

1. **Reduced Request Count**: By selecting only specific variations, you can significantly reduce the number of requests sent
2. **Focused Testing**: Target specific attack vectors or bypass techniques
3. **Performance**: Faster scans when you know which variations are most relevant
4. **Rate Limiting**: Avoid overwhelming targets with too many requests

## Best Practices

1. **Start Simple**: Begin with no variations or just method variations
2. **Target Specific**: Use specific payload sets rather than "all" when possible
3. **Monitor Performance**: Watch for rate limiting and adjust variation sets accordingly
4. **Combine Strategically**: Use combinations that make sense for your target (e.g., body + encoded for API testing)

## Test Coverage

### Previous State
- **XSS**: ~20 payload × 4 parametre = 80 test
- **SQL Injection**: ~20 payload × 4 parametre = 80 test
- **Total**: ~800 test

### Current State
- **XSS**: ~20 payload × 4 parametre = 80 temel test
- **XSS Method Varyasyonları**: ~20 payload × 7 method = 140 test
- **XSS Kombinasyonları**: ~20 payload × 2 kombinasyon = 40 test
- **XSS Kodlanmış Varyasyonlar**: ~20 payload × 4 encoding × 4 parametre = 320 test
- **XSS Toplam**: 580 test
- **Tüm Saldırı Türleri**: ~15,000+ test

This comprehensive variation system allows OWASPAttackSimulator to perform extensive security testing with over 15,000 different test combinations, covering real-world attack scenarios more effectively.
