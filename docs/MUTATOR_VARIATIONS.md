# Mutator Varyasyonları ve Kullanımı

Bu dokümantasyon, OWASP Attack Simulator'da mutator'ın oluşturduğu tüm varyasyonları ve bunların engine'de nasıl kullanıldığını açıklar.

## Genel Bakış

Mutator, güvenlik testleri için çeşitli saldırı payload'ları ve bunların varyasyonlarını oluşturur. Engine ise bu varyasyonları kullanarak kapsamlı güvenlik testleri gerçekleştirir.

## Oluşturulan Varyasyon Türleri

### 1. Temel Payload'lar
Her saldırı türü için temel payload'lar oluşturulur:
- **XSS**: 20+ farklı XSS payload'ı
- **SQL Injection**: 20+ farklı SQL injection payload'ı
- **SSRF**: 25+ farklı SSRF payload'ı
- **IDOR**: 20+ farklı IDOR payload'ı
- Ve diğer saldırı türleri...

### 2. Kodlanmış Varyasyonlar
Her temel payload için şu kodlanmış varyasyonlar oluşturulur:
- **URL Encoded**: `%3Cscript%3Ealert(1)%3C/script%3E`
- **Double URL Encoded**: `%253Cscript%253Ealert(1)%253C/script%253E`
- **Hex Encoded**: `\x3cscript\x3ealert(1)\x3c/script\x3e`
- **Unicode Encoded**: `\u003cscript\u003ealert(1)\u003c/script\u003e`

### 3. HTTP Method Varyasyonları
Her payload için farklı HTTP metodları test edilir:
- GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS

### 4. Kombinasyon Varyasyonları
Payload'lar birden fazla yere enjekte edilir:
- **Header + URL**: User-Agent ve URL parametrelerine aynı anda
- **URL + Body**: URL parametreleri ve request body'sine aynı anda

## Engine'de Kullanım

### Önceki Durum
Engine sadece temel payload'ları kullanıyordu:
```go
// Sadece temel payload değeri kullanılıyordu
work := AttackWork{
    Parameter:  parameter,
    Payload:    payload.Value,  // Sadece temel değer
    Type:       string(payload.Type),
    AttackType: attackType,
}
```

### Yeni Durum
Engine artık tüm varyasyonları kullanıyor:

#### 1. Temel Payload'lar
```go
// Standart parametre enjeksiyonu
req.Params[work.Parameter] = work.Payload
```

#### 2. Method Varyasyonları
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

#### 3. Kombinasyon Varyasyonları
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

## Kullanım Örnekleri

### 1. Komut Satırı ile Tüm Varyasyonları Test Etme
```bash
# Tüm payload setlerini ve varyasyonları kullan
./cli attack --target "http://example.com" --payload-set "all" --debug

# Belirli bir saldırı türünün tüm varyasyonlarını test et
./cli attack --target "http://example.com" --payload-set "xss.reflected" --debug
```

### 2. Senaryo Dosyası ile Kapsamlı Test
```yaml
# configs/scenarios/comprehensive_test.yaml
attack:
  enabled: true
  workers: 3
  payload_sets: ["all"]  # Tüm payload setlerini kullan
  delay: 100
  debug: true  # Debug modunu etkinleştir
```

```bash
# Senaryo dosyasını çalıştır
./cli scenario --file configs/scenarios/comprehensive_test.yaml --debug
```

## Test Edilen Varyasyon Sayıları

### Önceki Durum
- **XSS**: ~20 payload × 4 parametre = 80 test
- **SQL Injection**: ~20 payload × 4 parametre = 80 test
- **Toplam**: ~800 test

### Yeni Durum
- **XSS**: ~20 payload × 4 parametre = 80 temel test
- **XSS Method Varyasyonları**: ~20 payload × 7 method = 140 test
- **XSS Kombinasyonları**: ~20 payload × 2 kombinasyon = 40 test
- **XSS Kodlanmış Varyasyonlar**: ~20 payload × 4 encoding × 4 parametre = 320 test
- **XSS Toplam**: 580 test
- **Tüm Saldırı Türleri**: ~15,000+ test

## Debug Modu

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

## Performans Optimizasyonları

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

## Sonuç

Bu geliştirmelerle birlikte OWASP Attack Simulator artık:
- **15,000+ farklı test** gerçekleştirebilir
- **Kodlanmış payload'ları** test eder
- **HTTP method varyasyonlarını** test eder
- **Kombinasyon saldırılarını** test eder
- **Daha kapsamlı güvenlik testleri** sağlar

Bu sayede gerçek dünya saldırı senaryolarına daha yakın testler gerçekleştirilebilir ve daha fazla güvenlik açığı tespit edilebilir.
