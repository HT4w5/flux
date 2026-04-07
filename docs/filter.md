# Filter Rule Examples

## Logical Rules

### ALL
```yaml
filter: ALL
```

### NONE
```yaml
filter: "NONE"
```

### AND
```yaml
filter:
  AND:
    - METHOD: "GET"
    - URL-PREFIX: "/api"
    - STATUS-CLASS: "successful"
```

### OR
```yaml
filter:
  OR:
    - STATUS: 200
    - STATUS: 201
    - STATUS: 204
```

### NOT
```yaml
filter:
  NOT:
    AGENT-KEYWORD: "bot"
```

## Time Rules

### BEFORE
```yaml
filter:
  BEFORE: "2024-12-31T23:59:59Z"
```

### AFTER
```yaml
filter:
  AFTER: "2024-01-01T00:00:00Z"
```

## IP Rules

### CLIENT-IP-CIDR
```yaml
filter:
  CLIENT-IP-CIDR:
    - "192.168.1.0/24"
    - "10.0.0.1"
```

### SERVER-IP-CIDR
```yaml
filter:
  SERVER-IP-CIDR:
    - "10.0.0.0/8"
```

## Methods

### METHOD
```yaml
filter:
  METHOD: "GET"
```

## URL Rules

### URL
```yaml
filter:
  URL: "/foo/bar.tar.gz"
```

### URL-PREFIX
```yaml
filter:
  URL-PREFIX: "/foo"
```

### URL-KEYWORD
```yaml
filter:
  URL-KEYWORD: "bar"
```

### URL-SUFFIX
```yaml
filter:
  URL-SUFFIX: ".tar.gz"
```

### URL-SET
```yaml
filter:
  URL-SET:
    - "/api/v1/users"
    - "/api/v1/posts"
    - "/static/css/style.css"
```

### URL-PREFIX-SET
```yaml
filter:
  URL-PREFIX-SET:
    - "/api"
    - "/static"
    - "/images"
```

## Status rules

### STATUS
```yaml
filter:
  STATUS: 200
```

### STATUS-CLASS
```yaml
filter:
  STATUS-CLASS: 2  # 1, 2, 3, 4, 5
```
```yaml
filter:
  STATUS-CLASS: successful  # informational, successful, redirection, client_error, server_error
```
```yaml
filter:
  STATUS-CLASS: 2xx # 1xx, 2xx, 3xx, 4xx, 5xx
```

## Sent Rules

### SENT-MORE-THAN
```yaml
filter:
  SENT-MORE-THAN: 1000
```
```yaml
filter:
  SENT-MORE-THAN: 1kB
```

### SENT-LESS-THAN
```yaml
filter:
  SENT-MORE-THAN: 1000
```
```yaml
filter:
  SENT-MORE-THAN: 1kB
```

## Duration Rules

### TOOK-LONGER-THAN
```yaml
filter:
  TOOK-LONGER-THAN: "100ms"
```

### TOOK-SHORTER-THAN
```yaml
filter:
  TOOK-SHORTER-THAN: "100ms"
```

## Host Rules

### HOST
```yaml
filter:
  HOST: "example.com"
```

### HOST-SUFFIX
```yaml
filter:
  HOST-SUFFIX: ".com"
```

### HOST-KEYWORD
```yaml
filter:
  HOST-KEYWORD: "google"
```

## Agent Rules

### AGENT
```yaml
filter:
  AGENT: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.7339.208 Safari/537.36"
```

### AGENT-KEYWORD
```yaml
filter:
  AGENT-KEYWORD: "Chrome"
```

### AGENT-SET
```yaml
filter:
  AGENT-SET:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    - "curl/7.88.1"
    - "PostmanRuntime/7.36.3"
```

