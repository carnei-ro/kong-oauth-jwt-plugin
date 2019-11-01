# Kong OAUTH JWT plugin

# Use

Use with https://github.com/carnei-ro/kong-google-oauth-jwt-signer (or its variations, `microsoft`, `zoho`, `github`).  
Plugin priority: 1000.  

summary: validate JWT. Creates headers X-CLAIM-SUB, X-CLAIM-DOMAIN and X-CLAIM-USER if claims exists.

## Default values

```yaml
---
plugins:
- name: kong-oauth-jwt-plugin
  config:
    uri_param_names:
    - oauth_jwt
    cookie_names:
    - oauth_jwt
    use_cache: true # Disable to verify the token in each request (careful performance)
    override_ttl: false # Default TTL is JWT claim "exp" - now
    ttl: 120
    algorithm: RS512 # Only supported value for now
    run_on_preflight: false # Enable to required a valid token on OPTIONS requests
    validate_token_exp_date: true # Disable to ignore validation of JWT claim "exp"
    issuer_uri: /_oauth # URI for the JWT issuer (kong-...-oauth-jwt-signer)
    valid_iss:
    - Kong
    valid_domains: [] # To validate domains
    sub_whitelist: [] # To allow specific "sub"
    sub_blacklist: [] # To deny specific "sub"
    claims_to_headers: [] # Format claim:header. Generates a header with the value of the claim.
```

## Real example

Allow emails from `foo.com` and allow a user with email `email-not-from-domain@gmail.com`.

```yaml
---
routes:
- hosts:
  - example.com
  methods: []
  name: example
  paths:
  - /
  preserve_host: false
  regex_priority: 1
  service: example
  strip_path: false
  plugins:
  - name: kong-oauth-jwt-plugin
    config:
      valid_domains:
      - foo.com
      sub_whitelist:
      - email-not-from-domain@gmail.com
```

## Requirements

Edit `kong.conf` to create a **lua_shared_dict** named `oauth_jwt_shared_dict` for the plugin:
```conf
nginx_http_lua_shared_dict=oauth_jwt_shared_dict 32m
```

Generate a key pair to use in the JWT. (The `private` goes to the `kong-...-oauth-jwt-signer` plugin.)  
```bash
openssl genrsa -out private.pem 2048 # generates the private
openssl rsa -in private.pem -outform PEM -pubout -out public.pem  # generates the public
```

Create the file `/etc/kong/oauth_jwt_public_keys.json`.
Format:  
- key = `kid` of the JWT 
- value = public key for the JWT in base64.  

To generates the base64 do:
```bash
cat public.pem | base64 | paste -s -d ""
```

Example:
`oauth_jwt_public_keys.json`
```json
{
  "12345678-1234-1234-1234-123456789ABC":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEzOUk3QndkZTdzV3hsRmdGdElhVQpiTDVBUjY2WWJ0MmJmazFqREFDYjd4b25mam54Sm5nZXdBSnZtTWxmYzBtV0owVll1TVJnalExUExsUUNqL0o3ClNZR1UydnNtS0I3VjIyVjU4Yjd6Z1BCVGtNNDFWYytOZks2M3dGVUdYbUQrdzdBSTFiOXRXZzhORXk3UkRyaW0KZldmUnhLNGlUSGZrSnpMYXJ6c3MzRHVzUzRNbTRJVXIzc2ZXNDFVZVhGRE1ubnc1RWRLbHdvd1lFT3RaaXJJbQpZU1QrZDE5QWFlaDVOMU94YldoVWxqci9NYnFXNXlWV2RPaEZqZENKeDJQZWgxdU9JUUlScjV0U0Rva2kzZ0FLClRWRnpyV3ZoZE51SGw1NTdKV2FTVnJxano5TGt0VEUyN3lKUlhtbGZmK1BSb0VhcmdGY0s1RnhzdDFlSnRkYTIKT1FJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
}
```