return {
    fields = {
        -- Describe your plugin's configuration's schema here.
        uri_param_names = { type = "array", default = { "access_token", "jwt" }, required = true },
        cookie_names = { type = "array", default = { "access_token", "jwt" }, required = true },
        valid_iss = { type = "array", default = { "kong-google-oauth-jwt-signer" }, required = true },
        valid_domains = {type = "array", default={ "google.com" }, required=true},
        use_cache = { type = "boolean", default = true },
        override_ttl = { type = "boolean", default = false },
        ttl = { type = "number", default = 120, required = true },
        algorithm = { type = "string", default = "RS512", required = true },
        run_on_preflight = { type = "boolean", default = false },
        validate_token_exp_date = { type = "boolean", default = true },
        issuer_uri = {type = "string", default="/_oauth", required=true},
        sub_whitelist = {type = "array", default={}, required=false},
        sub_blacklist = {type = "array", default={}, required=false}
    }
}
