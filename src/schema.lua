local typedefs = require "kong.db.schema.typedefs"

return {
  name = "kong-oauth-jwt-plugin",
  fields = {
    {
      config = {
        type = "record",
        fields = {
            { uri_param_names = {
                type = "array",
                elements = { type = "string" },
                default = { "oauth_jwt" },
                required = true
            } },
            { cookie_names = {
                type = "array",
                elements = { type = "string" },
                default = { "oauth_jwt" },
                required = true
            } },
            { use_cache = {
                type = "boolean",
                default = true,
                required = true
            } },
            { override_ttl = {
                type = "boolean",
                default = false,
                required = true
            } },
            { ttl = {
                type = "number",
                default = 120,
                required = true
            } },
            { algorithm = {
                type = "string",
                default = "RS512",
                required = true
            } },
            { run_on_preflight = {
                type = "boolean",
                default = false,
                required = true
            } },
            { validate_token_exp_date = {
                type = "boolean",
                default = true,
                required = true
            } },
            { issuer_uri = {
                type = "string",
                default = "/_oauth",
                required = true
            } },
            { valid_iss = {
                type = "array",
                elements = { type = "string" },
                required = false
            } },
            { valid_domains = {
                type = "array",
                elements = { type = "string" },
                required = false
            } },
            { sub_whitelist = {
                type = "array",
                elements = { type = "string" },
                required = false
            } },
            { sub_blacklist = {
                type = "array",
                elements = { type = "string" },
                required = false
            } },
            { claims_to_headers = {
                type = "array",
                elements = { type = "string", match = "^[^:]+:.*$" },
                required = false
            } }
        },
      },
    },
  },
}