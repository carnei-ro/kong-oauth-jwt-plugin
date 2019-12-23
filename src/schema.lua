local typedefs = require "kong.db.schema.typedefs"
local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

return {
  name = plugin_name,
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
                default = { "Kong" },
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
            } },
            { set_header_with_token = {
                type = "boolean",
                default = false,
                required = true
            } },
            { token_header = {
                type = "string",
                default = "oauth_jwt",
                required = true
            } }
        },
      },
    },
  },
}
