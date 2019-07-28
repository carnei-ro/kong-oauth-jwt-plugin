package = "kong-oauth-jwt-plugin"
version = "0.0-2"

source = {
 url    = "git@bitbucket.org:leandro-carneiro/kong-oauth-jwt-plugin.git",
 branch = "master"
}

description = {
  summary = "validate JWT",
}

dependencies = {
  "lua ~> 5.1"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.kong-oauth-jwt-plugin.schema"] = "src/schema.lua",
    ["kong.plugins.kong-oauth-jwt-plugin.access"] = "src/access.lua",
    ["kong.plugins.kong-oauth-jwt-plugin.handler"] = "src/handler.lua",
  }
}