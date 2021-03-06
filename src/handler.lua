local BasePlugin = require "kong.plugins.base_plugin"
local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")
local access = require("kong.plugins." .. plugin_name .. ".access")


local plugin = BasePlugin:extend()

function plugin:new()
    plugin.super.new(self, plugin_name)
end

function plugin:access(conf)
    plugin.super.access(self)
    access.execute(conf)
end

plugin.PRIORITY = 1000
plugin.VERSION = "1.2-0"

return plugin
