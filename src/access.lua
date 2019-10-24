local public_keys_file = '/etc/kong/public_keys.json' -- hard coded to be loaded at init_work phase

local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

local read_file     = require("pl.file").read
local write         = require("pl.pretty").write
local jwt_decoder   = require("kong.plugins.jwt.jwt_parser")
local ngx_b64       = require("ngx.base64")
local cjson         = require("cjson.safe")
local mlcache       = require("resty.mlcache")

local ipairs        = ipairs
local pairs         = pairs
local tostring      = tostring
local string_format = string.format
local ngx_re_gmatch = ngx.re.gmatch
local get_method    = ngx.req.get_method
local set_header    = ngx.req.set_header
local ngx_header    = ngx.header
local start_time    = ngx.req.start_time
local ngx_now       = ngx.now
local ngx_time      = ngx.time
local ngx_say       = ngx.say
local ngx_exit      = ngx.exit
local ngx_log       = ngx.log
local ngx_DEBUG     = ngx.DEBUG
local ngx_ERR       = ngx.ERR


local cache, err = mlcache.new(plugin_name, "jwt_shared_dict", {
    lru_size = 20000,  -- size of the L1 (Lua VM) cache
    ttl      = 120,    -- 120s ttl for hits
    neg_ttl  = 1,      -- 1s ttl for misses
})
if err then
    return error("failed to create the cache: " .. (err or "unknown"))
end

local function load_public_keys(public_keys_file)
  local content, err = read_file(public_keys_file)
  if content == nil or err then
      ngx_log(ngx_ERR, "Could not read file contents. ", err)
      return nil, tostring(err)
  end

  local pkeys = cjson.decode(content)
  if not pkeys then
    ngx_log(ngx_ERR, "Could not get 'keys' object from " .. public_keys_file )
    return nil, "Could not get 'keys' object from " .. public_keys_file
  end

  local public_keys={}
  for k,v in pairs(pkeys) do
    public_keys[k]=ngx_b64.decode_base64url(v)
  end

  if not public_keys['default'] then
    ngx_log(ngx_ERR, "The 'default' value is not set in " .. public_keys_file)
    return public_keys, "The 'default' value is not set in " .. public_keys_file
  end
  return public_keys
end

local public_keys, err_pk = load_public_keys(public_keys_file)
if err_pk then
  ngx_log(ngx_ERR,   ">>>>>>>>>>> BE CAREFUL: PUBLIC KEYS NOT LOADED CORRECTLY. THIS MAY CAUSE SOME UNEXPECTED 401 RETURNS. <<<<<<<<<<<")
end

local _M = {}

local function has_value(tab, val)
    for index, value in ipairs(tab) do
        if value == val then
            return true
        end
    end

    return false
end

--- Retrieve a JWT in a request.
-- Checks for the JWT in URI parameters, then in cookies, and finally
-- in the `Authorization` header.
-- @param request ngx request object
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_token(request, conf)
  local ngx_var = ngx.var
  for _, v in ipairs(conf.cookie_names) do
      local jwt_cookie = ngx_var["cookie_" .. v]
      if jwt_cookie and jwt_cookie ~= "" then
          return jwt_cookie
      end
  end

  local authorization_header = request.get_headers()["authorization"]
  if authorization_header then
    local iterator, iter_err = ngx_re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
    if not iterator then
        return nil, iter_err
    end

    local m, err = iterator()
    if err then
        return nil, err
    end

    if m and #m > 0 then
        return m[1]
    end
  end

  local uri_parameters = request.get_uri_args()

  for _, v in ipairs(conf.uri_param_names) do
      if uri_parameters[v] then
          return uri_parameters[v]
      end
  end

end

-- local function response_time()
--     local req_start_time = start_time()
--     local system_clock = ngx_now()
--     return string_format("%0.3f", (system_clock - req_start_time))
-- end

local function return_redirect(issuer_uri, uri, err)
  ngx_log(ngx_ERR, tostring(err))
  ngx_header["WWW-Authenticate"]='error="' .. tostring(err) .. '"'
  return ngx.redirect(issuer_uri.."?uri="..uri)
end

local function retrieve_jwt(conf, token)
    ngx_log(ngx_DEBUG, ">>> Token was not in the cache")
    local ttype = type(token)
    if ttype ~= "string" then
        if ttype == "nil" then
            return nil, "Token is nil"
        elseif ttype == "table" then
            return nil, "Multiple tokens provided"
        else
            return nil, "Unrecognizable token"
        end
    end

    local jwt, err = jwt_decoder:new(token)
    if err then
        return nil, "Bad token; " .. tostring(err)
    end

    if jwt.header.alg ~= conf.algorithm then
        return nil, "Invalid algorithm: got [" .. jwt.header.alg .. "], expected [" .. conf.algorithm .. "]"
    end

    if public_keys == {} or public_keys == nil then
      ngx_log(ngx_DEBUG, ">>>>>>>>>>> PUBLIC KEYS WAS NOT LOADED. Trying again ... <<<<<<<<<<<")
      local err
      public_keys, err = load_public_keys(public_keys_file)
      if err then
        ngx_log(ngx_ERR,   ">>>>>>>>>>> PUBLIC KEYS NOT LOADED CORRECTLY. Check file: " .. public_keys_file .. "  <<<<<<<<<<<")
        return nil, "Could not load public keys file"
      end
    end

    local kid = jwt.header.kid or 'default'
    ngx_log(ngx_DEBUG, "Using Key_ID: " .. kid)
    if not public_keys[kid] then
      return nil, "Could not load public key"
    end

    if not jwt:verify_signature(public_keys[kid]) then
      return nil, "Invalid signature"
    end

    if conf["valid_iss"] and table.getn(conf["valid_iss"]) ~= 0 then
      if not has_value(conf.valid_iss, jwt.claims.iss) then
        return nil, "Invalid iss"
      end
    end

    if conf["valid_domains"] and table.getn(conf["valid_domains"]) ~= 0 then
      if not has_value(conf.valid_domains, jwt.claims.domain) then
        return nil, "Invalid domain"
      end
    end

    if conf["sub_whitelist"] and table.getn(conf["sub_whitelist"]) ~= 0 then
      if not has_value(conf.sub_whitelist, jwt.claims.sub) then
        return nil, "Sub is not in the whitelist"
      end
    end

    if conf["sub_blacklist"] and table.getn(conf["sub_blacklist"]) ~= 0 then
      if has_value(conf.sub_blacklist, jwt.claims.sub) then
        return nil, "Sub is in the blacklist"
      end
    end

    local system_clock = ngx_now()
    if conf.validate_token_exp_date and jwt.claims.exp and system_clock > jwt.claims.exp then
      return nil, "token expired"
    end

    if conf.override_ttl then
      ngx_log(ngx_DEBUG, "Token valid. TTL: " .. tostring(conf.ttl))
      return jwt.claims
    else
      local token_ttl = jwt.claims.exp - ( ngx_time() - 1 )
      ngx_log(ngx_DEBUG, "Token valid. TTL: " .. tostring(token_ttl))
      return jwt.claims, nil, token_ttl
    end
end

local function do_authentication(conf)
    local token, err = retrieve_token(ngx.req, conf)
    if err then
        return false, err
    end

    if not token then
        ngx_log(ngx_ERR, ">>> no jwt token")
        return_redirect(conf["issuer_uri"], conf["uri"], "no jwt token")
    end

    local claims, err
    if conf.use_cache then
      claims, err = cache:get(token, { ttl = conf.ttl }, retrieve_jwt, conf, token)
    else
      claims, err = retrieve_jwt(conf, token)
    end

    if err then
      ngx_log(ngx_ERR, ">>> ERROR retrieve_jwt: [", err, "]")
      return_redirect(conf["issuer_uri"], conf["uri"], err)
    end

    set_header("X-CLAIM-SUB", claims.sub)
    set_header("X-CLAIM-DOMAIN", claims.domain)
    set_header("X-CLAIM-USER", claims.user)

    if conf.t_claims then
      for _,claim in ipairs(conf.t_claims) do
        if claims[claim] then
          set_header(conf['t_claims_to_headers'][claim], claims[claim])
        else
          set_header(conf['t_claims_to_headers'][claim], nil)
        end
      end
    end

    return true
end

function _M.execute(conf)   
    conf["uri"] = ngx.var.uri

    if not conf.run_on_preflight and get_method() == "OPTIONS" then
        return
    end

    if conf.claims_to_headers then
      conf['t_claims_to_headers'] = {}
      conf['t_claims'] = {}
      for _,map in pairs(conf.claims_to_headers) do
        local claim, header = map:match("^([^:]+):*(.-)$")
        conf['t_claims_to_headers'][claim] = header
        table_insert(conf['t_claims'], claim)
      end
    end

    local ok, err = do_authentication(conf)
    local e = err
    if type(err) == "table" then
        e = write(err)
    end
    ngx_log(ngx_DEBUG, ">>> authentication: [", ok, ", ", e, "]")
    if not ok then
      return_error(500)
    end
end

function _M.retrieve_token(M,request,conf)
  local token, err = retrieve_token(request,conf)
  return token, err
end

return _M
