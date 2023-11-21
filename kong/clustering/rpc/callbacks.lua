local pl_stringx = require "pl.stringx"


--local cjson = require("cjson.safe")
local constants = require("kong.clustering.rpc.constants")
local serializer = require("kong.clustering.rpc.serializer")


--local type = type
local pcall = pcall
--local assert = assert


local ERROR_CODE = constants.ERROR_CODE
local JSONRPC_VERSION = constants.JSONRPC_VERSION
local encode = serializer.encode
local rfind = pl_stringx.rfind


local RESPONSE_T = {
  jsonrpc = JSONRPC_VERSION,
  id = 0,
  error = "",
  result = "",
}


local ERROR_T = {
  code = 0,
  message = "",
}


local _M = {}


-- store all rpc methods
local _callbacks = {}

-- store all capabilities
local _capabilities = {}


local function response(id, res, is_failing)
  -- notification call
  if not id then
    return
  end

  RESPONSE_T.id     = id
  RESPONSE_T.error  = is_failing and res or nil
  RESPONSE_T.result = not is_failing and res or nil

  --ngx.log(ngx.ERR, "rpc return: ", cjson.encode(RESPONSE_T))

  return encode(RESPONSE_T)
end


function _M.register(method, func)
  local cap = _M.split(method)
  if not cap then
    return nil, "method is invalid"
  end

  _capabilities[cap] = true

  _callbacks[method] = func

  return true
end


function _M.unregister(method)
  _callbacks[method] = nil
end


function _M.execute(payload)
  local id     = payload.id
  local method = payload.method
  local params = payload.params

  local func = _callbacks[method]
  if not func then
    ERROR_T.code = ERROR_CODE.METHOD_NOT_FOUND
    ERROR_T.message = "Method not found"

    return response(id, ERROR_T, true)
  end

  local ok, res, err = pcall(func, params)
  if not ok then
    ERROR_T.code = ERROR_CODE.INTERNAL_ERROR
    ERROR_T.message = res

    return response(id, ERROR_T, true)
  end

  if err then
    return response(id, err, true)
  end

  return response(id, res)
end


function _M.split(method)
  local pos = rfind(method, ".")
  if not pos then
    return nil, nil, "not a valid method name"
  end

  return method:sub(1, pos - 1), method:sub(pos + 1)
end


function _M.capabilities()
  return _capabilities
end


return _M