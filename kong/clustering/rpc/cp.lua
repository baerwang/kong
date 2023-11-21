local constants = require("kong.clustering.rpc.constants")
local callbacks = require("kong.clustering.rpc.callbacks")
local connector = require("kong.clustering.rpc.connector")
local handler = require("kong.clustering.rpc.handler")
local threads = require("kong.clustering.rpc.threads")
local peer = require("kong.clustering.rpc.peer")


local META_HELLO_METHOD = constants.META_HELLO_METHOD


local _M = {}
local _MT = { __index = _M, }


function _M.new()
  local self = {
    connector = connector.new(),

    -- nodes[id] = worker count
    nodes = {},

    -- hold all dps connecting to this cp
    peers = {}, --setmetatable({}, { __mode = "k", }),
  }

  return setmetatable(self, _MT)
end


function _M:init_worker()
  callbacks.register(META_HELLO_METHOD, function(params)
    --ngx.log(ngx.ERR, "in meta.hello")
    return callbacks.capabilities()
  end)
end


function _M:connect()
  return self.connector:init()
end


-- choose a node by node_id
function _M:get_peer(node_id)
  local _, peers
  if not node_id then
    _, peers = next(self.peers)

  else
    peers = self.peers[node_id]
  end

  if not peers then
    return nil
  end

  local _, peer = next(peers)

  return peer
end


-- get all dp nodes connecting to this cp
function _M:get_nodes()
  return self.nodes
end


-- get one dp by node_id
function _M:notify(node_id, method, params, opts)
  local peer = self:get_peer(node_id)
  if not peer then
    return nil, "peer is not available"
  end

  return peer:notify(method, params, opts)
end


-- get one dp by node_id
function _M:call(node_id, method, params, opts)
  local peer = self:get_peer(node_id)
  if not peer then
    return nil,{ code = constants.INTERNAL_ERROR,
                 message = "peer is not available", }
  end

  return peer:call(method, params, opts)
end


function _M:run()
  local wb, err = self:connect()
  if not wb then
    ngx.log(ngx.ERR, "[cp] wb:connect err: ", err)
    return
  end

  -- log info of dp connection
  ngx.log(ngx.ERR, "[cp] wb:connect ok")

  -- basic node info
  local node_id = ngx.var.arg_node_id

  -- set rpc peer
  local hdl = handler.new()
  local pr = peer.new(hdl)
  local thds = threads.new(wb, hdl)

  -- store node info
  --self.peers[wb] = pr
  --self.peers[wb] = { peer = pr, node_id = node_id, }
  if not self.peers[node_id] then
    self.peers[node_id] = setmetatable({}, { __mode = "k", })
  end
  self.peers[node_id][wb] = pr
  self.nodes[node_id] = (self.nodes[node_id] or 0) + 1

  -- cp/dp has almost the same workflow
  thds:run()

  -- dp disconnect

  self.peers[node_id][wb] = nil
  self.nodes[node_id] = self.nodes[node_id] - 1

  wb:send_close()

  ngx.log(ngx.ERR, "close wb")

  return ngx.exit(ngx.OK)
end


return _M