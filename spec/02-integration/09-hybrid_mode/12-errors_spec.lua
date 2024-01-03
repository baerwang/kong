local helpers = require "spec.helpers"
local cjson = require "cjson.safe"
local uuid = require "kong.tools.uuid"
local constants = require "kong.constants"

local CONFIG_PARSE = constants.CLUSTERING_DATA_PLANE_ERROR.CONFIG_PARSE
local RELOAD_FAILED = constants.CLUSTERING_DATA_PLANE_ERROR.RELOAD_FAILED

local CLUSTER_PORT = helpers.get_available_port()
local CLUSTER_SSL_PORT = helpers.get_available_port()


local function json(data)
  return {
    headers = {
      ["accept"] = "application/json",
      ["content-type"] = "application/json",
    },
    body = assert(cjson.encode(data)),
  }
end


local mock_cp = ([[
  lua_shared_dict kong_test_cp_mock 10m;

  server {
      charset UTF-8;
      server_name kong_cluster_listener;
      listen %s;
      listen %s ssl;

      access_log ${{ADMIN_ACCESS_LOG}};
      error_log  ${{ADMIN_ERROR_LOG}} ${{LOG_LEVEL}};

> if cluster_mtls == "shared" then
      ssl_verify_client   optional_no_ca;
> else
      ssl_verify_client   on;
      ssl_client_certificate ${{CLUSTER_CA_CERT}};
      ssl_verify_depth     4;
> end
      ssl_certificate     ${{CLUSTER_CERT}};
      ssl_certificate_key ${{CLUSTER_CERT_KEY}};
      ssl_session_cache   shared:ClusterSSL:10m;

      location = /v1/outlet {
          content_by_lua_block {
              require("spec.fixtures.mock_cp").outlet()
          }
      }

      location = /payload {
          content_by_lua_block {
              require("spec.fixtures.mock_cp").set_payload()
          }
      }

      location = /log {
          content_by_lua_block {
              require("spec.fixtures.mock_cp").get_log()
          }
      }
  }
]]):format(CLUSTER_PORT, CLUSTER_SSL_PORT)


local function set_cp_payload(client, payload)
  local res = client:post("/payload", json(payload))
  assert.response(res).has.status(201)
end


local function get_connection_log(client)
  local res = client:get("/log")
  assert.response(res).has.status(200)
  local body = assert.response(res).has.jsonbody()
  assert.is_table(body.data)

  return body.data
end


for _, strategy in helpers.each_strategy() do
  describe("CP/DP sync error-reporting with #" .. strategy .. " backend", function()
    local client
    local fixtures = { http_mock = { control_plane = mock_cp } }

    before_each(function()
      helpers.clean_prefix()

      assert(helpers.start_kong({
        role                        = "data_plane",
        database                    = "off",
        konnect_mode                = "on",
        nginx_conf                  = "spec/fixtures/custom_nginx.template",
        cluster_cert                = "spec/fixtures/kong_clustering.crt",
        cluster_cert_key            = "spec/fixtures/kong_clustering.key",
        lua_ssl_trusted_certificate = "spec/fixtures/kong_clustering.crt",
        cluster_control_plane       = "127.0.0.1:" .. tostring(CLUSTER_SSL_PORT),
        -- use a small map size so that it's easy for us to max it out
        lmdb_map_size               = "1m",
      }, nil, nil, fixtures))

      client = helpers.http_client("127.0.0.1", CLUSTER_PORT)
    end)

    after_each(function()
      if client then client:close() end
      helpers.stop_kong()
    end)

    it("reports invalid configuration errors", function()
      set_cp_payload(client, {
        type = "reconfigure",
        config_table = {
          _format_version = "3.0",
          services = {
            {
              id = uuid.uuid(),
              name = "my-service",
              extra_field = 123,
              tags = { "tag-1", "tag-2" },
            },
          },
        }
      })

      assert.eventually(function()
        local entries = get_connection_log(client)

        if #entries == 0 then
          return nil, { err = "no data plane client log entries" }
        end

        for _, entry in ipairs(entries) do
          if    entry.event == "client-recv"
            and entry.type  == "binary"
            and type(entry.json) == "table"
            and entry.json.type == "error"
            and type(entry.json.error) == "table"
            and entry.json.error.name == CONFIG_PARSE
          then
            return true
          end
        end

        return nil, {
          err     = "did not find expected error in log",
          entries = entries,
        }
      end)
      .is_truthy("the data-plane should return an " ..
                 "'invalid declarative configuration' error to the " ..
                 "control-plane after sending it an invalid config")
    end)

    it("reports other types of errors", function()
      local services = {}

      -- The easiest way to test for this class of error is to generate a
      -- config payload that is too large to fit in the configured
      -- `lmdb_map_size`, so this test works by setting a low limit of 1MB on
      -- the data plane and then attempting to generate a config payload that
      -- is 2MB in hopes that it will be too large for the data plane.
      local size = 1024 * 1024 * 2

      while #cjson.encode(services) < size do
        for i = #services, #services + 1000 do
          i = i + 1

          services[i] = {
            id = uuid.uuid(),
            name = "service-" .. i,
            host = "127.0.0.1",
            retries = 5,
            protocol = "http",
            port = 80,
            path = "/",
            connect_timeout = 1000,
            write_timeout = 1000,
            tags = {
              "tag-1", "tag-2", "tag-3",
            },
            enabled = true,
          }
        end
      end

      set_cp_payload(client, {
        type = "reconfigure",
        config_table = {
          _format_version = "3.0",
          services = services,
        }
      })

      assert.eventually(function()
        local entries = get_connection_log(client)

        if #entries == 0 then
          return nil, { err = "no data plane client log entries" }
        end

        for _, entry in ipairs(entries) do
          if    entry.event == "client-recv"
            and entry.type  == "binary"
            and type(entry.json) == "table"
            and entry.json.type == "error"
            and type(entry.json.error) == "table"
            and entry.json.error.name == RELOAD_FAILED
            and entry.json.error.message == "map full"
          then
            return true
          end
        end

        return nil, {
          err = "did not find expected error in log",
          entries = entries,
        }
      end)
      .is_truthy("the data-plane should return a 'map full' error after " ..
                 "sending it a config payload of >2MB")
    end)


  end)
end
