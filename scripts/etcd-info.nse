local http = require "http"
local json = require "json"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Detects the etcd distributed key-value store and retrieves its version,
cluster version, and health status via etcd's unauthenticated HTTP
endpoints (/version and /health).

etcd's client port (2379 by default) commonly exposes these endpoints
without authentication even when the key space itself is protected.
This script also performs a conservative, read-only check of whether the
v2 key API (/v2/keys/) is reachable without credentials, which is a
widely documented misconfiguration (unauthenticated etcd deployments have
repeatedly been found leaking secrets). It reports only whether the
endpoint is accessible, and does not retrieve, dump, or display any key
names or values.
]]

---
-- @usage
-- nmap -p 2379 <ip> --script etcd-info
--
-- @output
-- PORT     STATE SERVICE VERSION
-- 2379/tcp open  etcd    etcd 3.5.9
-- | etcd-info:
-- |   Server Version: 3.5.9
-- |   Cluster Version: 3.5.0
-- |   Health: true
-- |_  v2 Key API: accessible without authentication (unauthenticated access)
--
-- @xmloutput
-- <elem key="server_version">3.5.9</elem>
-- <elem key="cluster_version">3.5.0</elem>
-- <elem key="health">true</elem>
-- <elem key="v2_keys_exposed">true</elem>

author = "Claude Code"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "version", "safe"}

portrule = shortport.version_port_or_service({2379, 4001}, {"etcd", "etcd-client"}, "tcp")

-- Fetches a URL and returns the decoded JSON body, or nil on any failure.
local function get_json(host, port, path)
  local response = http.get(host, port, path, {timeout = 5000})
  if not response or not response.status or response.status ~= 200 or not response.body then
    return nil
  end
  local ok, parsed = json.parse(response.body)
  if not ok then
    return nil
  end
  return parsed
end

action = function(host, port)
  local version_info = get_json(host, port, "/version")
  if not version_info or not version_info["etcdserver"] then
    return nil
  end

  local output = stdnse.output_table()
  output.server_version = version_info["etcdserver"]
  output.cluster_version = version_info["etcdcluster"]

  port.version.name = "etcd"
  port.version.product = "etcd"
  port.version.version = version_info["etcdserver"]
  nmap.set_port_version(host, port)

  local health_info = get_json(host, port, "/health")
  if health_info and health_info["health"] ~= nil then
    output.health = tostring(health_info["health"])
  end

  -- Conservative, read-only check: is the v2 key API reachable without
  -- any credentials? We deliberately do not request the key listing
  -- recursively, and we discard the response body entirely -- only the
  -- HTTP status is used to decide reachability.
  local keys_response = http.get(host, port, "/v2/keys/", {timeout = 5000})
  if keys_response and keys_response.status == 200 then
    output.v2_keys_exposed = true
    table.insert(output, "v2 Key API: accessible without authentication (unauthenticated access)")
  elseif keys_response and (keys_response.status == 401 or keys_response.status == 403) then
    output.v2_keys_exposed = false
  end

  return output
end
