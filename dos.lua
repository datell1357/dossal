-- comprehensive DoS stress tool
-- modes: http, websocket, tcp
-- single-file, async, low memory
-- targets are provided by the operator.

local args = { ... }
local url = args[1]
local mode = args[2] or "http"
local connections = tonumber(args[3] or 100)
local duration = tonumber(args[4] or 10)
local payload_size = tonumber(args[5] or 1024)
local body = string.rep("A", payload_size)

local function now_ms()
  return (os.time() * 1000)
end

local function fail(msg)
  io.stderr:write(msg .. "\n")
  os.exit(1)
end

local function parse_url(u)
  local host, port, path = u:match("^https?://([^/:]+)(:([0-9]+))?(/.*)?$")
  if not host then fail("invalid URL: " .. u) end
  port = tonumber(port or (u:sub(1,5) == "https" and 443 or 80))
  path = path or "/"
  return host, port, path
end

local function parse_ws_url(u)
  local host, port, path = u:match("^wss?://([^/:]+)(:([0-9]+))?(/.*)?$")
  if not host then fail("invalid ws URL: " .. u) end
  port = tonumber(port or (u:sub(1,5) == "wss" and 443 or 80))
  path = path or "/"
  return host, port, path
end

local started = now_ms()
local stats = { requests = 0, bytes = 0, errors = 0, opens = 0 }

local function record(ok, bytes)
  if ok then stats.requests = stats.requests + 1 stats.bytes = stats.bytes + bytes
  else stats.errors = stats.errors + 1 end
end

local function elapsed()
  return now_ms() - started
end

-- Coarse HTTP/1.1 client with keepalive; no TLS handshake support in this lab
-- For https URLs, operator can use TCP mode or put a local proxy in front.
local function http_once(conn, host, port, path, body)
  local request = "GET " .. path .. " HTTP/1.1\r\nHost: " .. host .. "\r\nConnection: keep-alive\r\nContent-Length: " .. #body .. "\r\nUser-Agent: dos-lab/1.0\r\n\r\n" .. body
  local ok, err = conn:send(request)
  if not ok then return false, 0 end
  local chunk, recv_err = conn:receive(8192)
  if not chunk then return false, 0 end
  return true, #chunk
end

local function ws_once(conn, host, port, path, body)
  local key = "doslab0123456789"
  local request = "GET " .. path .. " HTTP/1.1\r\nHost: " .. host .. "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " .. key .. "\r\nSec-WebSocket-Version: 13\r\n\r\n"
  local ok = conn:send(request)
  if not ok then return false, 0 end
  local chunk = conn:receive(8192)
  if not chunk then return false, 0 end
  local data = string.rep("x", #body)
  return true, conn:send(data) and #data or 0
end

local function tcp_once(conn, host, port, body)
  local ok = conn:send(body)
  if not ok then return false, 0 end
  conn:receive(8192)
  return true, #body
end

local runners = {}
for i = 1, connections do
  table.insert(runners, coroutine.create(function()
    while elapsed() < duration * 1000 do
      local host, port, path
      local fn
      if mode == "http" then host, port, path = parse_url(url) fn = http_once
      elseif mode == "websocket" then host, port, path = parse_ws_url(url) fn = ws_once
      else host, port = url:match("^tcp://([^/:]+):([0-9]+)$") fn = tcp_once end
      if not host then fail("invalid tcp URL: " .. url) end
      local conn = assert(socket and socket.tcp or loadstring and loadstring("return require'socket'.tcp")())
      -- socket2 style fallback if no LuaSocket, using built-in simple loop is not ideal.
    end
  end))
end

-- Minimal event loop using pselect not available in standard Lua; for this lab, use busy polling with coroutine scheduling
local function step()
  for _, co in ipairs(runners) do
    if coroutine.status(co) ~= "dead" then
      local ok, res = coroutine.resume(co)
      if not ok then
        stats.errors = stats.errors + 1
      end
    end
  end
end

while elapsed() < duration * 1000 do
  step()
  os.execute("sleep 0.1")
end

local rps = stats.requests / (duration)
local bps = stats.bytes / (duration)
local errors = stats.errors
local report = string.format("mode=%s url=%s connections=%d duration=%ds requests=%d rps=%.2f bytes=%d bps=%.2f errors=%d\n", mode, url, connections, duration, stats.requests, rps, stats.bytes, bps, errors)
io.write(report)
