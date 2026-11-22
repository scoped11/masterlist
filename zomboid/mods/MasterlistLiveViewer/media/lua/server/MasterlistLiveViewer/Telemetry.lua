--[[
  MasterlistLiveViewer — server-authoritative player list for admin/co-op tooling.
  Runs only on the multiplayer server (not on pure clients).

  Writes JSON to: Zomboid/MasterlistLiveViewer/telemetry/players.json
  Consumed by: zomboid/viewer/pz_live_viewer.exe (localhost:8880)
]]

if isClient() or not isServer() then
    return
end

local MOD = "MasterlistLiveViewer"
local WRITE_INTERVAL_MS = 1000
local lastWrite = 0

local function escapeJson(str)
    if str == nil then return "" end
    str = tostring(str)
    str = string.gsub(str, "\\", "\\\\")
    str = string.gsub(str, "\"", "\\\"")
    str = string.gsub(str, "\n", "\\n")
    str = string.gsub(str, "\r", "\\r")
    return str
end

local function telemetryDir()
  return Core.getMyDocumentFolder() .. "/" .. MOD .. "/telemetry/"
end

local function telemetryPath()
    return telemetryDir() .. "players.json"
end

local function ensureDir()
    -- getFileWriter create dirs=false; create marker file in parent if needed via writer
    local path = telemetryPath()
    local slash = string.find(path, "[/\\][^/\\]+$")
    if not slash then return end
    local dir = string.sub(path, 1, slash - 1)
    if not fileExists(dir) then
        -- PZ API: createDirectory may be unavailable; writer with true may create path on some builds
    end
end

local function writeTelemetry()
    local players = getOnlinePlayers()
    if players == nil then return end

    local count = players:size()
    local ts = getTimeInMillis()
    local parts = {}
    table.insert(parts, "{\"schema\":1,\"source\":\"server\",\"updatedMs\":" .. tostring(ts) .. ",\"players\":[")
    for i = 0, count - 1 do
        local p = players:get(i)
        if p ~= nil then
            local username = ""
            if p.getUsername then username = p:getUsername() end
            local x = p:getX()
            local y = p:getY()
            local z = p:getZ()
            if i > 0 then table.insert(parts, ",") end
            table.insert(parts, string.format(
                "{\"username\":\"%s\",\"x\":%.2f,\"y\":%.2f,\"z\":%.2f}",
                escapeJson(username), x, y, z
            ))
        end
    end
    table.insert(parts, "]}")
    local body = table.concat(parts)

    ensureDir()
    local writer = getFileWriter(telemetryPath(), true, false)
    if writer == nil then
        print("[" .. MOD .. "] failed to open telemetry file")
        return
    end
    writer:write(body)
    writer:close()
end

Events.OnServerStarted.Add(function()
    print("[" .. MOD .. "] telemetry enabled → " .. telemetryPath())
end)

Events.OnTick.Add(function()
    local now = getTimeInMillis()
    if now - lastWrite < WRITE_INTERVAL_MS then return end
    lastWrite = now
    writeTelemetry()
end)