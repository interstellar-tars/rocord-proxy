-- examples/roblox/SendFromRoblox.lua
-- Replace KEY with your provisioned key.
local HttpService = game:GetService("HttpService")
local SEND_URL = "https://your-worker.workers.dev/api/send/KEY"

local payload = { content = "Hello from Roblox!" }

local ok, res = pcall(function()
  return HttpService:PostAsync(
    SEND_URL,
    HttpService:JSONEncode(payload),
    Enum.HttpContentType.ApplicationJson
  )
end)

if ok then
  print("Sent:", res)
else
  warn("Failed:", res)
end
