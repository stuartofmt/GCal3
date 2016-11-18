-- Google Calendar Plugin
-- Constants
local GCAL_VERSION = " V3.0"
local GCAL_SID = "urn:srs-com:serviceId:GCalIII"
local SECURITY_SID = "urn:micasaverde-com:serviceId:SecuritySensor1"

-- Variables that are 'global' for this plugin

-- PLUGIN_NAME server several purposes - do not change
-- it identifies and names key files
-- also creates a subdirectory in /etc/cmh-ludl of the same name
local PLUGIN_NAME = "GCal3"
local PRE = PLUGIN_NAME .. " device: "-- debug message prefix
-- make the file names and paths available
local BASEPATH = "/etc/cmh-ludl/" -- default vera directory for uploads
local LIBPATH = BASEPATH -- default vera directory for modules
local PLUGINPATH = BASEPATH .. PLUGIN_NAME .."/" -- sub directory to keep things uncluttered
local JSON_MODULE = "dkjson.lua"
--  local JSON_MODULE_SIZE = 16947 -- correct size of the json.lua file
-- local DKJSON_MODULE = LIBPATH .. "dkjson.lua"
local VARIABLES_FILE = ""
local LOGFILE = BASEPATH .. "LuaUPnP.log"
local LOGFILECOPY = ""
-- local LOGFILECOMPRESSED = ""
local SETUPFAIL = true

local GC = {} -- Main plugin Variables
GC.timeZone = 0
GC.timeZonehr = 0
GC.timeZonemin = 0
GC.now = os.time()
GC.utc = 0
GC.startofDay = 0
GC.endofDay = 0
GC.Events = {}
GC.nextTimeCheck = os.time()
GC.trippedID = ""
GC.trippedEvent = ""
GC.trippedStatus = "0"
GC.trippedIndex = 0
GC.retrip = "true"
GC.retripTemp = "true"
GC.debug = 3 -- initial default, catches everything before variables initialized

GC.Keyword = ""
GC.ignoreKeyword = "false"
GC.exactKeyword = "true"
GC.triggerNoKeyword = "false"
GC.ignoreAllDayEvent = "false"
GC.StartDelta = 0
GC.EndDelta = 0

GC.access_token = false
GC.access_error = 0
GC.allowEventAdd = true
GC.nextCheckutc = "" -- string Time of next check for calendar in utc time
GC.lastCheckTime = 0
GC.allowCalendarUpdate = true
GC.ExtraDays = 0
GC.notify = {}
GC.CalendarEvents = {}
GC.Status = "Idle" -- default status used to mediate between GCalMain and Calendar Even Adds
GC.notifyLog = {}
GC.processLockCount = 0
GC.Disconnected = ""
GC.dkjson = true
GC.CalendarID = "Not Set"
GC.Interval = 180 * 60 -- default of 3 hrs

-- pointers for required modules
local json = nil
-- local http
local https = nil
local ltn12 = nil

-- control variables
local GCV = {}
-----------------------------
-- Utility local functions
-----------------------------
local function DEBUG(level,s)
  if GC.debug == 0 then return end
  if (level <= GC.debug) then
    s = PRE .." - " .. s
    luup.log(s)
  end
end

local function osExecute(command)
  local result = os.execute(command)
  local msg = 'Command ' .. command .. ' returned ' .. tostring(result)
  DEBUG(3,msg)
  return result
end

local function makejson(str)
  DEBUG(3,"local function: makejson")
  str = tostring(str) or "[]"
  local open = str:match("^%[") or false
  local close = str:match("%]$") or false
  if open and close then return str end
  return "[]"
end

local function readfromfile(filename)
  DEBUG(3,"local function: readfromFile")
  local result = osExecute("/bin/ls " .. filename) -- does the file exist
  if (result ~= 0) then -- return since we cannot read the file
    luup.variable_set(GCAL_SID, "gc_NextEvent",string.gsub(filename,"/(.*)/",""), lul_device)
    luup.variable_set(GCAL_SID, "gc_NextEventTime","Could not Open" , lul_device)
    return nil
  end

  local f = io.open(filename, "r")
  if not f then return false end
  local c = f:read "*a"
  f:close()
  return c
end

local function writetofile (filename,package)
  DEBUG(3,"local function: writetoFile")
  local f = assert(io.open(filename, "w"))
  local t = f:write(package)
  f:close()
  return t
end

-- open / close modules
local function moduleRequire (action)
  if action then -- true opens / false closes
    if type(json) ~= "table" then -- we assume all packages need to be loaded
      if GC.dkjson then
        json = require("dkjson")
      else
        json = require("json")
      end
      https = require("ssl.https")
      https.timeout = 30
      https.method = "GET"
      ltn12 = require("ltn12")
      return true -- loaded on the last call
    else
      return false
    end
  else
    package.loaded.json = nil
    package.loaded.https = nil
    package.loaded.ltn12 = nil
    return false
  end
end

-- Save GCV as a json string
local function setVariables()
  DEBUG(3,"local function: setVariables")
local temp = {}
local Variables = {}
local gcVariables = {}
temp.gCal = GCV.gCal
temp.CalendarID = GCV.CalendarID
local modulerequest = moduleRequire(true)
table.insert(Variables, GCV)
table.insert(gcVariables, temp)
local variables = json.encode(Variables)
local gcvariables = json.encode(gcVariables)
local result = writetofile (VARIABLES_FILE, variables)
if not result then
    local errormsg = "Could not create - " .. VARIABLES_FILE
    DEBUG(1, errormsg)
    return false , errormsg
end
luup.variable_set(GCAL_SID, "gc_Variables",gcvariables, lul_device)
if modulerequest then moduleRequire(false) end
end

-- Retrieve GCV as a json string
local function getVariables()
  DEBUG(3,"Function getVariables")
  local modulerequest = moduleRequire(true)
  local contents = readfromfile(VARIABLES_FILE)
  if not contents then
    local errormsg = "Could not read " .. VARIABLES_FILE
    DEBUG(1, errormsg)
    return false , errormsg
  end
  -- local s1 = luup.variable_get(GCAL_SID, "gc_Variables", lul_device)
   contents = makejson(contents)
GCV = {}
local Variables = {}
Variables = json.decode(contents) -- reads back all the global variables
if Variables[1] == nil then Variables[1] = {} end -- could be very first use of plugin
  GCV.CalendarID = Variables[1].CalendarID or "Not Set"
  GCV.Version = GCAL_VERSION
  GCV.TrippedID = Variables[1].TrippedID or ""
  GCV.LastCheck = Variables[1].LastCheck or os.date("%Y-%m-%dT%H:%M:%S", os.time())
  GCV.NextCheck = Variables[1].NextCheck or os.date("%Y-%m-%dT%H:%M:%S", os.time())
  GCV.gCal = Variables[1].gCal or "true"
  GCV.addCalendar = Variables[1].addCalendar or "false"
  GCV.CredentialFile = Variables[1].CredentialFile or "GCal3.json"
  GCV.CredentialCheck = Variables[1].CredentialCheck or false
  GCV.Events = Variables[1].Events or {}
  local _ = setVariables()
  if modulerequest then moduleRequire(false) end
  return true
end

local function makeBooleanstr(str,default)
  DEBUG(3,"local function: makeBoolean")
  default = tostring(default) or "false"
  default = string.upper(default)
  if (default == "FALSE") then
    default = "false"
  elseif (default == "TRUE") then
    default = "true"
  else
    default = "false" -- default value for default is false
  end
  str = tostring(str) or ""
  str = string.upper(str)
  if (str == "FALSE") then
    return "false"
  elseif (str == "TRUE") then
    return "true"
  else
    return default
  end
end

local function decompress(source, target)
  --decompress the source lzo file and place it in the target location
  --remove the lzo file
  local result = osExecute("pluto-lzo d " .. source .. ".lzo " .. target)
  if result ~= 0 then
    DEBUG(3,"Could not decompress the file - " .. source .. ".lzo")
    return nil
  end
  -- don't need the lzo file any more so delete it
  result = osExecute("/bin/rm -f " .. source .. ".lzo")
end

local function url_format(str)
  local legal_characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;="
  str = string.gsub(str," ","+") -- get rid of any spaces
  for position = 1, #str do
    local char = string.sub(str,position,position)
    if char ~= '%' then
      local found,_ = string.find(legal_characters,char)
      if not found then
        local hex = string.format( "%%%02X", string.byte(char))
        DEBUG(3, 'replace: ' .. char .. ' with ' .. hex)
        str = string.gsub(str,char,hex)
      end
    end
  end
  return str
end

local function upperCase(str)
  str = string.upper(str)
local minusChars={"à","á","â","ã","ä","å","æ","ç","è","é","ê","ë","ì","í","î","ï","ð","ñ","ò","ó","ô","õ","ö","÷","ø","ù","ú","û","ü","ý","þ","ÿ"}
local majusChars={"À","Á","Â","Ã","Ä","Å","Æ","Ç","È","É","Ê","Ë","Ì","Í","Î","Ï","Ð","Ñ","Ò","Ó","Ô","Õ","Ö","÷","Ø","Ù","Ú","Û","Ü","Ý","Þ","ß"}
for i = 1, #minusChars, 1 do
  str = string.gsub(str, minusChars[i], majusChars[i])
end
return str
end

local function trimString(s)
  return string.match( s,"^()%s*$") and "" or string.match(s,"^%s*(.*%S)" )
end

local function strToTime(s) -- assumes utc
  local _,_,year,month,day = string.find(s, "(%d+)-(%d+)-(%d+)")
  local _,_,hour,minute,seconds = string.find(s, "(%d+):(%d+):(%d+)")
  if (hour == nil) then -- an all-day event has no time component so adjust to utc
    hour = - GC.timeZonehr
    minute = - GC.timeZonemin
    seconds = 0
  end
  seconds = seconds or 0 -- just in case not found in string
  return os.time({isdst=os.date("*t").isdst,year=year,month=month,day=day,hour=hour,min=minute,sec=seconds})
end

local function strLocaltostrUTC(s)
  local localtc = strToTime(s)
  local utc = localtc - GC.timeZone -- convert to local
  local ta = os.date("*t",utc)
  return string.format("%04d-%02d-%02dT%02d:%02d:%02dZ", ta.year, ta.month, ta.day, ta.hour, ta.min, 0)
end

-- system, file i/o and related local functions

local function os_command (command)
  DEBUG(3,"local function: os_command")
  DEBUG(3,'Command was: ' .. command)
  local stdout = io.popen(command)
  local result = stdout:read("*a")
  stdout:close()
  return result
end

local function curl_get(url)
  -- quote the url
  url = '"' .. url .. '"'

  local command = 'curl -ksL ' .. url
  local result = os_command(command)
  command = 'curl -ksL -w "%{http_code} %{url_effective}\\n" ' .. url .. ' -o /dev/null' -- just ask return code and url
  local status = os_command(command)
  status = tostring(status)
  local _,_,code = string.find(status,'(%d%d%d)') -- get the first three digits
  code = tonumber(code)
  if code == 200 then
    return result, code
  else
    DEBUG(3,"iCal request error: " .. status)
    DEBUG(1,status)
    return "", code
  end
end

local function getfile(filename,url)
  DEBUG(3,"Downloading " .. filename)
  DEBUG(3,"Attempting to download " .. url)
  local file, code = curl_get(url)
  if (code == 200) then
    DEBUG(3,"Writing file " .. filename)
    local _ = writetofile(filename,file)
    return true
  else
    local errormsg = "Error downloading " .. filename
    DEBUG(1,errormsg)
    DEBUG(1,"Error code " ..code)
    return false
  end
end

-- Authorization related local functions

local function checkforcredentialFile(CredentialFile)
  -- check to see if there is a new credential file
  -- local result = osExecute("/bin/ls " .. BASEPATH .. CredentialFile .. ".lzo")
  local result = osExecute("/bin/ls " .. BASEPATH .. CredentialFile)
  if result == 0 then
    -- result = decompress( BASEPATH .. CredentialFile, PLUGINPATH .. CredentialFile)
    result = osExecute("cp " .. BASEPATH .. CredentialFile .. " " .. PLUGINPATH .. CredentialFile)
  end

  --make sure we have a credentials file
  result = osExecute("/bin/ls " .. PLUGINPATH .. CredentialFile) -- check to see if there is a file
  if result ~= 0 then -- we don't have a credential file
    DEBUG(3,"Could not find the credentials file: ")
    return false
  else
    return true
  end
end

local function checkforcredentials()
  DEBUG(3,"local function: checkforcredentials")
  if not GCV.gCal then return true, "iCal - no Credentials" end

  -- check to see if there is a new credential file
  -- the credentials file needs to be split into component parts
  local errormsg = ""
  if not checkforcredentialFile(GCV.CredentialFile) then
    errormsg = "No Credential File"
    return false , errormsg
  end

  -- now we can decompose the credentialsfile
  local contents = readfromfile(PLUGINPATH .. GCV.CredentialFile)
  if not contents then
    errormsg = "No Credential File"
    DEBUG(1, errormsg)
    return false , errormsg
  end

  if (not string.find(contents, '"type": "service_account"')) then
    errormsg = "Not a Service Account"
    DEBUG(1, errormsg)
    return false , errormsg
  end
  if (not string.find(contents, '"private_key":')) then
    errormsg = "No Private Key"
    DEBUG(1, errormsg)
    return false, errormsg
  end
  if (not string.find(contents, '"client_email":')) then
    errormsg = "No Client email"
    DEBUG(1, errormsg)
    return false, errormsg
  end

  local modulerequest = moduleRequire(true)
  local credentials = json.decode(contents)
  if modulerequest then moduleRequire(false) end

  local pemfile = PLUGINPATH .. string.gsub(GCV.CredentialFile,'.json(.*)',"") ..".pem"
  local pem = credentials.private_key
  local result = osExecute("/bin/rm -f ".. pemfile) -- delete the old one
  result = writetofile (pemfile,pem) -- create the new one
  if not result then
    errormsg = "Could not create - " .. pemfile
    DEBUG(1, errormsg)
    return false , errormsg
  end

  -- get the service account email name
  GC.ClientEmail = credentials.client_email
  return true , "Credentials File Set"
end

local function get_access_token()
  DEBUG(3, "local function: get_access_token")
  -- First check to see if we have an existing unexpired token
  -- get the access token from the file
  local errormsg = ""
  GC.access_token = GC.access_token or false
  if GC.access_token ~= false then
    local url = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" .. GC.access_token
    local body, code, _,status = https.request(url) -- check the token status
    status = status or '"No status returned. Error code was " .. code'
    code = code or '"No code returned. Status was " .. status'

    if (code == 200) then
      local tokencheck = json.decode(body)
      local time_to_expire = tokencheck.expires_in
      DEBUG(2,"Token will expire in " .. time_to_expire .." sec")
      if (time_to_expire > 120) then -- 2 minutes should be plenty
        return GC.access_token , errormsg-- the current token was still valid
      end
    end
    DEBUG(3,"Token Info request status: " .. status)
  end

  -- get a new token
  -- base 64 encoded form of {"alg":"RS256","typ":"JWT"}
  local jwt1 = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9'
  DEBUG(2,"Getting a new token")
  local pemfile = PLUGINPATH .. string.gsub(GCV.CredentialFile,'.json(.*)',"") ..".pem"
  local str, command
  local iss = GC.ClientEmail or ""
  local scope = "https://www.googleapis.com/auth/calendar"
  local aud = "https://accounts.google.com/o/oauth2/token"
  local exp = tostring(os.time() + 3600)
  local iat = tostring(os.time())

  str = '\'{"iss":"' .. iss .. '","scope":"' .. scope .. '","aud":"' .. aud .. '","exp":' .. exp .. ', "iat":' .. iat .. '}\''
  command = "echo -n " .. str .. " | openssl base64 -e"
  local jwt2 = os_command(command)
  if not jwt2 then
    errormsg = "Error encoding jwt2"
    DEBUG(1,errormsg)
    return false, errormsg
  end
  jwt2 = string.gsub(jwt2,"\n","")

  local jwt3 = jwt1 .. "." .. jwt2
  jwt3 = string.gsub(jwt3,"\n","")
  jwt3 = string.gsub(jwt3,"=","")
  jwt3 = string.gsub(jwt3,"/","_")
  jwt3 = string.gsub(jwt3,"%+","-")
  command ="echo -n " .. jwt3 .. " | openssl sha -sha256 -sign " .. pemfile .. " | openssl base64 -e"
  local jwt4 = os_command(command)
  if not jwt4 then
    errormsg = "Error encoding jwt4"
    DEBUG(1, errormsg)
    return false, errormsg
  end
  jwt4 = string.gsub(jwt4,"\n","")

  local jwt5 = string.gsub(jwt4,"\n","")
  jwt5 = string.gsub(jwt5,"=","")
  jwt5 = string.gsub(jwt5,"/","_")
  jwt5 = string.gsub(jwt5,"%+","-")
  command = "curl -k -s -H " .. '"Content-type: application/x-www-form-urlencoded"' .. " -X POST " ..'"https://accounts.google.com/o/oauth2/token"' .. " -d " .. '"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=' .. jwt3 .. "." .. jwt5 ..'"'

  local token = os_command(command)
  DEBUG(3,"Returned Token: " .. tostring(json.encode(token)))
  
  if not token then
    errormsg = "token request failed"
    DEBUG(1,errormsg)
    return false, errormsg
  end

  if (string.find(token, '"error":')) then
    errormsg = "token with error"
    DEBUG(1,errormsg)
    return false, errormsg
  end

  if (not string.find(token, '\"access_token\" :')) then
    errormsg = "missing access_token"
    DEBUG(1,errormsg)
    return false, errormsg
  end
  errormsg = "Got new token"
  DEBUG(2,errormsg)
  local jsontoken = json.decode(token)
  GC.access_token = jsontoken.access_token
  return GC.access_token, errormsg
end

-----------------------------------------------------------------------------------------------------------
-- Variable setup during plugin initialization and subsequent reads
-----------------------------------------------------------------------------------------------------------
local function setupVariables()
  DEBUG(3,"local function: setupVariables")
  -- Because variables do not exist before the first "variable_set"
  -- They are created here in the order that we want them to appear in the Advanced Tab
  local s1 = ""
  local n1 = 0
  
  -- get the control variables
      local result = getVariables()
      if (not result) then
          local errormsg = "Fatal Error could not read the variables file"
          DEBUG(1, errormsg)
          luup.variable_set(GCAL_SID, "gc_NextEvent",errormsg, lul_device)
          return false
      end 
 
  -- disable vera's ignoring of trips
    luup.variable_set(SECURITY_SID, "IgnoreTripTime","0", lul_device)


  s1 = luup.variable_get(SECURITY_SID, "Armed", lul_device)
  if s1 == nil then
    luup.variable_set(SECURITY_SID, "Armed","0", lul_device)
  end
  -- Do not write back as it changes device state

  s1 = luup.variable_get(SECURITY_SID, "Tripped", lul_device)
  if s1 == nil then
    luup.variable_set(SECURITY_SID, "Tripped","0", lul_device)
  end
  GC.trippedStatus = s1
  -- Do not write back as it changes device state

  s1 = luup.variable_get(GCAL_SID, "gc_TrippedEvent", lul_device)
  if s1 == nil then
    luup.variable_set(GCAL_SID, "gc_TrippedEvent","", lul_device)
  end

  GC.trippedID = GCV.TrippedID

  s1 = luup.variable_get(GCAL_SID, "gc_Value", lul_device)
  if s1 == nil then
    luup.variable_set(GCAL_SID, "gc_Value","", lul_device)
  end

  luup.variable_set(GCAL_SID, "gc_NextEvent","", lul_device)

  luup.variable_set(GCAL_SID, "gc_NextEventTime","", lul_device)

  n1 = luup.variable_get(GCAL_SID,"gc_Interval", lul_device)
  n1 = tonumber(n1)
  if ((n1 == nil) or (n1 < 1)) then
    n1 = 180  -- default 3 hrs
    luup.variable_set(GCAL_SID, "gc_Interval",n1, lul_device)
  end
  GC.Interval = n1 * 60 -- convert to seconds

  n1 = luup.variable_get(GCAL_SID, "gc_StartDelta", lul_device)
  n1 = tonumber(n1)
  if n1 == nil then
    n1 = 0
    luup.variable_set(GCAL_SID, "gc_StartDelta",n1, lul_device)
  end
  GC.StartDelta = n1

  n1 = luup.variable_get(GCAL_SID, "gc_EndDelta", lul_device)
  n1 = tonumber(n1)
  if n1 == nil then
    n1 = 0
    luup.variable_set(GCAL_SID, "gc_EndDelta",n1, lul_device)
  end
  GC.EndDelta = n1

  s1 = luup.variable_get(GCAL_SID, "gc_Keyword", lul_device)
  if s1 == nil then
    s1 = ""
    luup.variable_set(GCAL_SID, "gc_Keyword",s1, lul_device)
  end
  GC.Keyword = s1

  s1 = luup.variable_get(GCAL_SID, "gc_exactKeyword", lul_device)
  s1 = makeBooleanstr(s1,true)
  luup.variable_set(GCAL_SID, "gc_exactKeyword",s1, lul_device)
  GC.exactKeyword = s1

  s1 = luup.variable_get(GCAL_SID, "gc_ignoreKeyword", lul_device)
  s1 = makeBooleanstr(s1,false)
  luup.variable_set(GCAL_SID, "gc_ignoreKeyword",s1, lul_device)
  GC.ignoreKeyword = s1

  s1 = luup.variable_get(GCAL_SID, "gc_triggerNoKeyword", lul_device)
  s1 = makeBooleanstr(s1,false)
  luup.variable_set(GCAL_SID, "gc_triggerNoKeyword",s1, lul_device)
  GC.triggerNoKeyword = s1

  s1 = luup.variable_get(GCAL_SID, "gc_ignoreAllDayEvent", lul_device)
  s1 = makeBooleanstr(s1,false)
  luup.variable_set(GCAL_SID, "gc_ignoreAllDayEvent",s1, lul_device)
  GC.ignoreAllDayEvent = s1

  s1 = luup.variable_get(GCAL_SID, "gc_retrip", lul_device)
  s1 = makeBooleanstr(s1,true)
  luup.variable_set(GCAL_SID, "gc_retrip",s1, lul_device)
  GC.retrip = s1

  n1 = luup.variable_get(GCAL_SID, "gc_ExtraDays", lul_device)
  n1 = tonumber(n1)
  if ((n1 == nil) or (n1 < 0)) then
    n1 = 0
    luup.variable_set(GCAL_SID, "gc_ExtraDays",n1, lul_device)
  end
  GC.ExtraDays = n1

  s1 = luup.variable_get(GCAL_SID, "gc_jsonEvents", lul_device)
  s1 = makejson(s1)
  luup.variable_set(GCAL_SID, "gc_jsonEvents",s1, lul_device)

  s1 = luup.variable_get(GCAL_SID, "gc_jsonActiveEvents", lul_device)
  s1 = makejson(s1)
  luup.variable_set(GCAL_SID, "gc_jsonActiveEvents",s1, lul_device)

  s1 = luup.variable_get(GCAL_SID, "gc_ActiveEvents", lul_device)
  if s1 == nil then s1 = "" end
  luup.variable_set(GCAL_SID, "gc_ActiveEvents",s1, lul_device)

  n1 = luup.variable_get(GCAL_SID, "gc_EventsToday", lul_device)
  n1 = tonumber(n1)
  if n1 == nil then
    luup.variable_set(GCAL_SID, "gc_EventsToday",0, lul_device)
  end

  n1 = luup.variable_get(GCAL_SID, "gc_EventsLeftToday", lul_device)
  n1 = tonumber(n1)
  if n1 == nil then
    luup.variable_set(GCAL_SID, "gc_EventsLeftToday",0, lul_device)
  end

  n1 = luup.variable_get(GCAL_SID, "gc_debug", lul_device)
  n1 = tonumber(n1)
  if n1 == nil then
    n1 = 3 -- default to max debug
    luup.variable_set(GCAL_SID, "gc_debug",n1, lul_device) -- default debug level
  end
  GC.debug = n1

  n1 = luup.variable_get(GCAL_SID, "gc_displaystatus", lul_device)
  n1 = tonumber(n1) or 0
  luup.variable_set(GCAL_SID, "gc_displaystatus",n1, lul_device)

  s1 = luup.variable_get(GCAL_SID, "gc_notify", lul_device)
  if s1 == nil then
    luup.variable_set(GCAL_SID, "gc_notify","0", lul_device)
  end

  s1 = luup.variable_get(GCAL_SID, "gc_notifyName", lul_device)
  if s1 == nil then
    luup.variable_set(GCAL_SID, "gc_notifyName","", lul_device)
  end

  s1 = luup.variable_get(GCAL_SID, "gc_notifyValue", lul_device)
  if s1 == nil then
    luup.variable_set(GCAL_SID, "gc_notifyValue","", lul_device)
  end

  s1 = luup.variable_get(GCAL_SID, "gc_notifyType", lul_device)
  if s1 == nil then
    luup.variable_set(GCAL_SID, "gc_notifyType","", lul_device)
  end
  
  s1 = luup.variable_get(GCAL_SID, "gc_Variables", lul_device)
  s1 = makejson(s1)
  luup.variable_set(GCAL_SID, "gc_Variables",s1, lul_device)
  
end

local function getStartMinMax(startdelta,enddelta)
  DEBUG(3,"local function: getStartMinMax")
  local s1, s2, s3 = "","",""
  -- startmin and startmax use utc but startmin must be at least start of today local time
  local starttime, endofday, endtime = GC.now, GC.now, GC.now
  --local endofday = starttime
  local ta = os.date("*t", starttime)
  s1 = string.format("%d-%02d-%02dT%02d:%02d:%02d", ta.year, ta.month, ta.day, 00, 00, 00)
  starttime = strToTime(s1)
  s3 = string.format("%d-%02d-%02dT%02d:%02d:%02d", ta.year, ta.month, ta.day + 1  , 00, 00, 00)
  endofday = strToTime(s3)
  GC.startofDay = starttime
  GC.endofDay = endofday --  + GC.timeZone -- convert to utc
  
  -- look back 5 minutes to make sure we catch midnight events with the calendar lookup
  starttime = starttime - (60*5)
  
  -- look forward to the next refresh interval so we catch events in that interval
  if GC.ExtraDays > 0 then
    endtime = endtime + (3600*24*GC.ExtraDays)
  else
    endtime = endtime + GC.Interval
  end
  ta = os.date("*t", endtime)
  s2 = string.format("%d-%02d-%02dT%02d:%02d:%02d", ta.year, ta.month, ta.day + 1, 00, 00, 00) -- make it the end of day
  endtime = strToTime(s2)
  
  -- adjust for any start and end delta
  if (startdelta < 0) then -- look back in time
    starttime = starttime - (startdelta * 60)
  end
  if (enddelta > 0) then -- look forward in time
    endtime = endtime + (enddelta * 60)
  end

  ta = os.date("*t", starttime)
  s1 = string.format("%d-%02d-%02dT%02d:%02d:%02d.000", ta.year, ta.month, ta.day, ta.hour, ta.min, ta.sec)
  s1 = strLocaltostrUTC(s1)
  ta = os.date("*t", endtime)
  s2 = string.format("%d-%02d-%02dT%02d:%02d:%02d.000", ta.year, ta.month, ta.day, ta.hour, ta.min, ta.sec)
  s2 = strLocaltostrUTC(s2)
  DEBUG(3,"StartMin is " .. s1 .. " StartMax is " .. s2)
  DEBUG(3,"End of day is " .. s3)
  return s1, s2 -- in utc
end

local function formatDate(line) -- used to interpret ical
  local _,_,year,month,day = string.find(line,":(%d%d%d%d)(%d%d)(%d%d)") -- get the date
  local datetime = year .. "-" .. month .. "-" .. day -- format for google
  local _,_,hour,min,sec = string.find(line,"T(%d%d)(%d%d)(%d%d)Z")
  if (hour ~= nil) then -- time was specified in utc
    datetime = datetime .. "T" .. hour .. ":" .. min .. ":" .. sec .. "Z"
  else -- date and time are local and need to be converted to utc
    local _,_,hour,min,sec = string.find(line,"T(%d%d)(%d%d)(%d%d)")
    if (hour ~= nil) then -- this is a local time format and needs to be converted to utc
      datetime = datetime .. "T" .. hour .. ":" .. min .. ":" .. sec
      datetime = strLocaltostrUTC(datetime)
    end
  end
  return datetime
end

function tableInsertSorted(sorted,entry)
  local noinsert = true
  for i = #sorted,1,-1 do
    if sorted[i].stime < entry.stime then
      table.insert(sorted, i+1, entry)
      noinsert = false
      break
    end
  end
  if noinsert then table.insert(sorted,1,entry) end
  return
end


local function requestiCalendar(startmin, startmax)
  -- directly accesses an iCal - no credentials are checked no logon to google
  DEBUG(3,"local function: requestiCalendar")
  GC.Status = "requestiCalendar"
  startmin = string.gsub(startmin,"%.000Z","Z")
  local startminTime = strToTime(startmin)
  startmax = string.gsub(startmax,"%.000Z","Z")
  local startmaxTime = strToTime(startmax)

  if (GC.CalendarID == "Not Set") then
    DEBUG(3,"iCalendar ID is not set.")
    luup.variable_set(GCAL_SID, "gc_NextEvent","Missing iCalendar ID", lul_device)
    luup.variable_set(GCAL_SID, "gc_NextEventTime","" , lul_device)
    return nil,"stop"
  end

  DEBUG(2,"Checking iCal calendar")

  local url = GC.CalendarID

  luup.variable_set(GCAL_SID, "gc_NextEvent","Accessing iCal", lul_device)
  luup.variable_set(GCAL_SID, "gc_NextEventTime","" , lul_device)

  DEBUG(3,"Requested url: " .. url)
  local result, code = curl_get(url)

  if code ~= 200 then
    luup.variable_set(GCAL_SID, "gc_NextEvent","iCal error code: " .. code, lul_device)
    return nil,"retry"
  end

  if not string.find(result,'BEGIN:VCALENDAR') then
    luup.variable_set(GCAL_SID, "gc_NextEvent","Invalid iCal format" .. code, lul_device)
    return nil,"stop"
  end

local ical, icalevent = {}
local eventStart, eventEnd, eventName, eventDescription, _
local inEvent = false
-- Parse the iCal data
luup.variable_set(GCAL_SID, "gc_NextEvent","Start Parsing iCal", lul_device)
for line in result:gmatch("(.-)[\r\n]+") do

  if line:match("^BEGIN:VCALENDAR") then DEBUG(3,"Start parsing iCal") end
  if line:match("^END:VCALENDAR") then DEBUG(3,"End parsing iCal") end
  if line:match("^BEGIN:VEVENT") then
  icalevent = {}
  eventStart, eventEnd, eventName, eventDescription = ""
  inEvent = true
  DEBUG(3,"Found iCal event")
end
if (inEvent == true) then
  if line:match("^DTSTART") then eventStart = formatDate(line); DEBUG(3,"iCal Event Start is : " .. eventStart) end
  if line:match("^SUMMARY") then _,_,eventName = string.find(line,":(.-)$"); DEBUG(3,"iCal Event Name is : " .. eventName) end
  if line:match("^DTEND") then eventEnd = formatDate(line); DEBUG(3,"iCal Event End is : " .. eventEnd) end
  if line:match("^DESCRIPTION") then _,_,eventDescription = string.find(line,":(.*)$") end -- only gets one line
    if line:match("^END:VEVENT") then
      inEvent = false
      if ((strToTime(eventStart) >= startminTime) and (strToTime(eventStart) <= startmaxTime)) then
        if string.find(eventStart,"T") then -- not an all day event
        icalevent = {["start"] = {["dateTime"] = eventStart},["end"] = {["dateTime"] = eventEnd},["summary"] = eventName,["description"] = eventDescription}
      else
      icalevent = {["start"] = {["date"] = eventStart},["end"] = {["date"] = eventEnd},["summary"] = eventName,["description"] = eventDescription}
    end
    table.insert(ical, icalevent)
  end
end
end
end

if (#ical == 0) then
  DEBUG(1,"No iCal events found. Retry later")
  luup.variable_set(GCAL_SID, "gc_NextEvent","No iCal events found today" , lul_device)
  luup.variable_set(GCAL_SID, "gc_NextEventTime","", lul_device)
  luup.variable_set(GCAL_SID, "gc_EventsToday",0, lul_device)
  luup.variable_set(GCAL_SID, "gc_EventsLeftToday",0, lul_device)
  local _ = setTrippedOff(GC.trippedStatus)
  return "No Events","No Events"
else
  luup.variable_set(GCAL_SID, "gc_NextEvent","Found " .. #ical .. " iCal events", lul_device)
  return ical, "events found"
end
end

local function requestCalendar(startmin, startmax)
  DEBUG(3,"local function: requestCalendar")
  GC.Status = "requestCalendar"

  if (GC.CalendarID == "Not Set") then
    DEBUG(3,"Calendar ID is not set.")
    luup.variable_set(GCAL_SID, "gc_NextEvent","Calendar ID not set", lul_device)
    luup.variable_set(GCAL_SID, "gc_NextEventTime","", lul_device)
    return nil,"stop"
  end
  local errormsg = ""
  GC.access_token, errormsg = get_access_token ()
  if GC.access_token == false then
    luup.variable_set(GCAL_SID, "gc_NextEventTime",errormsg, lul_device)
    if SETUPFAIL and (not GCV.CredentialCheck) then return nil,"stop" else return nil,"retry" end
  end
  SETUPFAIL = false --If successgfully got credentials once then setup succeeded
  GCV.CredentialCheck = true
  local _ = setVariables
  DEBUG(2,"Checking google calendar")

  local url = "https://www.googleapis.com/calendar/v3/calendars/".. GC.CalendarID .. "/events?"
  url = url .. "access_token=" .. GC.access_token
  url = url .. "&timeZone=utc&singleEvents=true&orderBy=startTime"
  url = url .. "&timeMax=" .. startmax .. "&timeMin=" .. startmin
  url = url .. "&fields=items(description%2Cend%2Cstart%2Csummary)"

  luup.variable_set(GCAL_SID, "gc_NextEvent","Accessing Calendar", lul_device)
  luup.variable_set(GCAL_SID, "gc_NextEventTime","" , lul_device)

  DEBUG(3,"Requested url: " .. url)

  local body,code,_,status = https.request(url) -- get the calendar data

  status = status or "No status returned"
  code = code or "No code returned"
  if (not tonumber(code)) then
    DEBUG(1,"https.request returned an error with Code: " .. code .. "and Status: " .. status)
    return nil,"retry"
  end

  if (code ~= 200) then -- anything other than 200 is an error
    local errorMessage
    if (code == 404) then
      errorMessage = "Check Credentials: " .. code
    else
      errorMessage = "Http error code: " .. code
    end
    DEBUG(3,errorMessage)
    luup.variable_set(GCAL_SID, "gc_NextEvent",errorMessage , lul_device)
    luup.variable_set(GCAL_SID, "gc_NextEventTime","", lul_device)
    return nil,"retry"
  end
  
  DEBUG(2,"Calendar request status: " .. status)
  
  -- make sure we have well formed json
  local goodjson = string.find(body, "items")
  if (not goodjson) then
    DEBUG(1,"Calendar data problem - no items tag. Retry later...")
    luup.variable_set(GCAL_SID, "gc_NextEvent","Bad Calendar data" , lul_device)
    luup.variable_set(GCAL_SID, "gc_NextEventTime","", lul_device)
    return nil,"retry"
  end

  local noitems = string.find(body, '%"items%"%:% %[%]') -- empty items array
  if (noitems) then
    DEBUG(1,"No event items found . Retry later...")
    DEBUG(3, json.encode(body)) 
    luup.variable_set(GCAL_SID, "gc_NextEvent","No event items found" , lul_device)
    luup.variable_set(GCAL_SID, "gc_NextEventTime","", lul_device)
    luup.variable_set(GCAL_SID, "gc_EventsToday",0, lul_device)
    luup.variable_set(GCAL_SID, "gc_EventsLeftToday",0, lul_device)
    local _ = setTrippedOff(GC.trippedStatus)
    return "No Events","No Events"
  end
  DEBUG(2,"Calendar request code: " .. code)

  -- decode the calendar info
  local json_root = json.decode(body)

  local events = json_root.items

  if (events[1] == nil) then
    DEBUG(1,"No events found. Retry later...")
    luup.variable_set(GCAL_SID, "gc_NextEvent","No events found" , lul_device)
    luup.variable_set(GCAL_SID, "gc_NextEventTime","", lul_device)
    luup.variable_set(GCAL_SID, "gc_EventsToday",0, lul_device)
    luup.variable_set(GCAL_SID, "gc_EventsLeftToday",0, lul_device)
    local _ = setTrippedOff(GC.trippedStatus)
    return "No Events","No Events"
  end
  luup.variable_set(GCAL_SID, "gc_NextEvent","Calendar Access Success", lul_device)
  luup.variable_set(GCAL_SID, "gc_NextEventTime","" , lul_device)

  return events, "events found" -- an table of calendar events
end

local function allDay(start)
  DEBUG(3,"local function: allDay")
  -- Get the start time for the event
  local _,_,esHour,_,_ = string.find(start, "(%d+):(%d+):(%d+)")
  local allDayEvent
  if (esHour == nil) then -- an all day event has no hour component
    allDayEvent = os.date("%d %b", strToTime(start))
  else
    allDayEvent = ""
  end
  return allDayEvent
end

local function getjsonEvents() -- this is really some sample code and useful for debugging
  DEBUG(3,"local function: getjsonEvents")
  local jsonEvents = luup.variable_get(GCAL_SID, "gc_jsonEvents",lul_device)

  if (jsonEvents == "[]") then -- equivalent of a nul so don't try
    return
  end

  local eventList =json.decode(jsonEvents)
  local numberEvents = #eventList
  local startevent, startDate, startTime, endevent, endTime, eventname, eventdescription, event

  for i = 1,numberEvents do
    startevent = eventList[i].eventStart
    --startevent = os.date("%Y-%m-%dT%H:%M:%S",startevent)
    startDate = os.date("%Y-%m-%d", startevent)
    startTime = os.date("%H:%M:%S", startevent)
    endevent = eventList[i].eventEnd
    endTime = os.date("%H:%M:%S", endevent)
    eventname = eventList[i].eventName
    eventdescription = eventList[i].eventDescription or "None"
    event = "On " .. startDate .. " event " .. eventname .. " will start at " .. startTime .. " and end at " .. endTime
    DEBUG(3,"Event " .. i .. ": " .. event)
    DEBUG(3, "Description = " .. eventdescription)
  end
  return
end

local function saveEvents() -- saves a version of events and checkpoints the calendar data
  DEBUG(3,"local function: saveEvents")
local eventsJson = {}
local jsonEvents = {}
local activeEventsJson = {}
local jsonActiveEvents = {}
local numberEvents = #GC.Events
-- Create a local time version of events for access as a variable
if numberEvents == 0 then
  luup.variable_set(GCAL_SID, "gc_jsonEvents","[]", lul_device)
  luup.variable_set(GCAL_SID, "gc_jsonActiveEvents","[]", lul_device)
  luup.variable_set(GCAL_SID, "gc_ActiveEvents","", lul_device)
  return
end

local event = {}
for i = 1,numberEvents do
jsonEvents = {}
event = GC.Events[i]
-- convert datetime to local time for easier use by others
jsonEvents.eventStart = event.stime + GC.timeZone
jsonEvents.eventEnd = event.etime + GC.timeZone
jsonEvents.eventName = event.title
jsonEvents.eventParameter = event.value
jsonEvents.eventDescription = event.description
table.insert(eventsJson, jsonEvents)
end

local ActiveEvents = ""
for i = 1,numberEvents do
  event = GC.Events[i]
jsonActiveEvents = {}
if ((event.stime <= GC.utc) and (GC.utc < event.etime)) then -- we are inside the event
  if (ActiveEvents == "" ) then
    ActiveEvents = event.title
  else
    ActiveEvents = ActiveEvents .. " , " .. event.title
  end
  jsonActiveEvents.eventName = event.title
  jsonActiveEvents.eventParameter = event.value
  table.insert(activeEventsJson, jsonActiveEvents)
end
end

luup.variable_set(GCAL_SID, "gc_ActiveEvents",ActiveEvents, lul_device)
ActiveEvents = ActiveEvents or "None"
DEBUG(3, "Active Events: " .. ActiveEvents)

local eventList =json.encode(eventsJson) -- encode the table for storage as a string

luup.variable_set(GCAL_SID, "gc_jsonEvents",eventList, lul_device)
DEBUG(3,"json event list " .. eventList)

eventList =json.encode(activeEventsJson) -- encode the table for storage as a string

luup.variable_set(GCAL_SID, "gc_jsonActiveEvents",eventList, lul_device)
DEBUG(2,"json active event list " .. eventList)

-- log it with sample code
if (GC.debug == 3) then getjsonEvents() end

return
end

-- ***********************************************************
-- This local function extracts the events from the calendar data
-- , does keyword matching where appropriate,
-- interprets start and end offsets, filters out
-- unwanted events
-- ***********************************************************

local function getEvents(eventlist, keyword,startdelta, enddelta, ignoreAllDayEvent, ignoreKeyword, exactKeyword)
  DEBUG(3,"local function: getEvents")

  -- Create a global array of events. Each row contains:
  -- event.stime -- starttime in utc
  -- event.etime -- endtime in utc
  -- event.title -- title as uppercase string
  -- event.value -- optional parameter as mixed case string
  -- event.description -- description as entered into calendar
  -- event.allday -- if All Day event then date in dd Mon format else ""
  -- event.endid -- unique event end id == concatination of title,endtime
  -- event.startid -- unique event start id == concatination of title,startime

  luup.variable_set(GCAL_SID, "gc_NextEvent","Checking Events", lul_device)
  luup.variable_set(GCAL_SID, "gc_NextEventTime","" , lul_device)

  local globalstartend = "[" .. startdelta .. "," .. enddelta .. "]"
  
  GC.Events = {} -- reset all Events
local event = {}
local keywords = {}
local key = {}
-- if one or more keywords, parse them into a usable form
if (keyword ~= "") then
  for keys in string.gmatch(keyword,"([^;]+)") do
  key = {}
  local _,_,keywordstartend = string.find(keys,"%[(.-)%]") -- does the keyword have a start / stop delta i.e. something in []?
  local _,_,keywordparameter = string.find(keys,"%{(.-)%}") -- does the keyword have a parameter i.e. something in {}?
  if (keywordstartend ~= nil) then
    key.delta = "[" .. keywordstartend .. "]"
    keys = string.gsub(keys, "%[(.-)%]", "") -- remove anything in []
  else
    key.delta = ""
  end
  if (keywordparameter ~= nil) then
    key.value = keywordparameter
    keys = string.gsub(keys, "%{(.-)%}", "") -- remove anything in {}
  else
    key.value = ""
  end
  key.name = trimString(upperCase(keys))
  table.insert(keywords,key)
end
else
  key.name = "" -- no keyword
  key.value = "" -- no value
  key.delta = "" -- no delta
  table.insert(keywords,key)
end

-- iterate through each of the events and interpret any special instructions
local numberEvents = #eventlist
DEBUG(2,"There were " .. numberEvents .. " events retrieved")
DEBUG(3, "Start of day = " .. os.date("%Y-%m-%d at %H:%M:%S", GC.startofDay) .. " End of day = " .. os.date("%Y-%m-%d at %H:%M:%S", GC.endofDay))
-- local j = 1
local EventsToday = 0
local EventsLeftToday = 0
-- local event = {}
for i=1,numberEvents do
  -- get the start and end times
  local eventStart = (eventlist[i]['start'].date or eventlist[i]['start'].dateTime)
  local allDayEvent = allDay(eventStart) -- flag if all day event
  local starttime = strToTime(eventStart)
  local endtime = strToTime(eventlist[i]['end'].date or eventlist[i]['end'].dateTime)
  
  -- get the title and any start / stop delta or parameter
  local eventname = (eventlist[i]['summary'] or "No Name")
  eventname = trimString(eventname)
  local _,_,eventstartend = string.find(eventname,"%[(.-)%]") -- does the event have a start / stop delta
  local _,_,eventparameter = string.find(eventname,"%{(.-)%}") -- does the event have a parameter
  local eventtitle = string.gsub(eventname, "%{(.-)%}", "") -- remove anything in {}
  eventtitle = string.gsub(eventtitle, "%[(.-)%]", "") -- remove anything in []
  eventtitle= trimString(upperCase(eventtitle)) -- force to upper case and trim

  -- get the description and any start / stop delta or parameter
  local description = (eventlist[i]['description'] or "none")
  -- description = trimString(upperCase(description))
  -- does the description have a start / stop delta
  local _,_,descriptionstartend = string.find(description,"%[(.-)%]")
  -- does the description have a parameter
  local _,_,descriptionparameter = string.find(description,"%{(.-)%}")
  -- remove additional arguments
  local descriptiontext = string.gsub(description, "%{(.-)%}", "") -- remove anything in {}
  descriptiontext = string.gsub(descriptiontext, "%[(.-)%]", "") -- remove anything in []
  descriptiontext = trimString(upperCase(descriptiontext))
  
  -- see if we have a keyword match in the title or the desciption
  local matchedEvent = false
  local matchAllEvents = false
  local matchedDescription = false
  local keyindex = 1
  local numkeywords = #keywords
  -- key = {}
  if (keyword == "") then -- all events match
    matchAllEvents = true
  else
    for j = 1,numkeywords do
      key = keywords[j]
      if (exactKeyword == "true") then -- we test for an exact match
        if ((eventtitle == key.name) or (descriptiontext == key.name)) then
          matchedEvent = true
          keyindex = j
          break
        end
      else -- we test for a loose match
        matchedEvent = string.find(eventtitle,key.name)
        matchedDescription = string.find(descriptiontext,key.name)
        matchedEvent = matchedEvent or matchedDescription
        if matchedEvent then
          DEBUG(3,"Fuzzy Match: " .. eventtitle .. " -- " .. key.name)
          keyindex = j
          break
        end
      end
    end
  end

  -- add start/end delta if specified
  local effectiveEventName
  eventname = eventtitle
  key = keywords[keyindex]
  if (matchedEvent and (key.delta ~= "")) then -- offset specified for the keyword takes precedence
    eventname = eventname .. key.delta
  elseif (eventstartend ~= nil) then
    eventname = eventname .. "[" .. eventstartend .. "]"
  elseif (descriptionstartend ~= nil) then
    eventname = eventname .. "[" .. descriptionstartend .. "]"
  else -- use the global value
  eventname = eventname .. globalstartend
end

-- add parameter if specified
local value = ""
if (matchedEvent and (key.value ~= "")) then -- parameter specified for the keyword takes precedence
  value = trimString(key.value)
elseif (eventparameter ~= nil) then
  value = trimString(eventparameter)
elseif (descriptionparameter ~= nil) then
  value = trimString(descriptionparameter)
end

effectiveEventName = eventname .. "{" ..value .. "}" -- this normalizes the 'value' parameter
DEBUG(3,"Effective Event Name " .. effectiveEventName)

-- apply any start end offsets
local _,_,startoffset,endoffset = string.find(eventname,"%[%s*([+-]?%d+)%s*,%s*([+-]?%d+)%s*%]") -- look in the title
DEBUG(3,"startoffset = " .. startoffset .. " endoffset = " .. endoffset)
startoffset = tonumber(startoffset)
endoffset = tonumber(endoffset)
if (startoffset and endoffset) then
  starttime = starttime + (startoffset * 60)
  endtime = endtime + (endoffset * 60)
end

-- filter out unwanted events
if ((ignoreAllDayEvent == "true") and (allDayEvent ~= "")) then -- it's an all day event and to be ignored
  DEBUG(2,"All Day Event " .. effectiveEventName .. " Ignored")
elseif ((ignoreKeyword == "true") and matchedEvent) then -- matched keyword and to be ignored
  DEBUG(2,"Event matched keyword " .. effectiveEventName .. " Ignored")
elseif ((endtime - starttime) < 0) then -- event cannot end before it starts
  DEBUG(2,"Event effectively ends before it starts: " .. effectiveEventName .. " Ignored")
elseif ((not matchAllEvents and matchedEvent) or matchAllEvents or (ignoreKeyword == "true") ) then -- good to go
  if ((endtime - starttime) < 60) then -- make each event at least 60 seconds so start/end updates occur
    endtime = starttime + 60
  end
  -- add a new entry into the list of valid events
event = {}
event.stime = starttime
event.etime = endtime
event.title = eventtitle
event.value = value
event.description = description
if ((startoffset == 0) and (endoffset == 0)) then
  event.allday = allDayEvent
else
  event.allday = ""
end
local ta = os.date("*t", endtime + GC.timeZone)
local s1 = string.format("%02d/%02d %02d:%02d",ta.month, ta.day, ta.hour, ta.min)
event.endid = eventtitle .. " " ..s1
ta = os.date("*t", starttime + GC.timeZone)
s1 = string.format("%02d/%02d %02d:%02d",ta.month, ta.day, ta.hour, ta.min)
event.startid = eventtitle .. " " ..s1
tableInsertSorted(GC.Events, event)

-- change the times to local for logical ease of comparison
starttime = starttime + GC.timeZone -- convert to local time
endtime = endtime + GC.timeZone -- convert to local time

--  The day starts at 00:00:00 and ends at 23:59:59 (logically)
if (((GC.startofDay <= starttime) and (starttime < GC.endofDay)) or ((GC.startofDay < endtime) and (endtime <= GC.endofDay))) then
  EventsToday = EventsToday + 1
  DEBUG(3, "Events Today: Count = " .. tostring(EventsToday))
else
  DEBUG(3, "Not one of today's events")
end

-- another fudge using GC.now instead of GC.utc
if (((GC.now <= starttime) and (starttime < GC.endofDay)) or ((GC.now <= endtime) and (endtime < GC.endofDay))) then
  EventsLeftToday = EventsLeftToday + 1
  DEBUG(3, "Events Left: Count = " .. tostring(EventsLeftToday))
  else
  DEBUG(3, "Event is in the past")
end
end
end

DEBUG(2, "Events Today = " .. tostring(EventsToday))
DEBUG(2, "Events Left Today = " .. tostring(EventsLeftToday))
luup.variable_set(GCAL_SID, "gc_EventsToday",EventsToday, lul_device)
luup.variable_set(GCAL_SID, "gc_EventsLeftToday",EventsLeftToday, lul_device)
end

-- ************************************************************
-- This local function determines if there is an event to trigger on
-- ************************************************************

local function nextEvent()
  DEBUG(3,"local function: nextEvent")
  local eventtitle = GC.Disconnected .. "No more events today"
  local nextEventTime = ""
  local nextEvent = -1
  local index = 0
  local numberEvents = table.getn(GC.Events)
local event = {}
GC.nextTimeCheck = GC.now + GC.Interval

for i = 1,numberEvents do
  event = GC.Events[i]
  if ((event.stime <= GC.utc) and (GC.utc < event.etime)) then -- we are inside an event
    nextEvent = i
    index = i
    eventtitle = event.title
    GC.nextTimeCheck = event.etime + GC.timeZone -- in local time
    break
  elseif ((nextEvent == -1) and (event.stime >= GC.utc)) then -- future event
    nextEvent = 0
    index = i
    eventtitle = event.title
    GC.nextTimeCheck = event.stime + GC.timeZone -- in local time
    break -- only need the first one
  end
end
event = GC.Events[index]
if (nextEvent ~= -1) then
  nextEventTime = os.date("%H:%M %b %d", event.stime + GC.timeZone) .. " to " .. os.date("%H:%M %b %d", event.etime + GC.timeZone)
end
eventtitle = GC.Disconnected .. string.sub(eventtitle,1,40) 
luup.variable_set(GCAL_SID, "gc_NextEvent",eventtitle , lul_device)
luup.variable_set(GCAL_SID, "gc_NextEventTime",nextEventTime , lul_device)
DEBUG(2,"Next Event: " .. index .. " " .. eventtitle .. " -- " .. nextEventTime)
return nextEvent
end

function setTrippedOff(tripped)
  tripped = tostring(tripped)
  -- DEBUG(3,"local function: setTrippedOff: " .. tostring(tripped))
  DEBUG(3,"local function: setTrippedOff: " .. tripped)

  luup.variable_set(GCAL_SID, "gc_Value", "", lul_device)
  GC.trippedEvent = ""
  luup.variable_set(GCAL_SID, "gc_TrippedEvent",GC.trippedEvent, lul_device)

  -- luup.variable_set(SECURITY_SID, "Tripped","0", lul_device)  -- force to not Tripped


  if (tripped == "1") then
    luup.variable_set(SECURITY_SID, "Tripped","0", lul_device)
    DEBUG(1,"**** Event-End " .. GC.trippedID .. " not Tripped ****")
  else
    DEBUG(1,"**** Event-End " .. GC.trippedID .. " not Active ****")
  end

  GC.trippedID = ""
  GCV.TrippedID = GC.trippedID
  local _ = setVariables()
  luup.variable_set(GCAL_SID, "gc_displaystatus",0, lul_device)
  return "0"
end

function setTripped(i, tripped)
  tripped = tostring(tripped)
  -- DEBUG(3,"local function: setTripped: " .. tostring(tripped))
  DEBUG(3,"local function: setTripped: " .. tripped)
  local event = {}
  event = GC.Events[i]
  GC.trippedIndex = i
  if ((event.endid == GC.trippedID)) then -- in the same event
    if (tripped == "1") then
      DEBUG(1,"**** Event-Start " .. event.startid .. " is already Tripped ****")
    else
      DEBUG(1,"**** Event-Start " .. event.startid .. " is already Active ****")
    end
  return tripped
end

local delay = 5 -- propogation delay for off / on transition

if (tripped == "1" and (event.endid ~= GC.trippedID)) then -- logically a new event
  if ((event.startid == GC.trippedID) and (GC.retrip == "false")) then
    -- if the name and time for the start of the next event = the prior event finish and we should not retrip
    GC.trippedID = event.endid -- update with the continuation event
    GCV.TrippedID = GC.trippedID
    local _ = setVariables()
    DEBUG(1,"Continuing prior event " .. GC.trippedID)
    return tripped
  else -- finish the previous and start the new event
    tripped = setTrippedOff("1")
    DEBUG(2,"Waiting " .. delay .. " sec to trigger the next event")
    luup.call_timer("setTrippedOn",1,delay,"","") -- wait 'delay' sec for the off status to propogate
  end
  return tripped
end
if (tripped == "0") then
  tripped = setTrippedOff("0") -- could have been a non-tripped but active event
  DEBUG(2,"Waiting " .. delay .. " sec to activate the next event")
  luup.call_timer("setTrippedOn",1,delay,"","") -- wait 'delay' sec for the off status to propogate
end
DEBUG(2,"No action on setTripped")
return tripped
end

function setTrippedOn()
  DEBUG(3,"local function: setTrippedOn")
  local i = GC.trippedIndex
  local event = GC.Events[i]
  luup.variable_set(GCAL_SID, "gc_NextEvent", event.title, lul_device)
  luup.variable_set(GCAL_SID, "gc_Value", event.value, lul_device)
  local TrippedEvent = luup.variable_get(GCAL_SID, "gc_TrippedEvent", lul_device)
  GC.trippedEvent = event.title
  if (GC.trippedEvent ~= TrippedEvent) then -- defensive code, some evidence of multiple scene triggers
    luup.variable_set(GCAL_SID, "gc_TrippedEvent",GC.trippedEvent, lul_device)
  end
  GC.trippedID = event.endid -- the end id for the event
  GCV.TrippedID = GC.trippedID
  local _ = setVariables()

  if (GC.Keyword ~= "") or (GC.triggerNoKeyword == "true") then
    luup.variable_set(SECURITY_SID, "Tripped","1", lul_device)
    luup.variable_set(GCAL_SID, "gc_displaystatus",100, lul_device)
    DEBUG(1,"**** Event-Start " .. event.startid .. " Tripped ****")
  else
    luup.variable_set(GCAL_SID, "gc_displaystatus",50, lul_device)
    DEBUG(1,"**** Event-Start " .. event.startid .. " Active ****")
  end
  local _ = notify(i)
end

local function setNextTimeCheck() -- returns the actual time for the next check in local time
  DEBUG(3,"local function: setNextTimeCheck")
  if ((GC.nextTimeCheck - GC.now) > GC.Interval) then -- min check interval is gc_Interval
    GC.nextTimeCheck = GC.now + GC.Interval
    DEBUG(3, "nextTimeCheck is: " .. GC.Interval .. " seconds from now")
  end
  if (GC.nextTimeCheck == GC.now) then -- unlikely but could happen
    GC.nextTimeCheck = GC.now + 60 -- check again in 60 seconds
    DEBUG(3, "nextTimeCheck is in 60 seconds")
  end
  
  DEBUG(3,"nextTimeCheck = " .. GC.nextTimeCheck .. " lastTimeCheck = " .. GC.lastCheckTime .. " endofDay = " .. GC.endofDay)
  
   if ((GC.nextTimeCheck > GC.endofDay) and (GC.lastCheckTime < GC.endofDay)) then
    -- force a check at midnight each day if there was no check at midnight
    GC.nextTimeCheck = GC.endofDay + 60 -- one minute after midnight
    DEBUG(3, "nextTimeCheck is a minute past midnight = " .. os.date("%Y-%m-%d at %H:%M:%S", GC.nextTimeCheck))
  end
  return GC.nextTimeCheck
end

local function nonotifySent(i)
  if #GC.notifyLog == 0 then return true end -- nothing ever sent
  local log = {}
  local event = GC.Events[i]
  for j = 1, #GC.notifyLog do
    log = GC.notifyLog[j]
    if (log.title == event.title) and (log.stime == event.stime) and (log.etime == event.etime) then -- a notification has been sent
      DEBUG(3,"Notification already set for event: " .. log.title)
      return false
    end
  end
  return true
end

local function setnotifyLog(i) -- put an entry in if notification scheduled for an event
local log = {}
local event = GC.Events[i]
log.title = event.title
log.stime = event.stime
log.etime = event.etime
tableInsertSorted(GC.notifyLog, log)
end

local function cleannotifyLog() -- get rid of old entries in GC.notifyLog
  if #GC.notifyLog == 0 then return end -- nothing to do
  local log = {}
  for i = #GC.notifyLog, 1, -1 do
    log = GC.notifyLog[i]
    if (log.etime < GC.utc) then -- clean out events that finished before now
      DEBUG(3,"Event: " .. log.title .. " removed from notify log")
      table.remove (GC.notifyLog,i)
    end
  end
  return
end

local function notifyList()
  DEBUG(3,"local function: notifyList")
  local startCheck = 0
  local endCheck = 0
  local i = 0
  local param = ""
  local startOffset = 0
  local endOffset = 0
local event = {}
GC.now = os.time() -- update because we will be making time sensitive calls
GC.utc = GC.now - GC.timeZone
DEBUG(3,"Setting up notifications for: " .. #GC.notify .. " event(s)")
for index = 1 , #GC.notify do
  i = GC.notify[index]

  if nonotifySent(i) then
    event = GC.Events[i]
    -- send the start notification
    startOffset = event.stime + GC.timeZone - GC.now -- done in local time
    DEBUG(3,"Notify startOffset is: " .. tostring(startOffset))
    if (startOffset >= -15) then -- allow 15 second into the past
      if (startOffset < 0) then startOffset = 0 end -- prevent negative luup.call_timer
        startCheck = startOffset + (index * 5) -- stagger by 5 seconds
        startCheck = tostring(startCheck)
        param = tostring(i) .. ",Start"
        DEBUG(3,"Calling notifySend with start delay: " .. startCheck .." on event " .. i)
        local _ = luup.call_timer("notifySend",1,startCheck,"",param)
      end
      -- send the end notification
      endOffset = event.etime + GC.timeZone - GC.now -- done in local time
      DEBUG(3,"Notify endOffset is: " .. tostring(endOffset))
      if (endOffset >= -15) then -- allow 15 seconds into the past
        if (endOffset < 60 ) then endOffset = 60 end -- must be at least 1 minute
          endCheck = endOffset + (index * 5) -- stagger by 5 seconds
          endCheck = tostring(endCheck)
          param = tostring(i) .. ",End"
          DEBUG(3,"Calling notifySend with end delay: " .. endCheck .." on event " .. i)
          local _ = luup.call_timer("notifySend",1,endCheck,"",param)
        end
        setnotifyLog(i)
      end
    end
    cleannotifyLog()
  end

  function notify(index)
  GC.notify = {}
  local event = GC.Events[index]
  local notifyNum = 1
  GC.notify[notifyNum] = index
  local startTime = event.stime
  local endTime = event.etime
  for i = (index +1) , #GC.Events do
    event = GC.Events[i]
    if (event.stime >= startTime) and (event.stime < endTime) then
      -- start time inside this event
      notifyNum = notifyNum + 1
      DEBUG(3, "Overlap event: " .. tostring(i) .. " - Notification number: " .. tostring(notifyNum))
      GC.notify[notifyNum] = i
    else
      DEBUG(3, "Not an overlap event: " .. tostring(i))
      break
    end
  end
  local _ = notifyList()
end

function notifySend(param)
  DEBUG(3,"local function: notifySend")
  local index,kind = param:match("([^,]+),([^,]+)")
  index = tonumber(index)
  local event = GC.Events[index]
  DEBUG(3, "notifySend called with: " .. index .. " , " .. kind)
  local notify = luup.variable_get(GCAL_SID, "gc_notify", lul_device)
  if (notify == "1") then
    local _ = notifyOff(index)
  end
  luup.variable_set(GCAL_SID, "gc_notifyName",event.title, lul_device)
  luup.variable_set(GCAL_SID, "gc_notifyValue",event.value, lul_device)
  luup.variable_set(GCAL_SID, "gc_notifyType",kind, lul_device)
  luup.variable_set(GCAL_SID, "gc_notify","1", lul_device)
  DEBUG(3,"**** Notify ON **** Event " .. index)
  luup.call_timer("notifyOff",1,15,"",index)
end

function notifyOff(eventnum)
  DEBUG(3,"local function: notifyOff Event " .. eventnum)
  luup.variable_set(GCAL_SID, "gc_notifyName","", lul_device)
  luup.variable_set(GCAL_SID, "gc_notifyValue","", lul_device)
  luup.variable_set(GCAL_SID, "gc_notifyType","", lul_device)
  luup.variable_set(GCAL_SID, "gc_notify","0", lul_device)
  DEBUG(3,"**** Notify OFF **** Event " .. eventnum)
end

-- ********************************************************************
-- This is the main routine that gets calendar events
-- ********************************************************************

local function checkGCal() -- this is the main sequence
  DEBUG(3, "local function: checkGCal")
  GC.Status = "checkGCal"

  -- get the start and stop window for requesting events from google
  local startmin, startmax = getStartMinMax(GC.StartDelta,GC.EndDelta)
  local events = nil
  local action = ""

  -- get the calendar information
  if GCV.gCal == "true" then
    events,action = requestCalendar(startmin, startmax)
  else
    events,action = requestiCalendar(startmin, startmax)
  end
  GC.Status = "checkGCal" -- successful return from calendar request
  -- update time since there may have been a response delay
  GC.now = os.time()
  GC.utc = GC.now - GC.timeZone
  DEBUG(3, "requestCalendar reported: " .. tostring(action))
  if action == "stop" then
    return nil
  end

  if (action == "retry") then -- no data from calendar could be network error
    if GC.access_error > 2 then -- continue with the last set of data
      action = "use-last-data"
    else
      GC.access_error = GC.access_error + 1
      luup.variable_set(GCAL_SID, "gc_NextEventTime", "Retry number " .. tostring(GC.access_error), lul_device)
      GC.nextTimeCheck = GC.now + 30 -- check again in 30 seconds
      return setNextTimeCheck()
    end
  end

  GC.access_error = 0

  if (events == "No Events") then -- request succeeded but no events were found
    if (GC.trippedStatus == "1") then -- plugin was tripped and no events today
      local _ = setTrippedOff(GC.trippedStatus)
    end
    luup.variable_set(GCAL_SID, "gc_jsonEvents","[]", lul_device)
    luup.variable_set(GCAL_SID, "gc_jsonActiveEvents","[]", lul_device)
    luup.variable_set(GCAL_SID, "gc_ActiveEvents","", lul_device)
    GC.nextTimeCheck = GC.now + GC.Interval
    return setNextTimeCheck()
  end

  if (action == "use-last-data") then
    GC.Disconnected = "**  "
    GC.Events = GCV.Events -- replace with the stored version
    DEBUG(3,"****************** In Offline Mode ******************")
  else -- get all the events in the current calendar window
    GC.Disconnected = ""
    local _ = getEvents(events, GC.Keyword, GC.StartDelta, GC.EndDelta, GC.ignoreAllDayEvent, GC.ignoreKeyword, GC.exactKeyword)
    GCV.Events = GC.Events
    local _ = setVariables()
  end

  -- save events, both calendar and active
  local _ = saveEvents()

  -- identify the active or next event
  local numActiveEvent = nextEvent()
  
  if (tonumber(numActiveEvent) < 1) then -- there were no active events so make sure any previous are off
    DEBUG(3,"Cancel any active event")
    GC.trippedStatus = setTrippedOff(GC.trippedStatus)
  else
    DEBUG(3,"Trip event: " .. tonumber(numActiveEvent) .. " with status: " .. GC.trippedStatus)
    GC.trippedStatus = setTripped(numActiveEvent, GC.trippedStatus)
    -- save it as the top event in the next cycle
    -- GC.midnightEvent = {}
    local nextEvent = GC.Events[numActiveEvent]
    DEBUG(3, "Active event is number " .. tonumber(numActiveEvent) .. " Event name = " .. nextEvent.title)
  end

  return setNextTimeCheck()
end

-- ********************************************************************
-- Gets the Calendar ID and format it for use in the API call and for display
-- ********************************************************************
function parseCalendarID(newID)
  DEBUG(3,"local function: parseCalendar")
  DEBUG(3, "Calendar Input: " .. newID)
  GC.CalendarID = "Not Set"
  GCV.CalendarID = "Not Set"
  GCV.addCalendar = "false"
  GCV.gCal = "true"
  local errormsg = ""

  if newID == nil or newID == "" or newID == "Not Set" then
    errormsg = "No CalendarID"
    return false, errormsg
  end

  local newIDupper = string.upper(newID)
  if string.find(newIDupper,"ICAL") or string.find(newIDupper,"ICLOUD") or string.find(newIDupper,"%.ICS") or string.find(newIDupper,"/ICS")then -- treat as a public ical
    GC.CalendarID = newID
    GCV.CalendarID = newID
    GCV.gCal = "false"
  else -- a regular google calendar
    -- there are several forms of the calendar url so we try to make a good one
    if string.find(newID,'(.-)src="http') then
      DEBUG(3,'Eliminate anything before src="http"') -- will also get https
      newID = string.gsub(newID,'(.-)src="http',"")
      newID = "http" .. newID
      DEBUG(3,newID)
    end

    DEBUG(3, 'Eliminate anything after &ctz=')
    newID = string.gsub(newID,'%&ctz=(.*)',"")

    if ((not string.find(newID,'google.com')) and (not string.find(newID,'gmail.com'))) then
      errormsg = 'Invalid Calendar url Format'
      DEBUG(1, errormsg)
      DEBUG(3,newID)
      GC.CalendarID = "Not Set"
      GCV.CalendarID = "Not Set"
      return false, errormsg
    end

    GCV.CalendarID = newID
    -- note GC.CalendarID is a subset of GCV.CalendarID
    GC.CalendarID = newID

    DEBUG(3, 'Eliminate anything before &src or ?src')
    GC.CalendarID = string.gsub(GC.CalendarID,'(.*)%?src=',"")
    GC.CalendarID = string.gsub(GC.CalendarID,'(.*)%%26src=',"")

    if string.find(GC.CalendarID,"%%40import.calendar.google.com") then --cannot add events
      GCV.addCalendar = "false"
    else
      GCV.addCalendar = "true"
    end
    GC.CalendarID = url_format(GC.CalendarID)
    DEBUG(3, "After recoding: " .. GC.CalendarID)
  end

  DEBUG(3,"Calendar ID is: " .. GC.CalendarID)
  return true, errormsg
end

-- ********************************************************************
-- This is the main program loop - it repeats by calling itself
-- (non-recursive) using the luup.call_timer at interval determined
-- from either event start / finish times or a maximum interval
-- set by gc_Interval
-- ********************************************************************

function GCalMain(command)
  DEBUG(1,"Running Version " .. GCAL_VERSION)
  DEBUG(3,"local function: GCalMain called with " .. command )
  --get the value of all variables since some may have been changed by the user
  luup.variable_set(GCAL_SID, "gc_NextEventTime","Checking variables", lul_device)
  local _ = setupVariables()
  luup.variable_set(GCAL_SID, "gc_NextEventTime","Variable check complete", lul_device)

  if (GC.Status ~= "Idle") then -- regulates what function can be running / not running)
    GC.processLockCount = GC.processLockCount +1
    luup.variable_set(GCAL_SID, "gc_NextEventTime","Busy Process: " .. GC.processLockCount .. " " .. GC.Status , lul_device)
    if (GC.processLockCount > 3) then
      -- assume something bad and restart the plugin
      GC.processLockCount = 0
      GC.Status = "Idle"
      luup.call_timer("GCalStartup",1,1,"","")
      return
    end
    luup.call_timer("GCalMain",1,30,"","from GCalMain Retry") -- try again in 30 seconds
    return
  else
    GC.processLockCount = 0
    luup.variable_set(GCAL_SID, "gc_NextEvent","Connecting  ..." , lul_device)
    luup.variable_set(GCAL_SID, "gc_NextEventTime","" , lul_device)
  end

  if (command ~= "fromAddEvent") then
    -- check to see if any Add Calendar Events need to be processed
    if (#GC.CalendarEvents ~= 0) then -- there are unprocessed adds
      GC.allowCalendarUpdate = false
      local _ = createNewCalendarEvents("fromGCalmain")
    end
  end

  -- if the plugin is not armed - stop
  local Armed = luup.variable_get(SECURITY_SID, "Armed", lul_device)
  DEBUG(3," ************** ARMED STATUS : " .. tostring(Armed) .. " *****************")
  if (Armed == "0") then
    local _ = setTrippedOff("1")
    luup.variable_set(GCAL_SID, "gc_NextEvent","In Bypass Mode" , lul_device)
    if GCV.addCalendar == "true" then
      luup.variable_set(GCAL_SID, "gc_NextEventTime","Can Add events to calendar" , lul_device)
    else
      luup.variable_set(GCAL_SID, "gc_NextEventTime","" , lul_device)
    end
    return
  end

  -- update time
  GC.now = os.time()
  GC.utc = GC.now - GC.timeZone

  GC.Status = "GCalMain" -- officially busy
  local modulerequest = moduleRequire(true)
  -- Check the calendar for any updates
  local nextCheckTime = checkGCal() -- returns time for next check in local time

  if (nextCheckTime == nil) then
    DEBUG(1,"A fatal error trying to access the calendar")
    luup.variable_set(GCAL_SID, "gc_NextEventTime","Fatal Calendar Error" , lul_device)
    GC.Status = "Idle"
    return nil
  end

  nextCheckTime = tonumber(nextCheckTime)
  -- update time: http requests can take some time
  GC.now = os.time()
  GC.utc = GC.now - GC.timeZone

  local lastCheck, nextCheck
  local delay = nextCheckTime - GC.now
  if (delay < 0) then
    delay = 60
    nextCheckTime = GC.now +60
    DEBUG(3,"Reset check time because delay was negative")
  end
  
  lastCheck = os.date("%Y-%m-%dT%H:%M:%S", GC.lastCheckTime) -- last time we were scheduled
  nextCheck = os.date("%Y-%m-%dT%H:%M:%S", nextCheckTime)
  GC.nextCheckutc = strLocaltostrUTC(nextCheck)
  GCV.NextCheck = nextCheck
  GC.allowEventAdd = true -- allow events to be added to calendar
  GC.retrip = GC.retripTemp -- reset GC.retrip after calendar event update
  GC.Status = "Idle" -- done
  if modulerequest then moduleRequire(false) end
  
  -- And away we go again (or not)
  DEBUG(3,"Next check is " .. nextCheck .. " and last scheduled check was at " .. lastCheck)

  if (math.abs(nextCheckTime - GC.lastCheckTime) < 30 ) then
    -- no need to call GCalMain again if within 30 sec of last check (1/2 x 1 min resolution)
    local _ = setVariables()
    DEBUG(1,"Next check already scheduled for " .. lastCheck)
  else
    -- Schedule the next check
    GCV.LastCheck = os.date("%Y-%m-%dT%H:%M:%S", nextCheckTime)
    GC.lastCheckTime = nextCheckTime
    local _ = setVariables()
    local msg = "fromGCalMain with delay = " .. delay
    luup.call_timer("GCalMain",1,delay,"",msg)
    DEBUG(1,"Schedule next check for " .. delay .. " sec at " .. nextCheck)
  end
end

--***************************************************************************************
-- local functions for adding events to calendar
-- **************************************************************************************
local function addEventToCalendar(startTime, endTime, title, description)
  DEBUG(2,"Adding Event to Google Calendar")

  local calendar = "https://www.googleapis.com/calendar/v3/calendars/".. GC.CalendarID .. "/events?" .. "access_token=" .. GC.access_token
  DEBUG(3,"url = " ..calendar)

  local post = '{"end": {"dateTime":"'
  post = post .. endTime
  post = post .. '"},"start": {"dateTime":"'
  post = post .. startTime
  post = post .. '"},"summary":"'
  post = post .. title
  if (description ~= nil) then
    post = post .. '","description":"'
    post = post .. description
  end
  post = post .. '"}'

  DEBUG(3,"Add Event payload: " .. post)

  local _, code,_,status = https.request
  {
    url = calendar,
    method = "POST",
    headers =
    {
      ["Content-Type"] = "application/json",
      ["Content-Length"] = tostring(#post)
      },
      source = ltn12.source.string(post)
    }

    status = status or 'nil'
    if (code == nil) then -- this is a fatal error
      luup.variable_set(GCAL_SID, "gc_NextEvent","http(s) POST returned nil", lul_device)
      DEBUG(1,"addEvent http(s) POST error code was nil and status was " .. status)
      return false
    end

    if (code ~= 200) then -- anything other than 200 is an error
      local errorMessage = ""
      if (code == 404) then
        errorMessage = "Check Credentials: " .. code
      else
        errorMessage = "Http error code: " .. code
      end
      DEBUG(3,errorMessage)
      luup.variable_set(GCAL_SID, "gc_NextEvent",errorMessage , lul_device)
      luup.variable_set(GCAL_SID, "gc_NextEventTime","", lul_device)
      return false
    end

    return true
  end

  function createNewCalendarEvents(command)
    DEBUG(3,"local function: createNewCalendarEvents")
    if (GC.Status ~= "Idle") then -- regulates what function can be running / not running)
      -- try again in 60 seconds
      luup.call_timer("createNewCalendarEvents", 1,60,"",command)
      return
    end
    GC.allowEventAdd = false -- do not accept new events until finished processing

    if (#GC.CalendarEvents == 0) then -- nothing to do mainly for loop checks
      GC.allowEventAdd = true -- allow events to be added to calendar
      GC.allowCalendarUpdate = true -- allow calendar update
      return true
    end

    GC.Status = "createNewCalendarEvents" -- this function is running
    local modulerequest = moduleRequire(true)
    https.method = "POST"

    local newerEvent = false
    local lastCheckutc = GC.nextCheckutc

    -- make sure we have an access token
    DEBUG(3,"Checking for access-token")
    local msg = ""
    GC.access_token, msg = get_access_token ()
    if not GC.access_token and (not GCV.CredentialCheck) then
      DEBUG(1, msg)
      luup.variable_set(GCAL_SID, "gc_NextEventTime", msg, lul_device)
      return false
    end

    --iterate through the even list
    for j = #GC.CalendarEvents,1, -1 do -- process in revererse order so we have the right "i"
    local eventList =json.decode(GC.CalendarEvents[j])
    local numberEvents = table.getn(eventList)
    local eventStart, eventEnd, eventName, eventDescription
    local success
    local AllEventsAdded = true
    for i = 1,numberEvents do
      eventStart = eventList[i].eventStart
      if (not string.find(eventStart,'Z')) then
        eventStart = strLocaltostrUTC(eventStart)
      end
      eventEnd = eventList[i].eventEnd
      if (not string.find(eventEnd, 'Z')) then
        eventEnd = strLocaltostrUTC(eventEnd)
      end
      eventName = eventList[i].eventName
      eventDescription = eventList[i].eventDescription

      success = addEventToCalendar(eventStart, eventEnd, eventName,eventDescription)
      if success then
        DEBUG(1, "Added event to Calendar")
        if GC.nextCheckutc > eventStart then -- if there is an event newer than already scheduled
          GC.nextCheckutc = eventStart
          DEBUG(3, "Newer Event - Check Calendar Sooner")
          newerEvent = true
        end
      else -- abort the attempts as something bad has happened
        DEBUG(1, "Failed to add event to Calendar")
        AllEventsAdded = false
        break
      end
      end -- inner loop i
      if AllEventsAdded then
        table.remove(GC.CalendarEvents, j)
        DEBUG(3,"Removed " .. tostring(j) .. " Remaining " .. tostring(#GC.CalendarEvents))
      else
        GC.Status = "Idle" -- done
        https.method = "GET" -- sat back to the default
        return false
      end
      end -- outer loop j

      https.method = "GET" -- set back to the default
      -- Check to see if we need to refresh the calendar
      local check = false
      if newerEvent then
        local lastTime = strToTime(lastCheckutc)
        local nextTime = strToTime(GC.nextCheckutc)
        if (lastTime - nextTime) > 60 then
          DEBUG(3,"Added event newer by " .. tostring(lastTime - nextTime) .. " sec")
          check = true
        else
          DEBUG(3,"No Calendar Update Necesary")
        end
      end

      if ((check) and (command ~= "fromGCalMain")) then
        GC.retripTemp = GC.retrip -- save the current value
        GC.retrip = "false" -- prevent a retrip of events because of an update made by the calendar
        luup.call_timer("GCalMain",1,2,"","fromAddEvent")
        -- luup.call_timer("",1,10,"","fromAddEvent")
      end

      GC.allowEventAdd = true -- allow events to be added to calendar
      GC.allowCalendarUpdate = true -- allow calendar update
      GC.Status = "Idle" -- done
      if modulerequest then moduleRequire(false) end
      return true
    end

    -- ****************************************************************
    -- startup and related local functions are all here
    -- ****************************************************************

    local function getTimezone()
      DEBUG(3,"local function: getTimezone")
      local now = os.time()
      local date = os.date("!*t", now)
      date.isdst = os.date("*t").isdst
      local tz = (now - os.time(date))
      local tzhr = math.floor(tz/3600) -- whole hour
      local tzmin = math.floor(tz%3600/60 + 0.5) -- nearest integer higher
      if (tzhr < 0) then
        tzmin = -tzmin
      end
      DEBUG(3,"Timezone is " ..tzhr .. " hrs and " .. tzmin .. " min")
      return tz, tzhr, tzmin
    end

    function copyLog()
      local device = tostring(luup.device)
      DEBUG(1,"*****************")
      DEBUG(1,"Creating " .. device .. "-GCal3.log")
      DEBUG(1,"*****************")
      luup.variable_set(GCAL_SID, "gc_NextEvent","Creating Log File" , lul_device)
      luup.variable_set(GCAL_SID, "gc_NextEventTime","" , lul_device)
      local errormsg = ""
      LOGFILECOPY = BASEPATH .. device .. "-GCal3.log"
      -- LOGFILECOMPRESSED = BASEPATH .. device .. "-GCal3.log.lzo"

      -- get rid of old device log file
      local command = "/bin/rm -f " .. LOGFILECOPY
      local result = osExecute(command)

      -- flush the write buffer
      command = "sync"
      result = osExecute(command)
      -- get the log entries for this device
      local pattern = "device: " .. device
      pattern = '"' .. pattern .. '"'
      command = "grep " .. pattern .. " " .. LOGFILE .. " > " .. LOGFILECOPY
      result = osExecute(command)
      if (result ~= 0) then
        errormsg ="Failed to create: " .. LOGFILECOPY .. " : " ..  tostring(result)
        luup.variable_set(GCAL_SID, "gc_NextEvent","Could not Extract the Log File" , lul_device)
        DEBUG(1, errormsg)
      else
        luup.variable_set(GCAL_SID, "gc_NextEvent","Log File Created" , lul_device) 
      end
      luup.call_timer("GCalMain",1,1,"","fromcopyLog")
      return
    end


    local function removefile(file)
      local errormsg = ""
      local result = osExecute("/bin/ls " .. file)
      if (result == 0) then -- if the file(s) exist then delete
        result = osExecute("bin/rm -f " .. file)
        if (result ~= 0) then
          errormsg ="Fatal Error could not delete " .. file
          DEBUG(1, errormsg)
        else
          errormsg ="Deleted file " .. file
          DEBUG(1, errormsg)
          return true, errormsg
        end
      end
      return false, errormsg
    end
    
       -- anything that requires json module must go after this setup step
       -- check to see if we have a suitable module
      local function haveModule(Module)
          local test = require(Module)
          if type(test) ~= "table" then
            DEBUG(1,"No Module: " .. Module)
            return false
          end
          package.loaded.test = nil
          return true
        end

    local function setupEnvironment()
	  -- force to the default json file
	  luup.attr_set("device_json", "D_GCal3.json", lul_device)
      
	  local restart = false
      local errormsg = ""
      -- make sure we have a plugin specific directory
      local result = osExecute("/bin/ls " .. PLUGINPATH)
      if (result ~= 0) then -- if the directory does not exist, it gets created
        result = osExecute("/bin/mkdir " .. PLUGINPATH)
        if (result ~= 0) then
          errormsg = "Fatal Error could not create plugin directory"
          DEBUG(1, errormsg)
          restart = true
        end
      end

      local Distro = ""
      if osExecute("cat /etc/*release | grep -i OpenWrt") == 0 then
        Distro = "OPENWRT"
      elseif osExecute("cat /etc/*release | grep -i Debian") == 0 then
        Distro = "DEBIAN"
      elseif osExecute("cat /etc/*release | grep -i Suse") == 0 then
        Distro = "SUSE"
      elseif osExecute("cat /etc/*release | grep -i Ubuntu") == 0 then
        Distro = "UBUNTU"
      elseif osExecute("cat /etc/*release | grep -i Raspbian") == 0 then
        Distro = "RASPBIAN"
      else
        Distro = "Unknown"
      end
      
      DEBUG(1,"Distro is: " .. Distro)
      if Distro ~= "OPENWRT" and Distro ~= "OPENWRT" and Distro ~= "DEBIAN" then
        luup.variable_set(GCAL_SID, "gc_NextEvent",Distro .. " is not supported" , lul_device)
      end

        -- check to see if openssl is on the system
        local stdout = io.popen("openssl version")
        local ver = stdout:read("*a")
        stdout:close()
        local _,_,version = string.find(ver,"(%d+.%d+.%d+)")
        version = version or false
        DEBUG(1, "Existing openssl version is: " .. tostring(version))
        if not version then
          DEBUG(1,"Installing openssl")
          -- install the default version for the vera model
          local result = nil
          if Distro == "OPENWRT" then
            result = osExecute ("/bin/opkg update && opkg install openssl-util")
          elseif Distro == "RASPBIAN" or Distro == "DEBIAN" then
            result = osExecute ("sudo apt-get update && sudo apt-get install openssl")
          else
            result = 0
          end
          if (result ~= 0) then
            errormsg = "Fatal error could not install openssl"
            DEBUG(1, errormsg)
            if (result == 100) then
              errormsg = "Do you have root permission ?"
              DEBUG(1, errormsg)
            end
            restart = true
          end
        end

        -- result = osExecute("ls " .. JSON_MODULE) -- check to see if the file is installed
        result= haveModule(JSON_MODULE)
        if (not result) then -- get the file
          DEBUG(3, "Getting " .. JSON_MODULE)
          local http = require "socket.http"
          --local https = require "ssl.https"
          local ltn12 = require "ltn12"
          --local lfs = require "lfs"  
          _, result = http.request{url = "http://dkolf.de/src/dkjson-lua.fsl/raw/dkjson.lua?name=16cbc26080996d9da827df42cb0844a25518eeb3",sink = ltn12.sink.file(io.open("dkjson.lua", "wb"))}
          package.loaded.http = nil
          --package.loaded.https = nil
          package.loaded.ltn12 = nil
          --package.loaded.lfs = nil
          if (result ~= 200) then
            errormsg = "Fatal Error could not get " .. JSON_MODULE
            DEBUG(1, errormsg)
            restart = true
          end
        end 
        

      -- need to initialize the GCV Variables
      result = getVariables()
      if (not result) then
        result = osExecute("touch " .. VARIABLES_FILE)
        if (result ~= 0) then
          errormsg = "Fatal Error could not create variables file"
          DEBUG(1, errormsg)
          restart = true
        end 
      end 
              
	  -- save any changes to GCV that happened as part of setup
      local _ = setVariables() -- need to update GCV
      
	  return (not restart), errormsg -- negated for syntax reasons
    end

    function GCalStartup()
      luup.set_failure(false, lul_device) -- just to clear any prior issues
      PRE = PRE .. tostring(luup.device) -- debug message prefix
      VARIABLES_FILE = PLUGINPATH .. tostring(luup.device) .. "GCalVariables"
      DEBUG(1,"local function: GCalStartup")
      luup.variable_set(GCAL_SID, "gc_NextEvent","Initial Startup" , lul_device)
      luup.variable_set(GCAL_SID, "gc_NextEventTime","", lul_device)

      -- Setup paths and cleanup old files etc etc
      local success, errormsg = setupEnvironment()
      
      if not success then
        local _ = copyLog()
        luup.variable_set(GCAL_SID, "gc_NextEvent",errormsg , lul_device)
        luup.variable_set(GCAL_SID, "gc_NextEventTime","Reboot Required" , lul_device)
        -- luup.set_failure(true, lul_device)
        return true
        -- return false -- just exit and stop
      end

      -- Initialize all the plugin variables
      local _ = setupVariables()

      -- Get the Time Zone info
      GC.timeZone, GC.timeZonehr, GC.timeZonemin = getTimezone()

      -- Check to make sure there is a Calendar ID else stop the plugin
      local ok = true
      DEBUG(1,"Checking CalendarID: " .. tostring(GCV.CalendarID))
      if GCV.CalendarID == "Not Set" then
        luup.variable_set(GCAL_SID, "gc_NextEvent","CalendarID not set" , lul_device)
        DEBUG(1,"CalendarID not set")
        ok = false
      else
        luup.variable_set(GCAL_SID, "gc_NextEvent","CalendarID is set" , lul_device)
      end

      -- make sure we have credentials file
      DEBUG(1,"Checking for Credential file: " .. tostring(GCV.CredentialFile))
      local check, msg = checkforcredentials()
      if not check then
        DEBUG(1, msg)
        luup.variable_set(GCAL_SID, "gc_NextEventTime", msg, lul_device)
        ok = false
      else
        luup.variable_set(GCAL_SID, "gc_NextEventTime", msg , lul_device)
      end

      if not ok then return true end -- stop and wait

        -- make sure we have an access token
        DEBUG(1,"Checking for access-token")
        GC.access_token, msg = get_access_token ()
        DEBUG(3,"GC.access_token is: " .. tostring(GC.access_token))
        DEBUG(3,"GCV.CredentialCheck is " ..tostring(GCV.CredentialCheck))
        if (not GC.access_token) and (not GCV.CredentialCheck) then
          -- error only if credential have not been previously checked and failed this time
          DEBUG(1, msg)
          luup.variable_set(GCAL_SID, "gc_NextEventTime", msg, lul_device)
          ok = false
        else
          luup.variable_set(GCAL_SID, "gc_NextEventTime", msg , lul_device)
        end

        if not ok then return true end -- stop and wait
          -- warp speed Mr. Sulu
          parseCalendarID(GCV.CalendarID)
          DEBUG(1,"Running Plugin ...")
          luup.call_timer("GCalMain",1,1,"","fromGCalStartup")
          return true
        end
