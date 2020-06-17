require 'config'
local match = string.match
local ngxmatch=ngx.re.match
local unescape=ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function (options) return options == "on" and true or false end
logpath = logdir 
rulepath = RulePath
UrlDeny = optionIsOn(UrlDeny)
PostCheck = optionIsOn(PostMatch)
CookieCheck = optionIsOn(CookieMatch)
WhiteCheck = optionIsOn(whiteModule)
WhiteHostCheck = optionIsOn(whiteHostModule)
PathInfoFix = optionIsOn(PathInfoFix)
attacklog = optionIsOn(attacklog)
CCDeny = optionIsOn(CCDeny)
Redirect=optionIsOn(Redirect)
function getClientIp()
    local headers = ngx.req.get_headers()
    local reip = headers["X-REAL-IP"] or headers["X_FORWARDED_FOR"] or ngx.var.remote_addr or "0.0.0.0"
    if reip == nil then
        reip = "unknown"
    end
    return reip
end
function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end
function log(method,url,data,ruletag)
    if attacklog then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername=ngx.var.server_name
        local time=ngx.localtime()
        if ua  then
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
        else
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
        end
        local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        write(filename,line)
    end
end

function ipToDecimal(ckip)
    local n = 4
    local decimalNum = 0
    local pos = 0
    for s, e in function() return string.find(ckip, '.', pos, true) end do
        n = n - 1
        decimalNum = decimalNum + string.sub(ckip, pos, s-1) * (256 ^ n)
        pos = e + 1
        if n == 1 then decimalNum = decimalNum + string.sub(ckip, pos, string.len(ckip)) end
    end
    return decimalNum
end
------------------------------------规则读取函数-------------------------------------------------------------------
function read_rule(var)
    file = io.open(rulepath..'/'..var,"r")
    if file==nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

urlrules=read_rule('url')
argsrules=read_rule('args')
uarules=read_rule('user-agent')
whiteuarules=read_rule('white-user-agent')
wturlrules=read_rule('whiteurl')
postrules=read_rule('post')
ckrules=read_rule('cookie')

function say_html(v)
    if not v then
        if Redirect then
            ngx.header.content_type = "text/html; charset=UTF-8"
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.say(html)
            ngx.exit(ngx.status)
        end
     else
         ngx.header.content_type = "text/html; charset=UTF-8"
         ngx.status = ngx.HTTP_FORBIDDEN
         ngx.say(say2_html(v))
         ngx.exit(ngx.status)
     end
end

function say2_html(var)
    return var
end

function whiteurl()
    if WhiteCheck then
        if wturlrules ~=nil then
            for _,rule in pairs(wturlrules) do
                if ngxmatch(ngx.var.request_uri,rule,"isjo") then
                    return true
                 end
            end
        end
    end
    return false
end

function whitehost()
	if WhiteHostCheck then
	    local items = Set(hostWhiteList)
	    for host in pairs(items) do
	    	if ngxmatch(ngx.var.host, host, "isjo") then
				log('POST',ngx.var.request_uri,"-","white host".. host)
	    		return true
	    	end
	    end
	end
	return false
end

function args()
    for _,rule in pairs(argsrules) do
            if ngxmatch(unescape(ngx.var.request_uri),rule,"isjo") then
                    log('test',ngx.var.request_uri,"-",rule)
                    say_html()
                    return true
            end
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val)=='table' then
                 local t={}
                 for k,v in pairs(val) do
                    if v == true then
                        v=""
                    end
                    table.insert(t,v)
                end
                data=table.concat(t, " ")
            else
                data=val
            end
            if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data),rule,"isjo") then
                log('GET',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function url()
    if UrlDeny then
        for _,rule in pairs(urlrules) do
            if rule ~="" and ngxmatch(ngx.var.request_uri,rule,"isjo") then
                log('GET',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(uarules) do
            if rule ~="" and ngxmatch(ua,rule,"isjo") then
                log('UA',ngx.var.request_uri,"-",rule)
                say_html()
            return true
            end
        end
    end
    return false
end

function body(data)
    for _,rule in pairs(postrules) do
        if rule ~="" and data~="" and ngxmatch(unescape(data),rule,"isjo") then
            log('POST',ngx.var.request_uri,data,rule)
            say_html()
            return true
        end
    end
    return false
end

function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _,rule in pairs(ckrules) do
            if rule ~="" and ngxmatch(ck,rule,"isjo") then
                log('Cookie',ngx.var.request_uri,"-",rule)
                say_html()
            return true
            end
        end
    end
    return false
end

function denycc()
    if CCDeny then
        local uri=ngx.var.uri
        CCcount=tonumber(string.match(CCrate,'(.*)/'))
        CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        local token = getClientIp()..uri
        local limit = ngx.shared.limit
        local req,_=limit:get(token)
        if req then
            if req > CCcount then
                 say_html("频繁访问限制，请稍后再试")
                return true
            else
                 limit:incr(token,1)
            end
        else
            limit:set(token,1,CCseconds)
        end
    end
    return false
end

function whiteua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(whiteuarules) do
            if rule ~="" and ngxmatch(ua,rule,"isjo") then
                return true
            end
        end
    end
    return false
end

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end

--数字转换为八位二进制
function byte2bin(n)
local t = {}
  for i=7,0,-1 do
    t[#t+1] = math.floor(n / 2^i)
    n = n % 2^i
  end
  return table.concat(t)
end

--拼接IP每部分的二进制，返回IP完整的二进制
function IP2bin(ip_s)
    local _,_,IP_p1,IP_p2,IP_p3,IP_p4=string.find(ip_s, "(%d+).(%d+).(%d+).(%d+)")
    ip_str = byte2bin(IP_p1)..byte2bin(IP_p2)..byte2bin(IP_p3)..byte2bin(IP_p4)
    return ip_str
end

--判断二进制IP是否在属于某网段
function IpBelongToNetwork(bin_ip,bin_network,mask)
    if (string.sub(bin_ip,1,mask) == string.sub(bin_network,1,mask)) then
        return true
    else
        return false
    end
end

--字符串分割函数
function split(str,delimiter)
    local dLen = string.len(delimiter)
    local newDeli = ''
    for i=1,dLen,1 do
        newDeli = newDeli .. "["..string.sub(delimiter,i,i).."]"
    end
    local locaStart,locaEnd = string.find(str,newDeli)
    local arr = {}
    local n = 1
    while locaStart ~= nil
    do
        if locaStart>0 then
            arr[n] = string.sub(str,1,locaStart-1)
            n = n + 1
        end
        str = string.sub(str,locaEnd+1,string.len(str))
        locaStart,locaEnd = string.find(str,newDeli)
    end
    if str ~= nil then
        arr[n] = str
    end
    return arr
end   


function blockip()
    if next(ipBlocklist) ~= nil then
        local cIP = getClientIp()
        local numIP = 0
        if cIP ~= "unknown" then
            numIP = tonumber(ipToDecimal(cIP))
        end
        for _,ip in pairs(ipBlocklist) do
            local s, e = string.find(ip, '-', 0, true)
            local x, j = string.find(ip, '/', 0, true)
            --IP字符串中不存在"-"、"/"等划分网段标识
            if s == nil and x == nil and cIP == ip then
                ngx.exit(403)
                return true
            --范围划分法
            elseif s ~= nil then
                sIP = tonumber(ipToDecimal(string.sub(ip, 0, s - 1)))
                eIP = tonumber(ipToDecimal(string.sub(ip, e + 1, string.len(ip))))
                if numIP >= sIP and numIP <= eIP then
                    ngx.exit(403)
                    return true
                end
            --掩码划分法
            elseif x ~= nil then
                local ip_list = split(ip, "/")
                if IpBelongToNetwork(IP2bin(cIP),IP2bin(ip_list[1]),ip_list[2]) then
                    ngx.exit(403)
                    return true
                end 
            end
        end
    end
        return false
end

function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext=string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext,rule,"isjo") then
	        log('POST',ngx.var.request_uri,"-","file attack with ext "..ext)
            say_html()
            end
        end
    end
    return false
end
function Set (list)
  local set = {}
  for _, l in ipairs(list) do set[l] = true end
  return set
end

function whiteip()
    if next(ipWhitelist) ~= nil then
        local cIP = getClientIp()
        local numIP = 0
        if cIP ~= "unknown" then 
            numIP = tonumber(ipToDecimal(cIP))
        end
        for _,ip in pairs(ipWhitelist) do
            local s, e = string.find(ip, '-', 0, true)
            local x, j = string.find(ip, '/', 0, true)
            --IP字符串中不存在"-"、"/"等划分网段标识
            if s == nil and x == nil and cIP == ip then
                return true
            --范围划分法
            elseif s ~= nil then
                sIP = tonumber(ipToDecimal(string.sub(ip, 0, s - 1)))
                eIP = tonumber(ipToDecimal(string.sub(ip, e + 1, string.len(ip))))
                if numIP >= sIP and numIP <= eIP then
                   return true
                end
            --掩码划分法
            elseif x ~= nil then
                local ip_list = split(ip, "/")
                if IpBelongToNetwork(IP2bin(cIP),IP2bin(ip_list[1]),ip_list[2]) then
                    return true
                end
            end
        end
    end
    return false
end


