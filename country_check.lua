-- 根据ip地址获取国家
function getCountry()
   local cjson=require "cjson"
   local geo=require "area/maxminddb"
   local now_ip = getClientIp()
   if not geo.initted() then
       geo.init("waf/area/GeoLite2-Country.mmdb")
   end
   local res,err=geo.lookup(now_ip)

   if not res then
       return "unknown_country"
   else
       return res["country"]["iso_code"]
   end
end

-- 国家白名单验证;如果开启国家验证，建议开启蜘蛛验证，并在参数内填写你允许的搜索引擎蜘蛛
function country_white()
    if CountryLimit then
        if next(WhiteCountry) ~= nil then
            local country = getCountry()
            local items = Set(WhiteCountry)
            if country == "unknown_country" then
                return true
            end
            for country_iso in pairs(items) do
                if country == string.upper(country_iso) then
                    return true
                end
            end
        end
    end
end

-- 国家黑名单验证
function country_block()
    if CountryLimit then
        if next(BlockCountry) ~= nil then
            local country = getCountry()
            local items = Set(BlockCountry)
            for country_iso in pairs(items) do
                if country == string.upper(country_iso) then
                    log("-","BlockCountry: ".. country)
                    ngx.exit(403)
                    return true
                end
            end
        end
    end
end
