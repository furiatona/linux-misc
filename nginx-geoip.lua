-- access by lua

local country = ngx.var.geoip_country_code
local locale_param = ngx.var.arg_locale
if locale_param == nil and country ~= nil then
    country = string.lower(country)
    local query_string = "locale=" .. country
    local original_uri = ngx.var.request_uri
    local new_uri = original_uri .. (original_uri:find("?") and "&" or "?") .. query_string
    ngx.redirect(new_uri, ngx.HTTP_MOVED_TEMPORARILY)
end

-- case www.example.com/ --> access from sg --> www.example.com/?locale=sg

-- nginx, geoip, lua