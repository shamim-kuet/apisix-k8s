--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local core = require("apisix.core")
local resty_sha256 = require("resty.sha256")
local str = require("resty.string")
local redis = require("resty.redis")
local ngx = ngx
local ngx_encode_base64 = ngx.encode_base64
local ngx_decode_base64 = ngx.decode_base64
local ngx_time = ngx.time
local ngx_cookie_time = ngx.cookie_time
local math = math

local schema = {
    type = "object",
    properties = {
        key = {
            description = "use to generate csrf token",
            type = "string",
        },
        expires = {
            description = "expires time(s) for csrf token",
            type = "integer",
            default = 7200
        },
        name = {
            description = "the csrf token name",
            type = "string",
            default = "apisix-csrf-token"
        },
        request_token_name = {
            description = "token name in response header",
            type = "string",
            default = "Cf-Ray-Status-Id-Tn"
        },
        validation_ip = {
            description = "validation ip",
            type = "string",
            default = ""
        },
        validation_port = {
            description = "validation port",
            type = "integer",
        },
        validation_cred = {
            description = "validation cred",
            type = "string",
        },
        bypass_uri_list = {
            description = "List of URI patterns to check before gateway token",
            type = "array",
            items = {
                type = "string",
            },
        },
        uri_list = {
            description = "List of URI patterns to check after gateway token",
            type = "array",
            items = {
                type = "string",
            },
        },
        cpu_limit = {
            description = "CPU Threshold",
            type = "integer",
            default = 70
        }
    },
    encrypt_fields = {"key"},
    required = {"key"}
}

local _M = {
    version = 0.1,
    priority = 2980,
    name = "csrf",
    schema = schema,
}


function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end


local function gen_sign(random, expires, key)
    local sha256 = resty_sha256:new()

    local sign = "{expires:" .. expires .. ",random:" .. random .. ",key:" .. key .. "}"

    sha256:update(sign)
    local digest = sha256:final()

    return str.to_hex(digest)
end


local function gen_csrf_token(conf)
    local random = math.random()
    local timestamp = ngx_time()
    local sign = gen_sign(random, timestamp, conf.key)

    local token = {
        random = random,
        expires = timestamp,
        sign = sign,
    }

    local cookie = ngx_encode_base64(core.json.encode(token))
    cookie = ngx_encode_base64(cookie)
    return cookie
end


local function check_csrf_token(conf, ctx, token)
    local token_str = ngx_decode_base64(token)
    if not token_str then
        core.log.error("csrf token base64 decode error")
        return false
    end

    local token_table, err = core.json.decode(token_str)
    if err then
        core.log.error("decode token error: ", err)
        return false
    end

    local random = token_table["random"]
    if not random then
        core.log.error("no random in token")
        return false
    end

    local expires = token_table["expires"]
    if not expires then
        core.log.error("no expires in token")
        return false
    end
    local time_now = ngx_time()
    if conf.expires > 0 and time_now - expires > conf.expires then
        core.log.error("token has expired")
        return false
    end

    local sign = gen_sign(random, expires, conf.key)
    if token_table["sign"] ~= sign then
        core.log.error("Invalid signatures")
        return false
    end

    return true
end

local function get_cpu_usage()
    local handle = io.popen("grep 'cpu ' /proc/stat")
    local result = handle:read("*a")
    handle:close()

    local user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice = result:match("cpu  (%d+) (%d+) (%d+) (%d+) (%d+) (%d+) (%d+) (%d+) (%d+) (%d+)")
    local total = user + nice + system + idle + iowait + irq + softirq + steal

    return 100 * (total - idle) / total
end

function _M.access(conf, ctx)
    -- Get the URI from the request
    local request_uri = string.lower((ngx.var.request_uri:match("([^?]+)")):match("(.*/)%d+$") or ngx.var.request_uri)

    -- Remove trailing '/' if it exists
    if request_uri:sub(-1) == '/' then
        request_uri = request_uri:sub(1, -2)
    end

    -- Check if the request_uri is /hello
    if request_uri == "/hello" then
        local cpu_usage = get_cpu_usage()
        local response = {
            status = cpu_usage < conf.cpu_limit and 200 or 500,
            info = {
                version = _M.version,
                cpu = cpu_usage,
            }
        }

        return response.status, response.info
    end

    -- Use uri_list from conf to check if request_uri contains any item from the array
    local uri_contains_public_item = false
    for _, item in ipairs(conf.bypass_uri_list) do
        if string.find(request_uri, item, 1, true) then
            uri_contains_public_item = true
            break
        end
    end

    if not uri_contains_public_item then

        local header_token = core.request.header(ctx, conf.name)
        if not header_token or header_token == "" then
            return 401, {error_msg = "invalid attempt to access"}
        end

        -- Decode the token twice with error handling
        local decoded_token = ngx_decode_base64(header_token)
        if not decoded_token then
            return 401, {error_msg = "invalid attempt to access"}
        end

        decoded_token = ngx_decode_base64(decoded_token)
        if not decoded_token then
            return 401, {error_msg = "invalid attempt to access"}
        end

        --local cookie_token = ctx.var["cookie_" .. conf.name]
        --if not cookie_token then
        --    return 401, {error_msg = "invalid attempt to access: 2"}
        --end

        --if header_token ~= cookie_token then
        --    return 401, {error_msg = "invalid attempt to access: 3"}
        --end

        local result = check_csrf_token(conf, ctx, ngx_decode_base64(decoded_token))
        if not result then
            return 401, {error_msg = "invalid attempt to access"}
        end

        if conf.validation_ip ~= "" then

            -- Use uri_list from conf to check if request_uri contains any item from the array
            local uri_contains_item = false
            for _, item in ipairs(conf.uri_list) do
                if string.find(request_uri, item, 1, true) then
                    uri_contains_item = true
                    break
                end
            end

            if not uri_contains_item then
                -- Connect to Redis
                local red = redis:new()
                red:set_timeout(1000) -- 1 second

                local ok, err = red:connect(conf.validation_ip, conf.validation_port)
                if not ok then
                    return 500, {error_msg = "failed to connect: down"}
                end

                -- Authenticate with Redis if password is provided
                if conf.validation_cred then
                    local res, err = red:auth(conf.validation_cred)
                    if not res then
                        return 500, {error_msg = "failed to connect: bad cred"}
                    end
                end

                -- Retrieve the 'Authorization' header
                local authorization_header = core.request.header(ctx, 'Authorization')
                if not authorization_header then
                    return 401, {error_msg = "unauthorized access attempt"}
                end

                -- Remove 'Bearer ' prefix from the 'Authorization' header
                local token_value = authorization_header:gsub("Bearer%s+", "")
                if token_value == "" then
                    return 401, {error_msg = "unauthorized access attempt"}
                end

                -- Check if exactly one Redis key contains '_bearer'
                local res, err = red:keys("*" .. token_value)
                if err then
                    return 500, {error_msg = "failed to connect:"}
                end

                if #res ~= 1 then
                    return 401, {error_msg = "unauthorized access attempt"}
                end
            end
        end
    end
end


function _M.header_filter(conf, ctx)
    -- local csrf_token = gen_csrf_token(conf)
    -- local cookie = conf.name .. "=" .. csrf_token .. ";path=/;Expires="
    --               .. ngx_cookie_time(ngx_time() + conf.expires)
    --               .. ";" .. conf.others
    core.response.add_header(conf.request_token_name, gen_csrf_token(conf))
end


return _M
