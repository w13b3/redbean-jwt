local JWT = {
    _VERSION = "jwt.lua 0.0.0",
    _URL = "https://github.com/w13b3",
    _DESCRIPTION = "JSON Web Token for redbean",
    _LICENSE = [[
        Copyright 2022 w13b3

        Permission to use, copy, modify, and/or distribute this software for
        any purpose with or without fee is hereby granted, provided that the
        above copyright notice and this permission notice appear in all copies.

        THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
        WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
        WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
        AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
        DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
        PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
        TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
        PERFORMANCE OF THIS SOFTWARE.
    ]],

    -- [[ Errors ]]
    ["Success"]          = 0,
    ["InvalidJWT"]       = 1,
    ["InvalidParameter"] = 2,

    --[[ JWT algorithms ]]
    -- lookup table
    alg = {
        ["DEFAULT"] = "HS256", -- default algorithm
        ["HS256"]   = "SHA256",
        ["HS384"]   = "SHA384",
        ["HS512"]   = "SHA512",
    }


}
JWT.__index = JWT

--[=[
sources used:
    datatracker.ietf.org/doc/html/rfc7519  -  archive.ph/KDWdO
    base64.guru/standards/base64url  -  archive.ph/T1hIZ
]=]


---Base64URL is a modification of the main Base64 standard
---@private
---@param str string string to encode in Base64URL
---@return string
function JWT.EncodeBase64URL(str)
    assert(type(str) == "string", ("EncodeBase64URL expects a string, received: %s"):format(type(str)))
    -- remove the `=` padding
    --> datatracker.ietf.org/doc/html/rfc7515#section-2
    local subsitute = { ["/"] = "_", ["+"] = "-", ["="] = "" }
    local result = EncodeBase64(str)  -- redbean function
    for key, val in pairs(subsitute) do
        result = (result):gsub(key, val)
    end
    return result
end


---Base64URL is a modification of the main Base64 standard
---@private
---@param str string Base64URL encoded string
---@return string
function JWT.DecodeBase64URL(str)
    assert(type(str) == "string", ("DecodeBase64URL expects a string, received: %s"):format(type(str)))
    local subsitute = { ["_"] = "/", ["-"] = "+" }
    for key, val in pairs(subsitute) do
        str = (str):gsub(key, val)
    end
    return DecodeBase64(str)  -- redbean function
end


--[[
expected jwtTable:
    {
        ["header"] = {
            ["alg"] = "HS256"
        },

        ["payload"] = {}
    }
]]

---Encode JSON that has header and payload keys
---@public
---@param jwtTable table header and payload of the JWT in a table
---@param key string secret password
---@param alg string if given it overrides the alg-value given in the JWT-header
---@return string, number JWT string and success code
---@return nil, number nil and error code
function JWT.Encode(jwtTable, key, alg)
    -- check given parameters
    if type(jwtTable) ~= "table" then
        Log(kLogError, "Given header not of type table")
        return nil, JWT.InvalidParameter
    end
    if jwtTable.header == nil or type(jwtTable.header) ~= "table" then
        Log(kLogError, "Given body header not of type table")
        return nil, JWT.InvalidParameter
    end
    if jwtTable.payload == nil or type(jwtTable.payload) ~= "table" then
        Log(kLogError, "Given body payload not of type table")
        return nil, JWT.InvalidParameter
    end

    if key ~= nil then
        if type(key) ~= "string" then
            Log(kLogError, "Given key not of type string")
            return nil, JWT.InvalidParameter
        end
    else
        -- key can be nil, but it defeats the purpose of JWT
        Log(kLogWarn, "given key is of value: nil")
    end

    -- override alg-value or fallback to default
    alg = alg or jwtTable.header.alg or JWT.alg.DEFAULT
    if JWT.alg[string.upper(alg)] == nil then
        Log(kLogError, "Given alg is not supported")
        return nil, JWT.InvalidParameter
    end

    -- create header
    local headerJSON = EncodeJson(jwtTable.header)
    local headerb64 = JWT.EncodeBase64URL(headerJSON)

    -- create payload
    local payloadJSON = EncodeJson(jwtTable.payload)
    local payloadb64 = JWT.EncodeBase64URL(payloadJSON)

    -- combine header and payload into body
    local combinedBody = ("%s.%s"):format(headerb64, payloadb64)

    -- sign body with secret and add this signature to the body
    local hash = GetCryptoHash(JWT.alg[string.upper(alg)], combinedBody, key)
    local hash64 = JWT.EncodeBase64URL(hash)

    -- create the JWT string
    local result = ("%s.%s"):format(combinedBody, hash64)
    return result, JWT.Success
end


return JWT