local JWT = {
    _VERSION = "jwt.lua 0.1.0",
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
    ["NotVerified"]      = 1,
    ["InvalidJWT"]       = 2,
    ["InvalidParameter"] = 3,

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


-- regex to split the JWT segments into header payload and signature
local splitRegex = re.compile([[^(.*?)\.(.*?)\.(.*?)$]])

---Split the JWT and return the separate segments
---@private
---@param data string JWT string
---@return number, string, string, string if given data is of valid structure
---@return number, nil, nil, nil if invalid structure is given
function JWT.Split(data)
    local match, headerb64, payloadb64, signatureb64 = splitRegex:search(data)
    if match then
        return JWT.Success, headerb64, payloadb64, signatureb64
    else
        return JWT.InvalidJWT
    end
end


---Decode the split up Base64URL strings
---@private
---@param headerBase64 string base64 string
---@param payloadBase64 string base64 string
---@param signatureBase64 string base64 string
---@return table with header, payload tables and decoded signature
function JWT.DecodeParts(headerBase64, payloadBase64, signatureBase64)
    local hb64 = headerBase64 or ""
    local pb64 = payloadBase64 or ""
    local sb64 = signatureBase64 or ""
    -- ternary: if string has length larger than 0 otherwise empty JSON string
    hb64 = (#hb64 > 0) and JWT.DecodeBase64URL(hb64) or "[]"
    pb64 = (#pb64 > 0) and JWT.DecodeBase64URL(pb64) or "[]"
    local result = {
        ["header"]    = DecodeJson(hb64),
        ["payload"]   = DecodeJson(pb64),
        ["signature"] = JWT.DecodeBase64URL(sb64)
    }
    return result
end


---Encode JSON that has header and payload keys
---@public
---@param jwtTable table header and payload of the JWT in a table
---@param key string secret of the server
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


---Decodes the given JWT string to a table
---@public
---@param data string JWT string
---@return table, number JWT parts in table and NOT-Verified code
---@return nil, number nil and error code
function JWT.Decode(data)
    -- check given parameters
    if type(data) ~= "string" then
        Log(kLogError, "data not of type string")
        return nil, JWT.InvalidParameter
    end

    -- split and decode
    local _, b64header, b64payload, b64signature = JWT.Split(data)
    local callSuccess, body = pcall(
            JWT.DecodeParts, b64header, b64payload, b64signature
    )

    -- error if failed to split and/or decode
    if not callSuccess then
        Log(kLogError, "Invalid JWT segment")
        return nil, JWT.InvalidJWT
    end

    -- reflect payload verification with the NotVerified code
    local result = {
        -- tables
        ["header"]    = body.header,
        ["payload"]   = body.payload,
        ["signature"] = body.signature,

        -- used in verify
        ["b64header"]    = b64header,
        ["b64payload"]   = b64payload,
        ["b64signature"] = b64signature,

    }
    return result, JWT.NotVerified
end


---Verify signature of the table received from the `Decode` function
---@public
---@param decodedTable table table received from `Decode` function
---@param key string secret of the server
---@param alg string if given it overrides the alg-value given in the JWT-header
---@return table, number JWT parts in table and success code
---@return nil, number nil and error code
function JWT.VerifyDecodedTable(decodedTable, key, alg)
    -- check given parameters
    if type(decodedTable) ~= "table" then
        Log(kLogError, "decodedTable not of type table")
        return nil, JWT.InvalidParameter
    end
    if type(key) ~= "string" then
        Log(kLogError, "key not of type string")
        return nil, JWT.InvalidParameter
    end

    -- verify the signature
    alg = alg or decodedTable.header.alg or JWT.alg.DEFAULT  -- override alg value or fallback to default
    local combinedBody = ("%s.%s"):format(decodedTable.b64header, decodedTable.b64payload)
    local hash = GetCryptoHash(JWT.alg[string.upper(alg)], combinedBody, key)

    if hash ~= decodedTable.signature then
        Log(kLogError, "Invalid signature")
        return nil, JWT.InvalidSignature
    end
    return decodedTable, JWT.Success
end


---Decode the JWT and verify the signature
---@public
---@param data string JWT string
---@param key string secret of the server
---@return table, number JWT parts in table and success code
---@return nil, number nil and error code
function JWT.DecodeAndVerify(data, key)
    -- check given parameters
    if type(key) ~= "string" then
        Log(kLogError, "key not of type string")
        return nil, JWT.InvalidParameter
    end
    if type(data) ~= "string" then
        Log(kLogError, "data not of type string")
        return nil, JWT.InvalidParameter
    end

    -- decode the data
    local decodedTable, errorCode = JWT.Decode(data)
    if errorCode ~= JWT.NotVerified then
        return nil, errorCode  -- jwt.InvalidJWT
    end

    -- verify the decoded table content
    decodedTable, errorCode = JWT.VerifyDecodedTable(decodedTable, key)
    return decodedTable, errorCode
end


return JWT