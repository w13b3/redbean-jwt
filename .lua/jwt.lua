local JWT = {
    _VERSION = "jwt.lua 0.2.1",
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

    --[[ JWT algorithms ]]
    -- lookup table
    alg = {
        ["DEFAULT"]    = "HS256", -- default algorithm
        ["HS256"]      = "SHA256",
        ["HS384"]      = "SHA384",
        ["HS512"]      = "SHA512",
        -- incompatible with JWT
        ["BLAKE2B256"] = "BLAKE2B256",
        ["MD5"]        = "MD5",
        ["SHA1"]       = "SHA1",
        ["SHA224"]     = "SHA224",
        ["SHA256"]     = "SHA256",
        ["SHA384"]     = "SHA384",
        ["SHA512"]     = "SHA512",
    }
}
JWT.__index = JWT


--[=[
sources used:
    jwt.io
    datatracker.ietf.org/doc/html/rfc7519  -  archive.ph/KDWdO
    base64.guru/standards/base64url  -  archive.ph/T1hIZ
]=]


---Wrapper to catch errors
---@private
---@param func function Function to catch errors from
---@param defaultReturn any Optional set what to return on failure
---@return any On success
---@return nil, string When error occurs
local function CatchError(func, defaultReturn)
    assert(type(func) == "function",
            ("Bad argument #1 to 'CatchError' (function expected, got %s)"):format(type(func)))
    -- wrapper function
    return function(...)
        -- pack result into a table, result[1] is the boolean from `pcall`
        local result = { pcall(func, ...) }
        if result[1] then
            -- unpack and discard the `pcall` bool
            return select(2, table.unpack(result))
        else -- `pcall` received error
            return defaultReturn, result[2]
        end
    end
end


---Base64URL is a modification of the main Base64 standard
---@private
---@param str string String to encode in Base64URL
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
local splitTokenRegex = assert(re.compile([[(\w+)\.(\w+)\.(\w+)]]))

---Split the JWT and return the separate segments
---@private
---@param data string JWT string
---@return boolean, string, string, string If given data is of valid structure
---@return boolean False is returned if invalid data has an invalid structure
function JWT.Split(data)
    local match, headerb64, payloadb64, signatureb64 = assert(splitTokenRegex:search(data))
    if match then  -- match is the token
        return true, headerb64, payloadb64, signatureb64
    else
        return false
    end
end


---Decode the split up Base64URL strings
---@private
---@param headerBase64 string Base64 string
---@param payloadBase64 string Base64 string
---@param signatureBase64 string Base64 string
---@return table Table with header, payload tables and decoded signature
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
---@param jwtTable table Header and payload of the JWT in a table
---@param key string Secret of the server
---@param alg string If given it overrides the alg-value given in the JWT-header
---@return string JWT string
---@return nil, string When error occurs
function JWT.Encode(jwtTable, key, alg)
    return CatchError(function(jwtTable, key, alg)
        -- check given parameters
        assert(type(jwtTable) == "table", "Parameter: 'jwtTable' not of type table")
        assert(type(jwtTable.header) == "table", "Header in the parameter: 'jwtTable' not of type table")
        assert(type(jwtTable.payload) == "table", "Payload in the parameter: 'jwtTable' not of type table")

        if key ~= nil then
            assert(type(key) == "string", "Parameter: 'key' is not of type string")
        else
            -- key can be nil, but it defeats the purpose of JWT
            Log(kLogWarn, "Given key is of value: nil")
        end

        -- override alg-value or fallback to default
        alg = alg or jwtTable.header.alg or JWT.alg.DEFAULT
        assert(JWT.alg[string.upper(alg)] ~= nil, "Given or received algorithm is not supported")

        -- override the algorithm in the header
        -- parameter: alg > header.alg > JWT.alg.DEFALT
        jwtTable.header.alg = alg

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
        return result
    end)(jwtTable, key, alg)  -- call and pass arguments to CatchError
end


---Decodes the given JWT string to a table
---@public
---@param data string JWT string
---@return table Table with data from the decoded JWT
---@return nil, string When error occurs
function JWT.Decode(data)
    return CatchError(function(data)
        -- check given parameters
        assert(type(data) == "string", "Parameter: 'data' not of type string")

        -- split the JWT on its dot's
        local success, b64header, b64payload, b64signature = JWT.Split(data)
        assert(success, "Parameter: 'data' has an unexpected format")

        -- decode the splitted parts
        local callSuccess, body = pcall(JWT.DecodeParts, b64header, b64payload, b64signature)
        assert(callSuccess, "Invalid segment in the parameter: 'data'")

        -- reflect payload verification with the NotVerified code
        local result = {
            ["jwtVerified"] = false,  -- this decoded JWT is not verified

            -- tables
            ["header"]    = body.header,
            ["payload"]   = body.payload,
            ["signature"] = body.signature,

            -- used in verify
            ["b64header"]    = b64header,
            ["b64payload"]   = b64payload,
            ["b64signature"] = b64signature
        }
        return result
    end)(data)  -- call and pass arguments to CatchError
end

---Verify signature of a decoded JWT table
---@public
---@param jwtTable table Preferably received from `Decode` function
---@param key string Secret of the server
---@param alg string If given it overrides the alg-value given in the JWT-header
---@return table Table with JWT parts
---@return nil, string When error occurs
function JWT.VerifyTable(jwtTable, key, alg)
    return CatchError(function(jwtTable, key, alg)
        -- check given parameters
        assert(type(jwtTable) == "table", "Parameter 'jwtTable' not of type table")
        assert(type(key) == "string", "Parameter: 'key' not of type string")
        -- check jwtTable content
        assert(type(jwtTable.signature) == "string", "Parameter: 'jwtTable' does not contain a signature string")
        assert(type(jwtTable.header) == "table", "Parameter: 'jwtTable' does not contain a header table")
        assert(type(jwtTable.payload) == "table", "Parameter: 'jwtTable' does not contain a payload table")

        -- define the algorithm
        alg = alg or jwtTable.header.alg or JWT.alg.DEFAULT  -- override alg value or fallback to default
        alg = JWT.alg[string.upper(alg)]
        assert(alg ~= nil, "Given or received algorithm is not supported")

        -- define the base64 header and payload
        local b64header = jwtTable.b64header or JWT.EncodeBase64URL(EncodeJson(jwtTable.header))
        local b64payload = jwtTable.b64payload or JWT.EncodeBase64URL(EncodeJson(jwtTable.payload))

        -- verify the signature
        local combinedBody = ("%s.%s"):format(b64header, b64payload)
        local hash = GetCryptoHash(alg, combinedBody, key)
        assert(hash == jwtTable.signature, "The 'key' and signature do not match")

        -- set verified to true, because the JWT is now verified
        jwtTable.jwtVerified = true
        return jwtTable
    end)(jwtTable, key, alg)  -- call and pass arguments to CatchError
end


---Decode the JWT and verify the signature
---@public
---@param data string JWT string
---@param key string Secret of the server
---@return table Table with data from the decoded JWT
---@return nil, string When error occurs
function JWT.DecodeAndVerify(data, key)
     return CatchError(function(data, key)
        -- check given parameters
        assert(type(key) == "string", "Parameter: 'key' not of type string")
        assert(type(data) == "string", "Parameter: 'data' not of type string")

        -- decode the data
        local jwtTable = assert(JWT.Decode(data))

        -- verify the decoded table content
        jwtTable = assert(JWT.VerifyTable(jwtTable, key))
        -- return verified table
        return jwtTable
    end)(data, key)  -- call and pass arguments to CatchError
end


return JWT