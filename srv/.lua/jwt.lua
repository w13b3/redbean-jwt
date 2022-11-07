local _INFO = {
    _VERSION = "jwt.lua 1.0.2",
    _URL = "github.com/w13b3/redbean-jwt",
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
}


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


local Common = {}
Common.__index = Common

---Base64URL is a modification of the main Base64 standard
---@private
---@param str string String to encode in Base64URL
---@return string
function Common.EncodeBase64URL(str)
    -- rfc7515#appendix-C
    assert(type(str) == "string", ("EncodeBase64URL expects a string, received: %s"):format(type(str)))
    local subsitute = { ["/"] = "_", ["+"] = "-", ["="] = "" }  -- also remove the `=` padding
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
function Common.DecodeBase64URL(str)
    -- rfc7515#appendix-C
    assert(type(str) == "string", ("DecodeBase64URL expects a string, received: %s"):format(type(str)))
    local subsitute = { ["_"] = "/", ["-"] = "+" }
    for key, val in pairs(subsitute) do
        str = (str):gsub(key, val)
    end
    -- has not seen any errors due to the lack of padding
    return DecodeBase64(str)  -- redbean function
end

---Encode a segment to a base64URL encoded string
---@private
---@param segmentObject JsonValue Commonly a table or a string
---@return string Base64URL encoded string
function Common.EncodeSegment(segmentObject)
    local encodedSegment = assert(EncodeJson(segmentObject, { pretty = false }))  -- encode to string
    return Common.EncodeBase64URL(encodedSegment)
end

---Decode a base64URL encoded string to the original segment
---@private
---@param base64Segment string Base64URL encoded string
---@return JsonValue
function Common.DecodeSegment(base64Segment)
    assert(type(base64Segment) == "string", ("DecodeSegment expects a string, received: %s"):format(type(base64Segment)))
    local decodedSegment = Common.DecodeBase64URL(base64Segment)
    -- ternary: if string has length larger than 0 otherwise empty JSON string
    decodedSegment = (#decodedSegment > 0) and decodedSegment or "[]"
    return assert(DecodeJson(decodedSegment))  -- decode the segment, not necessary a table
end


-- JWA  - datatracker.ietf.org/doc/html/rfc7518  - archive.ph/04oex
local JWA = {}
JWA.__index = JWA

--[[ algorithms lookup table ]]
JWA.alg = {
    ["DEFAULT"]    = "HS256",
    ["HS256"]      = "SHA256", -- required algorithm - rfc7518#section-3.1
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

---Normalize given algorithm using the algorithm lookup table
---@private
---@param algorithm string text
---@return string Normalized string that can be used in the header claim: 'alg'
---@return nil when given algorithm is not known
function JWA.NormalizeAlgorithm(algorithm)
    if algorithm == nil then
        algorithm = JWA.alg.DEFAULT
    end
    algorithm = tostring(algorithm):upper()
    if algorithm == "NONE" then
        return "none"  -- "alg" param value can be "none"
    end
    for alg, _ in pairs(JWA.alg) do
        if alg == algorithm then
            return algorithm  --  algorithm is supported -- rfc7518#section-3.6
        end
    end
    return nil -- algorithm is not supported
end


local JWT = {}
JWT.__index = JWT


-- JWS can have 2 or up to 3 segments
-- unsecured signatures are missing the 3rd segment but have may have a trailing dot '.' according rfc7519#section-6.1
JWT.splitTokenRegex = assert(re.compile([[([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)\.?([a-zA-Z0-9_-]+)?]]))


---Create a basic table
---@public
---@return table A default JWT table
function JWT.BasicTable()
    return {
        ["header"] = {
            ["alg"] = JWA.alg.DEFAULT
        },
        ["payload"] = {
            ["iat"] = os.time()
        }
    }
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
        alg = JWA.NormalizeAlgorithm(alg or jwtTable.header.alg)
        assert((alg ~= nil), "Given or received algorithm is not supported")

        -- override the algorithm in the header
        -- parameter: alg > header.alg > JWT.alg.DEFAULT
        jwtTable.header.alg = alg

        -- create header
        local headerb64 = Common.EncodeSegment(jwtTable.header)

        -- create payload
        local payloadb64 = Common.EncodeSegment(jwtTable.payload)

        -- combine header and payload into body
        local combinedBody = ("%s.%s"):format(headerb64, payloadb64)

        local hash64 = ""
        if alg ~= "none" then
            -- sign body with secret and add this signature to the body
            local hash = GetCryptoHash(JWA.alg[alg], combinedBody, key)
            hash64 = Common.EncodeBase64URL(hash)
        end

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
        local match, b64header, b64payload, b64signature = assert(JWT.splitTokenRegex:search(data))
        assert((match ~= nil), "Parameter: 'data' has an unexpected format")

        -- decode the splitted parts
        local header = Common.DecodeSegment(b64header)
        local payload = Common.DecodeSegment(b64payload)
        local signature = Common.DecodeBase64URL(b64signature)

        -- reflect payload verification with the NotVerified code
        local result = {
            ["jwtVerified"] = false,  -- this decoded JWT is not verified

            -- tables
            ["header"]    = header,
            ["payload"]   = payload,
            ["signature"] = signature,

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

        -- override alg-value or fallback to default
        alg = JWA.NormalizeAlgorithm(alg or jwtTable.header.alg)
        assert((alg ~= nil), "Given or received algorithm is not supported")

        -- define the base64 header and payload
        local b64header = jwtTable.b64header or Common.EncodeBase64URL(EncodeJson(jwtTable.header))
        local b64payload = jwtTable.b64payload or Common.EncodeBase64URL(EncodeJson(jwtTable.payload))

        if alg == "none" then
            -- Recipients MUST verify that the JWS Signature value is the empty octet sequence
            -- rfc7518#section-3.6
            assert(#tostring(jwtTable.signature) == 0, "'alg' claim is 'none' but the signature is given")
        else
            -- verify the signature
            local combinedBody = ("%s.%s"):format(b64header, b64payload)
            local hash = GetCryptoHash(JWA.alg[alg], combinedBody, key)
            assert(hash == jwtTable.signature, "The 'key' and signature do not match")
        end

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


---Set a cookie with a token
---@public
---@param jwtTable table Header and payload of the JWT in a table
---@param key string Secret of the server
---@param alg string If given it overrides the alg-value given in the JWT-header
---@param cookieOptions table Optional cookie options
---@return boolean True if no error has occurred
---@return nil, string When error occurs
function JWT.SetCookieToken(jwtTable, key, alg, cookieOptions)
    return CatchError(function(jwtTable, key, alg, cookieOptions)
        -- set default cookieOptions
        cookieOptions = cookieOptions or {}

        -- create and set the token in a Cookie
        local token = assert(JWT.Encode(jwtTable, key, alg))
        SetCookie(
            cookieOptions.name or "access_token",    -- name
            token,                                   -- token
            cookieOptions                            -- options
        )
        return true
    end)(jwtTable, key, alg, cookieOptions)
end


---Verify a cookie containing the token
---@public
---@param key string Secret of the server
---@param data string Optional verifies given data instead of cookie
---@param cookieName table Optional custom cookie name
---@return table Table with data from the decoded JWT
---@return nil, string When error occurs
function JWT.VerifyCookieToken(key, data, cookieName)
    return CatchError(function(key, data, cookieName)
        -- check given parameters
        assert(type(key) == "string", "Parameter: 'key' not of type string")
        if type(data) ~= "string" then
            data = GetCookie(cookieName or "access_token")
        end
        -- assure data is not nil
        assert(data ~= nil, "Could not read the cookie data")
        -- decode, verify and return data
        return assert(JWT.DecodeAndVerify(data, key))
    end)(key, data, cookieName)
end


---Set an Authorization header with a JWT Bearer token
---@public
---@param jwtTable table Header and payload of the JWT in a table
---@param key string Secret of the server
---@param alg string If given it overrides the alg-value given in the JWT-header
---@return boolean True if no error has occurred
---@return nil, string When error occurs
function JWT.SetHeaderToken(jwtTable, key, alg)
    return CatchError(function(jwtTable, key, alg)
        local token = assert(JWT.Encode(jwtTable, key, alg))
        SetHeader("Authorization", string.format("Bearer %s", token))
        return true
    end)(jwtTable, key, alg)
end


---Verify the Authorization header containing a JWT Bearer token
---@public
---@param key string Secret of the server
---@param data string Optional verifies given data instead of header
---@return table Table with data from the decoded JWT
---@return nil, string When error occurs
function JWT.VerifyHeaderToken(key, data)
    return CatchError(function(key, data)
        -- check given parameters
        assert(type(key) == "string", "Parameter: 'key' not of type string")
        if type(data) ~= "string" then
            data = GetHeader("Authorization")
        end
        -- assure data is not nil
        assert(data ~= nil, "Could not read the cookie data")
        data = assert(JWT.splitTokenRegex:search(data))  -- returned match is the token

        -- decode, verify and return data
        return assert(JWT.DecodeAndVerify(data, key))
    end)(key, data)
end


-- add Util to JWT
JWT._INFO = _INFO
JWT._Common = Common
JWT._JWA = JWA
return JWT