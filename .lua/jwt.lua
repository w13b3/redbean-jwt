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
    ]]
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


return JWT