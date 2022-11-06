--[=[
    test the base64url decode and encoding functions
]=]
local jwt = require("jwt")

local EncodeBase64URL = jwt.EncodeBase64URL
local DecodeBase64URL = jwt.DecodeBase64URL

-- test with predefined values
-- some test values are from datatracker.ietf.org/doc/html/rfc4648#section-10  -  archive.ph/htQta
do
    local testValues = {
        -- plain,                       expected after BASE64URL encode
        { "",                           "",                                 },
        { "f",                          "Zg",                               },
        { "fo",                         "Zm8",                              },
        { "foo",                        "Zm9v",                             },
        { "foob",                       "Zm9vYg",                           },
        { "fooba",                      "Zm9vYmE",                          },
        { "foobar",                     "Zm9vYmFy",                         },
        { "000000",                     "MDAwMDAw",                         },
        { "\0\0\0\0",                   "AAAAAA",                           },
        { "\xff",                       "_w",                               },
        { "\xff\xff",                   "__8",                              },
        { "\xff\xff\xff",               "____",                             },
        { "\xff\xff\xff\xff",           "_____w",                           },
        { "\xfb",                       "-w",                               },
        { [[{"foo":"bar"}]],            "eyJmb28iOiJiYXIifQ",               },
        { [[5%2+3-1=3 "Yes/No" <a&b>]], "NSUyKzMtMT0zICJZZXMvTm8iIDxhJmI-", },
    }
    for _, pair in ipairs(testValues) do
        local plain, expected = table.unpack(pair)
        local encoded = EncodeBase64URL(plain)
        assert(encoded == expected, ("%s ~= %s"):format(encoded, expected))
        local decoded = DecodeBase64URL(encoded)
        assert(plain == decoded, ("%s ~= %s"):format(plain, decoded))
    end
end
-- redbean DecodeBase64 seems not to care about the base64 padding

-- test with random text
do
    local charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    function RandomText(length)
        local c
        local result = {}
        for _ = 1, (tonumber(length) or 1) do
            c = math.random(1, #charset)
            table.insert(result, charset:sub(c, c))
        end
        return table.concat(result)
    end

    -- loop 100 times
    for _ = 1, 100 do
        local seed = Rdseed()
        math.randomseed(seed)
        local data = RandomText(seed % 100)
        local encoded = EncodeBase64URL(data)
        local decoded = DecodeBase64URL(encoded)
        assert(data == decoded, ("Test random text failed with seed: %s"):format(seed))
    end
end
