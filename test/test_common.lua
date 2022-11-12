--[=[
    test the base64url decode and encoding functions
]=]
local common = require("jwt")._Common

-- test EncodeBase64URL and DecodeBase64URL with predefined values
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
        { "<<???>>",                    "PDw_Pz8-Pg",                       },
    }
    for _, pair in ipairs(testValues) do
        local plain, expected = table.unpack(pair)
        local encoded = common.EncodeBase64URL(plain)
        assert(encoded == expected, ("%s ~= %s"):format(encoded, expected))
        local decoded = common.DecodeBase64URL(encoded)
        assert(plain == decoded, ("%s ~= %s"):format(plain, decoded))
    end
end
-- redbean DecodeBase64 seems not to care about the base64 padding

-- test with random text
do
    local whitespace = ' \t\n\r\v\f'
    local ascii_lowercase = 'abcdefghijklmnopqrstuvwxyz'
    local ascii_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    local ascii_letters = ascii_lowercase .. ascii_uppercase
    local digits = '0123456789'
    local punctuation = [[!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~]]
    local printable =  digits .. ascii_letters .. punctuation .. whitespace

    function RandomText(length)
        local char
        local result = {}
        for _ = 1, (tonumber(length) or 1) do
            char = math.random(1, #printable)
            table.insert(result, printable:sub(char, char))
        end
        return table.concat(result)  -- type: string
    end

    -- loop 100 times
    for _ = 1, 100 do
        local seed = Rdseed()
        math.randomseed(seed)
        local data = RandomText(seed % 100)
        local encoded = common.EncodeBase64URL(data)
        local decoded = common.DecodeBase64URL(encoded)
        assert(data == decoded, ("Test random text failed with seed: %s"):format(seed))
    end
end

-- test error if parameter is not of type string
do
    -- eight types in lua: nil, boolean, number, string, function, userdata, thread, and table.
    -- userdata values cannot be created or modified in Lua, only through the C API.
    -- lua manual 5.4 manual #2.1
    local obj, bool
    local func = function() end
    -- nil, boolean, number, function, thread, and table
    local types = { nil, true, 0, (func), (coroutine.create(func)), {"table"} }
    for i = 1, #types do
        obj, bool = types[i], nil
        bool = pcall(common.EncodeBase64URL, obj)  -- pcall catches the error and returns false if error occurred
        assert((not bool), ("EncodeBase64URL accepted type: %s"):format(type(obj)))
        bool = pcall(common.DecodeBase64URL, obj)
        assert((not bool), ("DecodeBase64URL accepted type: %s"):format(type(obj)))
    end
end

-- test EncodeSegment and DecodeSegment with predefined values
do
    local testValues = {
        -- object,                       expected after BASE64URL encode
        { "<html>hello</html>",          "Ilx1MDAzY2h0bWxcdTAwM2VoZWxsb1x1MDAzY1wvaHRtbFx1MDAzZSI", },
        { true,                          "dHJ1ZQ",                                                  },
        { { header = { alg = "none" } }, "eyJoZWFkZXIiOnsiYWxnIjoibm9uZSJ9fQ",                      },
        { 1234567890,                    "MTIzNDU2Nzg5MA",                                          },
    }
    for _, pair in ipairs(testValues) do
        local object, expected = table.unpack(pair)
        local encodedSegment = common.EncodeSegment(object)
        assert(encodedSegment == expected, ("%s ~= %s"):format(encodedSegment, expected))
        local decodedSegment = common.DecodeSegment(encodedSegment)

        local err = ("%s ~= %s"):format(decodedSegment, object)
        -- check if the given object is a table, if so compare with the CompareTables function
        if type(object) == "table" then
            assert(CompareTables(decodedSegment, object), err)
        else
            assert(decodedSegment == object, err)
        end
    end
end
