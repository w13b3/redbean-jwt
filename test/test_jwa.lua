--[=[
    test the JWA functionality
]=]

local jwa = require("jwt")._JWA


-- test default algorithm
do
    -- check default
    local expected = "HS256"
    local actual = jwa.default
    assert(actual == expected, ("The default algorithm is changed from %s to %s"):format(expected, actual))

    -- check default to be used in GetCryptoHash
    expected = "SHA256"
    actual = jwa.lookup[jwa.default]
    assert(actual == expected, ("The looked up algorithm is changed from %s to %s"):format(expected, actual))
end

-- test lookup values can be used in GetCryptoHash
do
    for _, alg in pairs(jwa.supported) do
        -- skip the supported "none"
        if (alg):lower() ~= "none" then
            alg = jwa.lookup[alg]
            assert(pcall(GetCryptoHash, alg, "", ""), ("GetCryptoHash can not use given hash type: %s"):format(alg))
        end
    end
end

-- test CheckHash with the supported algorithms
do
    local testValues = {
        -- message, key, algorithm, signature (Base64 encoded, prepared using GetCryptoHash)
        { "a", "1",  "none",       "",                                                                                         },
        { "b", "2",  "HS256",      "zyfxoP8Ww4i/QovzRCENoLM2er2VOQYSKzyLlOIYF8U=",                                             },
        { "c", "3",  "HS384",      "Je9et3xNWsni6dDD9Qi3XTNqsSm4Otjey8ZzYsJ11OEmsUlI3Oe2Wdy8v4QR7vki",                         },
        { "d", "4",  "HS512",      "I2KGc2boxIizeQm8YJ764gkpP+50d6J6V4wwOERIPi/1Fsj/n01FeoW6qXauC6fB0rkezNr48liZxAif5U6Vmg==", },
        { "e", "5",  "BLAKE2B256", "YaMBO8EGapzdscvOSIldL2rm70Rl2S7k0uWg+0egq/k=",                                             },
        { "f", "6",  "MD5",        "nNTGcpNgzAIX0sNEW2BpYQ==",                                                                 },
        { "g", "7",  "SHA1",       "xAFHNgMXwiYYcsmlJf1y0qj0hms=",                                                             },
        { "h", "8",  "SHA224",     "a0KJiLmxAqf7ERv/ZSPnNwSs9SFPmePpN7ARKg==",                                                 },
        { "i", "9",  "SHA256",     "6yR5G9dTgPwkeWnLCREBfJKfeKN/eHtX3xXybrqO0cE=",                                             },
        { "j", "10", "SHA384",     "bGOnNUG+OqsQ2BUu8P285pD8DJS6vJd5Vc64952dTO5K8ppqaQQqGXOIlvBISgUn",                         },
        { "k", "11", "SHA512",     "2BKi9RAPQCwdfsEbj4uJdhsq7YW+rMafA++58F0zCo/qB+4GffISy3ylq2Al9SZwJSo7H0NCbUVDMqpAnoaN/Q==", },
    }
    for _, pair in ipairs(testValues) do
        local message, key, algorithm, signature = table.unpack(pair)
        local bool, hashType = jwa.CheckHash(message, DecodeBase64(signature), key, { algorithm })

        assert(bool, ("CheckHash failed using algorithm: %s"):format(algorithm))
        assert(hashType == algorithm, ("%s ~= %s"):format(hashType, algorithm))
    end
end


-- test that CheckHash tests for algorithm: "none" to have a signature of: "" (empty string)
do
    local algorithm = "none"
    local bool, hashType = jwa.CheckHash("message", "signature", "key", { "none" })

    -- expected CheckHash to return false
    assert((not bool), ("Expected CheckHash to return boolean false, received: %s"):format(bool))
    assert(hashType ~= algorithm, ("Expected CheckHash to return an error message, received: %s"):format(hashType))

    -- expected CheckHash to return true
    bool, hashType = jwa.CheckHash("message", "", "key", { "none" })
    assert(bool, ("Expected CheckHash to return boolean true, received: %s"):format(bool))
    assert(hashType == algorithm, ("%s ~= %s"):format(hashType, algorithm))
end

-- test that the table of algorithms given to CheckHash is used
do
    local algorithm = "SHA256"
    local message = "x"
    local key = "secret"
    local signature = DecodeBase64("EX7KMy9+E8y45FdOTzPaohKpIxNTZwwri0eX3wu3evo=")  -- prepared using GetCryptoHash

    -- expected CheckHash to return true, used algorithm is in the algorithm table
    local bool, hashType = jwa.CheckHash(message, signature, key, { "none", "HS512", algorithm })
    assert(bool, ("Expected CheckHash to return boolean true, received: %s"):format(bool))
    assert(hashType == algorithm, ("%s ~= %s"):format(hashType, algorithm))

    -- expected CheckHash to return false, used algorithm is not in the algorithm table
    bool, hashType = jwa.CheckHash(message, signature, key, { "none", "HS512", "SHA1" })
    assert((not bool), ("Expected CheckHash to return boolean false, received: %s"):format(bool))
    assert(hashType ~= algorithm, ("Expected CheckHash to return an error message, received: %s"):format(hashType))
end
