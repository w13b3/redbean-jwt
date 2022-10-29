# Usage  <sub><sup>_Quick overview of how to use redbean-jwt_<sup><sub>

_Assuming the `jwt.lua` is added to the .lua directory in the redbean._

Add the module to the Lua script:

```lua
local jwt = require("jwt")
```

The minimal table required to create a JWT is the following:
```lua
local jwtTable = {
    ["header"] = {
        ["alg"] = "HS256"
    },
    ["payload"] = {}
} 
```
Normally the payload is filled an ["iat" (Issued At)](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6) claim.  
And if some data is to be transferred, the payload segment is the place to store it.

So we can make a JWT table with the data
```lua
local jwtTable = {
    ["header"] = {
        ["alg"] = "HS256"
    }, 
    payload = {
        ["iat"] = 1643673600, 
        ["data"] = "Valid JWT with data"
    }
}
```

> The function: `jwt.DefaultTable()` is an easy way to get a basic JWT table


Using the `jwtTable` with `JWT.Encode` a JWT string is created

```lua
local serverSecret = "SuperSecretKey"
local token = jwt.Encode(jwtTable, serverSecret) 

print(token)
```
Console output:
```
eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoiVmFsaWQgSldUIHdpdGggZGF0YSIsImlhdCI6MTY0MzY3MzYwMH0.x1S6pFtQEpBYaAt-eKrRXKQQAQR-HGE1uPRrhIPtP20
```

It can be verified that this token contains the data we expect by pasting it into [jwt.io](https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoiVmFsaWQgSldUIHdpdGggZGF0YSIsImlhdCI6MTY0MzY3MzYwMH0.x1S6pFtQEpBYaAt-eKrRXKQQAQR-HGE1uPRrhIPtP20)

The created token can also be decoded by `jwt.Decode`.  
However this does not verify the data by recreating the signature.

To also verify the signature `jwt.DecodeAndVerify` should be used.
```lua
-- token and serverSecret defined in example above
local decodedTable = jwt.DecodeAndVerify(token, serverSecret)

print(decodedTable.payload.data)
```
Console output:
```
Valid JWT with data
```

##### More about JWT
[jwt.io/introduction](https://jwt.io/introduction) <!-- archive.ph/djKJg -->
