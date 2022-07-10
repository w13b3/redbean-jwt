# red-jwt  <sub><sup>_JSON Web Token for redbean_<sup><sub>

[![jwt.io badge-compatible](https://jwt.io/img/badge-compatible.svg)](https://jwt.io/)
##### Compatible algorithms
`HS256`, `HS384` and `HS512`

### What is JSON Web Token?
> JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object.  
> This information can be verified and trusted because it is digitally signed.  
> JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA or ECDSA.  
> _source: [jwt.io/introduction](https://jwt.io/introduction)_

### How to use

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


### Notes
`jwt.lua` is possible because redbean 2.0.11 introduced `EncodeJson` and `DecodeJson`.  
Previous versions did not have these functions.  
If `jwt.lua` is needed for a previous version, a bit of work is required to make `jwt.lua` compatible.  
`json.stringify` and `json.parse` in [this gist](https://gist.github.com/tylerneylon/59f4bcf316be525b30ab) can be used in place of `EncodeJson` and `DecodeJson`.  

Consider the header & payload to be unencrypted and visible for the whole world.  
So it is recommended not to use it for unencrypted credentials/personal data. 

[`GetCryptoHash`](https://redbean.dev/#GetCryptoHash) is used to create the JWT signature segment.  
As of writing this, the function expects one of the following strings:   
`MD5`, `SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, `BLAKE2B256`.  
The `SHA256`, `SHA384`, `SHA512` are equal to `HS256`, `HS384`, `HS512`.    
For compatibility’s sake the received HS algo's are renamed to SHA counterpart by a lookup table.  
The strings expected by `GetCryptoHash` can also be used but this breaks compatibility.
