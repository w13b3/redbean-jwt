# Functions  <sub><sup>_A list of functions_<sup><sub>

---

## JWA

> ```lua
> jwa = require("jwt")._JWA
> ```  

### JWA Public

#### `jwa.default`  

_**The default algorithm is `HS256`**_  

#### `jwa.supported`  

_**Table with supported algorithms**_  

#### `jwa.lookup`  

_**Lookup table to convert algorithms to it's equivalent name to be used in `GetCryptoHash`**    

### JWA Private

#### `jwa.CheckHash(message, signature, key, algorithms)`

_**Check the signature by hashing the message with multiple algorithms**_  
param `message` type: `string` The payload that was encrypted  
param `signature` type: `string` The received decoded signature  
param `key` type: `string` The secret which was used to hash the payload  
param `algorithms` type: `table` The allowed algorithms  
return type: `boolean`, `string` If the hashed message matches the signature, returned string is the algorithm used  
return type: `nil`, `string` When no match is found  


---


## JWS  

> ```lua
> jws = require("jwt")._JWS
> ```  

### JWS Public  

#### `jws.splitTokenRegex`  

_**Compiled regex to split a JWS token**_  

#### `jws.BasicTable()`  

_**Create a basic table which can be used in `jwt.Encode`**_  
return type: `table`  

### JWS Private  

#### `jws.Encode(jwtTable, key, alg)`  

_**Encode JSON that has header and payload keys**_  
param `jwtTable` type: `table` Header and payload of the JWS in a table  
param `key` type: `string` Secret of the server  
param `algorithm` type: `string` If given it overrides the alg-value given in the JWS-header  
return type: `string` JWT string  

#### `jws.Decode(data)`

_**Decodes the given JWS string to a table**_  
param `data` type: `string` JWS string  
return `table` Table with data from the decoded JWS  

#### `jws.VerifyTable(jwtTable, key, alg)`

_**Verify signature of a decoded JWS table**_  
param `jwtTable` type: `table` Preferably received from `jws.Decode` function  
param `key` type: `string` Secret of the server  
param `algorithms` type: `table` A Table algorithm strings that are accepted to use  
return `table` Table with JWS parts  

#### `jws.DecodeAndVerify(data, key)`

_**Decode the JWS and verify the signature**_  
param `data` type: `string` JWS string  
param `key` type: `string` Secret of the server  
param `algorithms` type: `table` A Table algorithm strings that are accepted to use  
return `table` Table with data from the decoded JWS  


---


## JWT  

> ```lua
> jwt = require("jwt")
> ```  

### JWT Public  

#### `jwt.Encode(jwtTable, key, alg)`  

_**Encode JSON that has header and payload keys**_  
param `jwtTable` type: `table` Header and payload of the JWT in a table  
param `key` type: `string` Secret of the server  
param `algorithm` type: `string` If given it overrides the alg-value given in the JWT-header  
return `string` JWT string  
return `nil`, `string` When error occurs  

#### `jwt.Decode(data)`  

_**Decodes the given JWT string to a table**_  
param `data` type: `string` JWT string  
return `table` Table with data from the decoded JWT  
return `nil`, `string` When error occurs  

#### `jwt.VerifyTable(jwtTable, key, alg)`

_**Verify signature of a decoded JWT table**_  
param `jwtTable` type: `table` Preferably received from `jwt.Decode` function  
param `key` type: `string` Secret of the server  
param `algorithms` type: `table` A Table algorithm strings that are accepted to use  
return `table` Table with JWT parts  
return `nil`, `string` When error occurs  

#### `jwt.DecodeAndVerify(data, key)`

_**Decode the JWT and verify the signature**_  
param `data` type: `string` JWT string  
param `key` type: `string` Secret of the server  
param `algorithms` type: `table` A Table algorithm strings that are accepted to use  
return type: `table` Table with data from the decoded JWT  
return type: `nil`, `string` When error occurs  

#### `jwt.SetCookieToken(jwtTable, key, alg, cookieOptions)`

_**Set a cookie with a token**_  
param `jwtTable` type: `table` Header and payload of the JWT in a table  
param `key` type: `string` Secret of the server  
param `algorithm` type: `string` If given it overrides the alg-value given in the JWT-header  
param `cookieOptions` type: `table` Optional cookie options  
return type: `boolean` True if no error has occurred  
return type: `nil`, `string` When error occurs  

#### `jwt.VerifyCookieToken(key, data, cookieName)`

_**Verify a cookie containing the token**_  
param `key` type: `string` Secret of the server  
param `data` type: `string` Optional verifies given data instead of cookie  
param `algorithms` type: `table` A Table algorithm strings that are accepted to use  
param `cookieName` type: `table` Optional custom cookie name  
return type: `table` Table with data from the decoded JWT  
return type: `nil`, `string` When error occurs  


#### `jwt.SetHeaderToken(jwtTable, key, alg)`

_**Set an Authorization header with a JWT Bearer token**_  
param `jwtTable` type: `table` Header and payload of the JWT in a table  
param `key` type: `string` Secret of the server  
param `algorithm` type: `string` If given it overrides the alg-value given in the JWT-header  
return type: `boolean` True if no error has occurred  
return type: `nil`, `string` When error occurs  


#### `jwt.VerifyHeaderToken(key, data)`

_**Verify the Authorization header containing a JWT Bearer token**_  
param `key` type: `string` Secret of the server  
param `data` type: `string` Optional verifies given data instead of header  
param `algorithms` type: `table` A Table algorithm strings that are accepted to use  
return type: `table` Table with data from the decoded JWT  
return type: `nil`, `string` When error occurs  


---


## Common

> ```lua
> common = require("jwt")._Common
> ```  

## Private functions

#### `common.EncodeBase64URL(str)`

_**Base64URL is a modification of the main Base64 standard**_  
param `str` type: `string`  
return type: `string`  


#### `common.DecodeBase64URL(str)`

_**Base64URL is a modification of the main Base64 standard**_  
param `str` type: `string`  
return type: `string`  

#### `common.EncodeSegment(segmentObject)`

_**Encode a segment to a base64URL encoded string**_  
param `segmentObject` type: `JsonValue` Commonly a table or a string  
return type: `string` Base64URL encoded string  

#### `common.DecodeSegment(base64Segment)`

_**Decode a base64URL encoded string to the original segment**_  
param `base64Segment` type: `string` Base64URL encoded string  
return type: `JsonValue`  
