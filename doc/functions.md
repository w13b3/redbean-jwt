# Functions  <sub><sup>_A list of functions_<sup><sub>

## Public functions

### `jwt.BasicTable()`

Create a basic table  
return type: `table`


### `jwt.Encode(jwtTable, key, alg)`

Encode JSON that has header and payload keys  
param `jwtTable` type: `table`  
param `key` type: `string`  
optional param `alg` type: `string`  
return type: `string` - JWT string  
return type: `nil`, `string` - When error occurs


### `jwt.Decode(data)`

Decodes the given JWT string to a table, does not verify the JWT  
param `data` type: `string`  
return type: `table` - table with JWT parts  
return type: `nil`, `string` - When error occurs


### `jwt.VerifyTable(jwtTable, key, alg)`

Verify signature of a decoded JWT table  
param `jwtTable` type: `table`  
param `key` type: `string`  
optional param `alg` type: `string`  
return type: `table` - Table with JWT parts  
return type: `nil`, `string` - When error occurs


### `jwt.DecodeAndVerify(data, key)`

Decode the JWT and verify the signature  
param `data` type: `string`  
param `key` type: `string`  
return type: `table` - Table with JWT parts  
return type: `nil`, `string` - When error occurs


### `jwt.SetCookieToken(jwtTable, key, alg, cookieOptions)`

Set a cookie with a token  
param `jwtTable` type: `table`  
param `key` type: `string`  
optional param `alg` type: `string`  
optional param `cookieOptions` type: `table`  
return type: `boolean` - if no error has occurred  
return type: `nil`, `string` - When error occurs


### `jwt.VerifyCookieToken(key, data, cookieName)`

Verify a cookie containing the token  
param `key` type: `string`  
optional param `data` type: `string`  
optional param `cookieName` type: `string`  
return type: `table` - Table with JWT parts  
return type: `nil`, `string` - When error occurs


### `jwt.SetHeaderToken(jwtTable, key, alg)`

Set an Authorization header with a JWT Bearer token  
param `jwtTable` type: `table`  
param `key` type: `string`  
optional param `alg` type: `string`  
return type: `boolean` - if no error has occurred  
return type: `nil`, `string` - When error occurs


### `jwt.VerifyHeaderToken(key, data)`

Verify the Authorization header containing a JWT Bearer token  
param `key` type: `string`  
optional param `data` type: `string`  
return type: `table` - Table with JWT parts  
return type: `nil`, `string` - When error occurs


## Private functions


### `jwt.EncodeBase64URL(str)`

Base64URL is a modification of the main Base64 standard  
param `str` type: `string`  
return type: `string`


### `jwt.DecodeBase64URL(str)`

Base64URL is a modification of the main Base64 standard  
param `str` type: `string`  
return type: `string`


### `jwt.Split(data)`

Split the JWT and return the separate segments  
param `data` type: `string`   
return type: `boolean`, `string`, `string`, `string` - If given data is of valid structure  
return type: `boolean`, `string` - False is returned if invalid data has an invalid structure


### `jwt.DecodeParts(headerBase64, payloadBase64, signatureBase64)`

Decode the split up Base64URL strings  
param `headerBase64` type: `string`  
param `payloadBase64` type: `string`  
param `signatureBase64` type: `string`  
return type: `table` - Table with header, payload tables and decoded signature
