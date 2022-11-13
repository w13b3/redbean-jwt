# redbean-jwt  <sub><sup>_JSON Web Token for redbean_<sup><sub>

[![jwt.io badge-compatible](https://jwt.io/img/badge-compatible.svg)](https://jwt.io/)
##### Compatible algorithms
`none`, `HS256`, `HS384` and `HS512`

### What is JSON Web Token?
> JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object.  
> This information can be verified and trusted because it is digitally signed.  
> JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA or ECDSA.  
> _source: [jwt.io/introduction][1]_  

### How to use
Read the [documentation](./doc/)  

### Notes
`jwt.lua` is possible because [redbean][2] 2.0.11 introduced `EncodeJson` and `DecodeJson`.  
Previous versions did not have these functions.  
If `jwt.lua` is needed for a previous version, a bit of work is required to make `jwt.lua` compatible.  
`json.stringify` and `json.parse` in [this gist][3] can be used in place of `EncodeJson` and `DecodeJson`.  

Consider the header & payload to be unencrypted and visible for the whole world.  
So it is recommended not to use it for unencrypted credentials/personal data.  

[`GetCryptoHash`][4] is used to create the JWT signature segment.  
As of writing this, the function expects one of the following strings:  
`MD5`, `SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, `BLAKE2B256`.  
The `SHA256`, `SHA384`, `SHA512` are equal to `HS256`, `HS384`, `HS512`.  
For compatibility’s sake the received HS algo's are renamed to SHA counterpart by a lookup table.  
It is possible to use the other algorithms in a JWT, but this breaks compatibility.  

### More awesome projects
Check out this collection with [awesome-cosmopolitan][5] projects  


[1]: https://jwt.io/introduction
  <!-- archive.ph/djKJg -->

[2]: https://redbean.dev 
  <!-- archive.ph/xZPJX -->

[3]: https://gist.github.com/tylerneylon/59f4bcf316be525b30ab "tylerneylon"
  <!-- archive.ph/5leC3 -->

[4]: https://redbean.dev/#GetCryptoHash "redbean.dev"
[5]: https://github.com/shmup/awesome-cosmopolitan "shmup"
  <!-- archive.ph/nC7QT -->