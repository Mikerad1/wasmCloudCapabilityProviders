# wasmCloudCapabilityProviders
A collection of capability providers that can be used for wasmCloud

# JWT Handler Provider
This provider will generate, verify, get values and check the expiration of a jwt token. 
It takes 3 link values:
1. secret - This is the secret to use when generating and verifying the JWT token
2. issuer - This is the issuer of the token
3. expiration - This is how long (in seconds) a token should be valid for
