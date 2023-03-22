// jwt_handler.smithy
// A simple service that calculates the factorial of a whole number


// Tell the code generator how to reference symbols defined in this namespace
metadata package = [ { namespace: "com.michaelrademeyer.interfaces.jwt_handler", crate: "jwt_provider" } ]

namespace com.michaelrademeyer.interfaces.jwt_handler

use org.wasmcloud.model#wasmbus
use org.wasmcloud.model#U32
use org.wasmcloud.model#U64

/// The JwtHandler service has a single method, calculate, which
/// calculates the factorial of its whole number parameter.
@wasmbus(
    contractId: "michaelrademeyer:interfaces:jwt_handler",
    providerReceive: true )
service JwtHandler {
  version: "0.1",
  operations: [ GenerateJwt, ValidateJwt, GetJwtValues, IsTokenExpired ]
}

structure User {
  @required
  id: String,
  username: String,
  @required
  email: String,
  @required
  createdAt: Timestamp,
  @required
  updatedAt: Timestamp,
  firstName: String,
  lastName: String
}

map ClaimMap {
    key: String,
    value: String
}

operation GenerateJwt {
    input: User
    output: String
}

operation ValidateJwt {
    input: String
    output: Boolean
}

operation GetJwtValues {
    input: String
    output: ClaimMap
}

operation IsTokenExpired {
    input: String
    output: Boolean
}