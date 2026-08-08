// Package additionalfields ports single-auth 1.6.26's server-side
// additionalFields contract.
//
// single-auth does not implement additional fields as an independent server
// plugin. The feature is composed through the core schema, input parsers,
// adapter transforms, endpoint handlers, cookie cache, and secondary session
// storage. This package exposes that contract as an engine.Plugin without
// coupling it to either net/http or fasthttp.
//
// The returned plugin contributes field metadata to the host schema and runs
// the create/update request parser for signUpEmail, updateUser, and
// updateSession. single-auth's root runtime consumes the contributed schema for
// database defaults and transforms, returned:false filtering, cookie-cache
// serialization, and secondary-storage session propagation. Therefore no
// adapter or secondary-storage handle is duplicated in Runtime. Integrations
// that create users, accounts, or sessions outside the built-in endpoints can
// retain the same behavior by keeping the Processor returned by Compile and
// calling its parsing helpers before their own persistence operation.
package additionalfields
