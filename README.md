An implementation of the Security Assertion Markup Language (SAML) in Erlang. So far this supports enough of the standard to act as a Service Provider (SP) to perform authentication with SAML. It has been tested extensively against the SimpleSAMLPHP IDP and can be used in production.

IdP functionality is planned to be added in the future.

# Using esaml

The simplest way to use esaml in your app is with the `esaml_cowboy` module. There is an example under `examples/sp` that shows how to make a simple SAML SP in this way.

TODO: more documentation
