An implementation of the Security Assertion Markup Language (SAML) in Erlang. So far this supports enough of the standard to act as a Service Provider (SP) to perform authentication with SAML. It has been tested extensively against the SimpleSAMLPHP IDP and can be used in production.

IDP functionality is planned to be added in the future.

# Using esaml

To use esaml in a cowboy app you need to do three things:

1. Add the /saml/[...] route to esaml_cowboy_handler in your cowboy_router config
2. Write a callback module that implements the esaml_sp behaviour
3. Supply appropriate configuration to esaml, either via app.config or through the cowboy_router config

TODO: more documentation and stuff
