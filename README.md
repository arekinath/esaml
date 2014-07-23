An implementation of the Security Assertion Markup Language (SAML) in Erlang. So far this supports enough of the standard to act as a Service Provider (SP) to perform authentication with SAML. It has been tested extensively against the SimpleSAMLPHP IdP and can be used in production.

## Supported protocols

The SAML standard refers to a flow of request/responses that make up one concrete action as a "protocol". Currently all of the basic Single-Sign-On and Single-Logout protocols are supported. There is no support at present for the optional Artifact Resolution, NameID Management, or NameID Mapping protocols.

Future work may add support for the Assertion Query protocol (which is useful to check if SSO is already available for a user without demanding they authenticate immediately).

Single sign-on protocols:

 * SP: send AuthnRequest (REDIRECT or POST) -> receive Response + Assertion (POST)

Single log-out protocols:

 * SP: send LogoutRequest (REDIRECT) -> receive LogoutResponse (REDIRECT or POST)
 * SP: receive LogoutRequest (REDIRECT OR POST) -> send LogoutResponse (REDIRECT)

esaml supports RSA+SHA1 signing of all SP payloads, and validates signatures on all IdP responses. Compatibility flags are available to disable verification where IdP implementations lack support (see the [esaml_sp record](http://arekinath.github.io/esaml/esaml.html#type-sp), and members such as `idp_signs_logout_requests`).

## API documentation

Edoc documentation for the whole API is available at:

http://arekinath.github.io/esaml/

## Using esaml

The simplest way to use esaml in your app is with the `esaml_cowboy` module. There is an example under `examples/sp` that shows how to make a simple SAML SP in this way.

Each of the protocols you wish to support will normally require at least one distinct URL endpoint, plus one additional URL for the SAML SP metadata. In the `sp` example, only one protocol is used: the single-sign-on SP AuthnRequest -> Response + Assertion protocol.

The typical approach is to use a single Cowboy route for all SAML endpoints:

    Dispatch = cowboy_router:compile([
        {'_', [
            {"/saml/:operation", sp_handler, []}
        ]}
    ])

Then, based on the value of the `operation` binding, you can decide which protocol to proceed with, by matching these up with the URIs you supply to `esaml_sp:setup/1`.

    init(_Transport, Req, _Args) ->
        ...
        SP = esaml_sp:setup(#esaml_sp{
            consume_uri = Base ++ "/consume",
            metadata_uri = Base ++ "/metadata",
            ...
        }),
        ...

    handle(Req, S = #state{}) ->
        {Operation, Req2} = cowboy_req:binding(operation, Req),
        {Method, Req3} = cowboy_req:method(Req2),
        handle(Method, Operation, Req3, S).

    handle(<<"GET">>, <<"metadata">>, Req, S) ->
        ...

    handle(<<"POST">>, <<"consume">>, Req, S) ->
        ...

The functions on the `esaml_cowboy` module can either parse and validate an incoming SAML payload, or generate one and reply to the request with it.

For example, the way the metadata endpoint is handled in the example is to unconditionally call `esaml_cowboy:reply_with_metadata/2`, which generates the SP metadata and replies to the request:

    handle(<<"GET">>, <<"metadata">>, Req, S = #state{sp = SP}) ->
        {ok, Req2} = esaml_cowboy:reply_with_metadata(SP, Req),
        {ok, Req2, S};

On the other hand, the consumer endpoint (which handles the second step in the SSO protocol, receiving the Response + Assertion from the IdP) has to validate its payload before replying:

    handle(<<"POST">>, <<"consume">>, Req, S = #state{sp = SP}) ->
        case esaml_cowboy:validate_assertion(SP, Req) of
            {ok, Assertion, RelayState, Req2} ->
                % authentication success!
                ...;

            {error, Reason, Req2} ->
                {ok, Req3} = cowboy_req:reply(403, [{<<"content-type">>, <<"text/plain">>}],
                    ["Access denied, assertion failed validation\n"], Req2),
                {ok, Req3, S}
        end;

More complex configurations, including multiple IdPs, dynamic retrieval of IdP metadata, and integration with many kinds of application authentication systems are possible.

The second esaml example, `sp_with_logout` demonstrates the addition endpoints necessary to enable Single Log-out protocol support. It also shows how you can build a bridge from esaml to local application session storage, by generating session cookies for each user that logs in (and storing them in ETS).

