%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc Convenience functions for use with Cowboy handlers
%%
%% This module makes it easier to use esaml in your Cowboy-based web
%% application, by providing easy wrappers around the functions in 
%% esaml_binding and esaml_sp.
-module(esaml_cowboy).

-include_lib("xmerl/include/xmerl.hrl").
-include("esaml.hrl").

-export([reply_with_authnreq/4, reply_with_metadata/2, reply_with_logoutreq/4, reply_with_logoutresp/5]).
-export([validate_assertion/2, validate_assertion/3, validate_logout/2]).

-type uri() :: string().

%% @doc Reply to a Cowboy request with an AuthnRequest payload
%%
%% RelayState is an arbitrary blob up to 80 bytes long that will
%% be returned verbatim with any assertion that results from this
%% AuthnRequest.
-spec reply_with_authnreq(SP :: esaml:sp(), IdPSSOEndpoint :: uri(), RelayState :: binary(), Req) -> {ok, Req}.
reply_with_authnreq(SP, IDP, RelayState, Req) ->
    SignedXml = SP:generate_authn_request(IDP),
    reply_with_req(IDP, SignedXml, RelayState, Req).

%% @doc Reply to a Cowboy request with a LogoutRequest payload
%%
%% NameID should be the exact subject name from the assertion you
%% wish to log out.
-spec reply_with_logoutreq(SP :: esaml:sp(), IdPSLOEndpoint :: uri(), NameID :: string(), Req) -> {ok, Req}.
reply_with_logoutreq(SP, IDP, NameID, Req) ->
    SignedXml = SP:generate_logout_request(IDP, NameID),
    reply_with_req(IDP, SignedXml, <<>>, Req).

%% @doc Reply to a Cowboy request with a LogoutResponse payload
%%
%% Be sure to keep the RelayState from the original LogoutRequest that you
%% received to allow the IdP to keep state.
-spec reply_with_logoutresp(SP :: esaml:sp(), IdPSLOEndpoint :: uri(), Status :: esaml:status_code(), RelayState :: binary(), Req) -> {ok, Req}.
reply_with_logoutresp(SP, IDP, Status, RelayState, Req) ->
    SignedXml = SP:generate_logout_response(IDP, Status),
    reply_with_req(IDP, SignedXml, RelayState, Req).

%% @private
reply_with_req(IDP, SignedXml, RelayState, Req) ->
    Target = esaml_binding:encode_http_redirect(IDP, SignedXml, RelayState),
    {UA, _} = cowboy_req:header(<<"user-agent">>, Req, <<"">>),
    IsIE = not (binary:match(UA, <<"MSIE">>) =:= nomatch),
    if IsIE andalso (byte_size(Target) > 2042) ->
        Html = esaml_binding:encode_http_post(IDP, SignedXml, RelayState),
        cowboy_req:reply(200, [
            {<<"Cache-Control">>, <<"no-cache">>},
            {<<"Pragma">>, <<"no-cache">>}
        ], Html, Req);
    true ->
        cowboy_req:reply(302, [
            {<<"Cache-Control">>, <<"no-cache">>},
            {<<"Pragma">>, <<"no-cache">>},
            {<<"Location">>, Target}
        ], <<"Redirecting...">>, Req)
    end.

%% @doc Validate and parse a LogoutRequest or LogoutResponse
%%
%% This function handles both REDIRECT and POST bindings.
-spec validate_logout(SP :: esaml:sp(), Req) -> 
        {request, esaml:logoutreq(), RelayState::binary(), Req} | 
        {response, esaml:logoutresp(), RelayState::binary(), Req} | 
        {error, Reason :: term(), Req}.
validate_logout(SP, Req) ->
    {Method, Req} = cowboy_req:method(Req),
    case Method of
        <<"POST">> ->
            {ok, PostVals, Req2} = cowboy_req:body_qs(Req, [{length, 128000}]),
            SAMLEncoding = proplists:get_value(<<"SAMLEncoding">>, PostVals),
            SAMLResponse = proplists:get_value(<<"SAMLResponse">>, PostVals,
                proplists:get_value(<<"SAMLRequest">>, PostVals)),
            RelayState = proplists:get_value(<<"RelayState">>, PostVals, <<>>),
            validate_logout(SP, SAMLEncoding, SAMLResponse, RelayState, Req2);
        <<"GET">> ->
            {SAMLEncoding, Req2} = cowboy_req:qs_val(<<"SAMLEncoding">>, Req),
            {SAMLResponse, Req2} = case cowboy_req:qs_val(<<"SAMLResponse">>, Req2) of
                {undefined, Req2} -> cowboy_req:qs_val(<<"SAMLRequest">>, Req2);
                Other -> Other
            end,
            RelayState = case cowboy_req:qs_val(<<"RelayState">>, Req2) of
                {undefined, Req2} -> <<>>;
                {B, Req2} -> B
            end,
            validate_logout(SP, SAMLEncoding, SAMLResponse, RelayState, Req2)
    end.

%% @private
validate_logout(SP, SAMLEncoding, SAMLResponse, RelayState, Req2) ->
    case (catch esaml_binding:decode_response(SAMLEncoding, SAMLResponse)) of
        {'EXIT', Reason} ->
            {error, {bad_decode, Reason}, Req2};
        Xml ->
            Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
                  {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
            case xmerl_xpath:string("/samlp:LogoutRequest", Xml, [{namespace, Ns}]) of
                [#xmlElement{}] ->
                    case SP:validate_logout_request(Xml) of
                        {ok, Reqq} -> {request, Reqq, RelayState, Req2};
                        Err -> Err
                    end;
                _ ->
                    case SP:validate_logout_response(Xml) of
                        {ok, Resp} -> {response, Resp, RelayState, Req2};
                        Err -> Err
                    end
            end
    end.

%% @doc Reply to a Cowboy request with a Metadata payload
-spec reply_with_metadata(SP :: esaml:sp(), Req) -> {ok, Req}.
reply_with_metadata(SP, Req) ->
    SignedXml = SP:generate_metadata(),
    Metadata = xmerl:export([SignedXml], xmerl_xml),
    cowboy_req:reply(200, [{<<"Content-Type">>, <<"text/xml">>}], Metadata, Req).

%% @doc Validate and parse an Assertion inside a SAMLResponse
%%
%% This function handles only POST bindings.
-spec validate_assertion(SP :: esaml:sp(), Req) -> 
        {ok, Assertion :: esaml:assertion(), RelayState :: binary(), Req} | 
        {error, Reason :: term(), Req}.
validate_assertion(SP, Req) ->
    validate_assertion(SP, fun(_A, _Digest) -> ok end, Req).

%% @doc Validate and parse an Assertion with duplicate detection
%%
%% This function handles only POST bindings.
%%
%% For the signature of DuplicateFun, see esaml_sp:validate_assertion/3
-spec validate_assertion(SP :: esaml:sp(), DuplicateFun :: fun(), Req) -> 
        {ok, Assertion :: esaml:assertion(), RelayState :: binary(), Req} | 
        {error, Reason :: term(), Req}.
validate_assertion(SP, DuplicateFun, Req) ->
    {ok, PostVals, Req2} = cowboy_req:body_qs(Req, [{length, 128000}]),
    SAMLEncoding = proplists:get_value(<<"SAMLEncoding">>, PostVals),
    SAMLResponse = proplists:get_value(<<"SAMLResponse">>, PostVals),
    RelayState = proplists:get_value(<<"RelayState">>, PostVals),

    case (catch esaml_binding:decode_response(SAMLEncoding, SAMLResponse)) of
        {'EXIT', Reason} ->
            {error, {bad_decode, Reason}, Req2};
        Xml ->
            case SP:validate_assertion(Xml, DuplicateFun) of
                {ok, A} -> {ok, A, RelayState, Req2};
                {error, E} -> {error, E, Req2}
            end
    end.


