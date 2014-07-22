%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(esaml_sp).

-include("esaml.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-export([setup/1, generate_authn_request/2, generate_metadata/1]).
-export([validate_assertion/2, validate_assertion/3]).

%% @doc Return an AuthnRequest as an XML element
-spec generate_authn_request(IdpURL :: string(), #esaml_sp{}) -> #xmlElement{}.
generate_authn_request(IdpURL, SP = #esaml_sp{metadata_uri = MetaURI, consume_uri = ConsumeURI}) ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    Stamp = esaml_util:datetime_to_saml(Now),

    Xml = esaml:to_xml(#esaml_authnreq{issue_instant = Stamp,
                                       destination = IdpURL,
                                       issuer = MetaURI,
                                       consumer_location = ConsumeURI}),
    if SP#esaml_sp.sp_sign_requests ->
        xmerl_dsig:sign(Xml, SP#esaml_sp.key, SP#esaml_sp.certificate);
    true ->
        Xml
    end.

%% @doc Return the SP metadata as an XML element
-spec generate_metadata(#esaml_sp{}) -> #xmlElement{}.
generate_metadata(SP = #esaml_sp{org = Org, tech = Tech}) ->
    Xml = esaml:to_xml(#esaml_sp_metadata{
        org = Org,
        tech = Tech,
        signed_requests = SP#esaml_sp.sp_sign_requests,
        signed_assertions = SP#esaml_sp.idp_signs_assertions or SP#esaml_sp.idp_signs_envelopes,
        certificate = SP#esaml_sp.certificate,
        consumer_location = SP#esaml_sp.consume_uri,
        logout_location = SP#esaml_sp.logout_uri,
        entity_id = SP#esaml_sp.metadata_uri}),
    if SP#esaml_sp.sp_sign_metadata ->
        xmerl_dsig:sign(Xml, SP#esaml_sp.key, SP#esaml_sp.certificate);
    true ->
        Xml
    end.

%% @doc Initialize and validate an esaml_sp record
-spec setup(#esaml_sp{}) -> #esaml_sp{}.
setup(SP = #esaml_sp{trusted_fingerprints = FPs, metadata_uri = MetaURI,
                     consume_uri = ConsumeURI, logout_uri = LogoutURI}) ->
    FPSources = FPs ++ esaml:config(trusted_fingerprints, []),
    Fingerprints = lists:map(fun(Print) ->
        if is_list(Print) ->
            Parts = string:tokens(Print, ":"),
            list_to_binary(lists:map(fun(P) -> list_to_integer(P, 16) end, Parts));
        is_binary(Print) ->
            Print;
        true ->
            error("unknown fingerprint format")
        end
    end, FPSources),
    case MetaURI of undefined -> error("must specify metadata URI"); _ -> ok end,
    case ConsumeURI of undefined -> error("must specify consume URI"); _ -> ok end,
    case LogoutURI of undefined -> error("must specify logout URI"); _ -> ok end,
    if (SP#esaml_sp.key =:= undefined) andalso (SP#esaml_sp.sp_sign_requests) ->
        error("must specify a key to sign requests");
    true -> ok
    end,
    if (not (SP#esaml_sp.key =:= undefined)) and (not (SP#esaml_sp.certificate =:= undefined)) ->
        SP#esaml_sp{sp_sign_requests = true, sp_sign_metadata = true, trusted_fingerprints = Fingerprints};
    true ->
        SP#esaml_sp{trusted_fingerprints = Fingerprints}
    end.

%% @doc Validate and decode an assertion envelope in parsed XML
-spec validate_assertion(Xml :: #xmlElement{} | #xmlDocument{}, #esaml_sp{}) -> {ok, Assertion :: #esaml_assertion{}} | {error, Reason :: term()}.
validate_assertion(Xml, SP = #esaml_sp{}) ->
    validate_assertion(Xml, fun(_A, _Digest) -> ok end, SP).

-spec validate_assertion(Xml :: #xmlElement{} | #xmlDocument{}, DuplicateFun :: fun(), #esaml_sp{}) -> {ok, Assertion :: #esaml_assertion{}} | {error, Reason :: term()}.
validate_assertion(Xml, DuplicateFun, SP = #esaml_sp{}) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        fun(X) ->
            case xmerl_xpath:string("/samlp:Response/saml:Assertion", X, [{namespace, Ns}]) of
                [A] -> A;
                _ -> {error, bad_assertion}
            end
        end,
        fun(A) ->
            if SP#esaml_sp.idp_signs_envelopes ->
                case xmerl_dsig:verify(Xml, SP#esaml_sp.trusted_fingerprints) of
                    ok -> A;
                    OuterError -> {error, {envelope, OuterError}}
                end;
            true -> A
            end
        end,
        fun(A) ->
            if SP#esaml_sp.idp_signs_assertions ->
                case xmerl_dsig:verify(A, SP#esaml_sp.trusted_fingerprints) of
                    ok -> A;
                    InnerError -> {error, {assertion, InnerError}}
                end;
            true -> A
            end
        end,
        fun(A) ->
            case esaml:validate_assertion(A, SP#esaml_sp.consume_uri, SP#esaml_sp.metadata_uri) of
                {ok, AR} -> AR;
                {error, Reason} -> {error, Reason}
            end
        end,
        fun(AR) ->
            case DuplicateFun(AR, xmerl_dsig:digest(Xml)) of
                ok -> AR;
                _ -> {error, duplicate}
            end
        end
    ], Xml).
