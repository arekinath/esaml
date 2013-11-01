%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(esaml_cowboy_handler).
-behaviour(cowboy_http_handler).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("esaml.hrl").

-export([init/3, handle/2, get/3, post/3, terminate/3]).

-record(state, {idp_target, sp, max_saml_response_size}).

init(_Transport, Req, Options) ->
    PrivKey = case proplists:get_value(sp_private_key, Options, esaml:config(sp_private_key)) of
        undefined -> none;
        PrivKeyPath -> esaml_util:load_private_key(PrivKeyPath)
    end,
    Cert = case proplists:get_value(sp_certificate, Options, esaml:config(sp_certificate)) of
        undefined -> none;
        CertPath -> esaml_util:load_certificate(CertPath)
    end,
    Tech = proplists:get_value(tech_contact, Options, esaml:config(tech_contact, [{name, "undefined"}, {email, "undefined"}])),

    GetUriFromOptions =
        fun(OptionName, DefaultPostfix) ->
                case proplists:get_value(OptionName, Options) of
                    undefined ->
                        proplists:get_value(base_uri, Options) ++ "/" ++ DefaultPostfix;
                    Value ->
                        Value
                end
        end,

    {ok, Req, #state{
        idp_target = proplists:get_value(idp_sso_target, Options, esaml:config(idp_sso_target)),
        max_saml_response_size = proplists:get_value(max_saml_response_size, Options, infinity),
        sp = esaml_sp:setup(#esaml_sp{
            module = proplists:get_value(module, Options, esaml_sp_default),
            modargs = proplists:get_value(modargs, Options, []),
            key = PrivKey,
            certificate = Cert,
            trusted_fingerprints = proplists:get_value(trusted_fingerprints, Options, []),
            consume_uri = GetUriFromOptions(consume_uri, "consume"),
            metadata_uri = GetUriFromOptions(metadata_uri, "metadata"),
            org = #esaml_org{
                name = proplists:get_value(org_name, Options, esaml:config(org_name, "undefined")),
                displayname = proplists:get_value(org_displayname, Options, esaml:config(org_displayname, "undefined")),
                url = proplists:get_value(org_url, Options, esaml:config(org_url, "undefined"))
            },
            tech = #esaml_contact{
                name = proplists:get_value(name, Tech),
                email = proplists:get_value(email, Tech)
            }
        })
    }}.

terminate(_Reason, _Req, _State) ->
    ok.

handle(Req, State) ->
    {Method, Req2} = cowboy_req:method(Req),
    {Operation, Req3} = cowboy_req:binding(operation, Req2),
    MethodAtom = list_to_atom(string:to_lower(binary_to_list(Method))),
    {ok, Req4} = apply(?MODULE, MethodAtom, [Operation, Req3, State]),
    {ok, Req4, State}.

decode_saml_response(PostVals) ->
    case (catch begin
        Resp = proplists:get_value(<<"SAMLResponse">>, PostVals),
        XmlData = case proplists:get_value(<<"SAMLEncoding">>, PostVals) of
            <<"urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE">> ->
                binary_to_list(zlib:unzip(base64:decode(Resp)));
            _ ->
                base64:decode_to_string(Resp)
        end,
        {Xml, _} = xmerl_scan:string(XmlData, [{namespace_conformant, true}]),
        Xml
    end) of
        {'EXIT', Reason} ->
            {error, Reason};
        Other ->
            Other
    end.

post(<<"consume">>, Req, #state{max_saml_response_size = MaxSamlResponseSize,
        sp = SP}) ->
    {ok, PostVals, Req2} = cowboy_req:body_qs(MaxSamlResponseSize, Req),

    case decode_saml_response(PostVals) of
        {error, Reason} ->
            error_logger:warning_msg("Failed to decode SAMLResponse value:\n  ~p\n  req = ~p\n", [Reason, Req2]),
            cowboy_req:reply(403, [], <<"Failed to decode SAMLResponse value">>, Req2);
        Xml ->
            case SP:consume(Xml, Req2) of
                {ok, Req3} ->
                    {ok, Req3};
                {error, Reason} ->
                    error_logger:warning_msg("Rejected SAML assertion for reason:\n  ~p\n  req = ~p\n", [Reason, Req2]),
                    cowboy_req:reply(403, [], <<"Invalid SAML assertion">>, Req2)
            end
    end;

post(_, Req, _) ->
    cowboy_req:reply(404, [], <<>>, Req).

generate_post_html(Dest, Req) ->
    <<"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">
<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">
<head>
<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\" />
<title>POST data</title>
</head>
<body onload=\"document.forms[0].submit()\">
<noscript>
<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>
</noscript>
<form method=\"post\" action=\"",Dest/binary,"\">
<input type=\"hidden\" name=\"SAMLRequest\" value=\"",Req/binary,"\" />
<noscript><input type=\"submit\" value=\"Submit\" /></noscript>
</form>
</body>
</html>">>.

get(<<"auth">>, Req, S = #state{sp = SP}) ->
    SignedXml = SP:authn_request(S#state.idp_target),
    AuthnReq = lists:flatten(xmerl:export([SignedXml], xmerl_xml)),
    Param = edoc_lib:escape_uri(base64:encode_to_string(zlib:zip(AuthnReq))),
    Target = list_to_binary(S#state.idp_target ++ "?SAMLEncoding=urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE&SAMLRequest=" ++ Param),
    {UA, _} = cowboy_req:header(<<"user-agent">>, Req, <<"">>),
    IsIE = not (binary:match(UA, <<"MSIE">>) =:= nomatch),
    if IsIE andalso (byte_size(Target) > 2042) ->
        BaseData = base64:encode_to_string(AuthnReq),
        Html = generate_post_html(list_to_binary(S#state.idp_target), list_to_binary(BaseData)),
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
    end;

get(<<"metadata">>, Req, #state{sp = SP}) ->
    SignedXml = SP:metadata(),
    Metadata = xmerl:export([SignedXml], xmerl_xml),
    cowboy_req:reply(200, [{<<"Content-Type">>, <<"text/xml">>}], Metadata, Req);

get(_, Req, _) ->
    cowboy_req:reply(404, [], <<>>, Req).
