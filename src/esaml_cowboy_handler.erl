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

-record(state, {module, idp_target,
	base_uri, sign_req, sign_ass, spkey, spcert, trusted,
	org_name, org_displayname, org_url, tech_contact
	}).

ets_table_owner() ->
	receive
		stop -> ok;
		_ -> ets_table_owner()
	end.

init(_Transport, Req, Options) ->
	case {ets:info(esaml_privkey_cache), ets:info(esaml_certbin_cache)} of
		{undefined, undefined} ->
			spawn(fun() ->
				register(esaml_cowboy_ets_table_owner, self()),
				ets:new(esaml_privkey_cache, [set, public, named_table]),
				ets:new(esaml_certbin_cache, [set, public, named_table]),
				ets_table_owner()
			end);
		_ -> ok
	end,

	PrivKey = case proplists:get_value(sp_private_key, Options) of
		undefined -> none;
		PrivKeyPath ->
			case ets:lookup(esaml_privkey_cache, PrivKeyPath) of
				[{_, Key}] -> Key;
				_ ->
					{ok, KeyFile} = file:read_file(PrivKeyPath),
					[KeyEntry] = public_key:pem_decode(KeyFile),
					Key = case public_key:pem_entry_decode(KeyEntry) of
						#'PrivateKeyInfo'{privateKey = KeyData} ->
							public_key:der_decode('RSAPrivateKey', list_to_binary(KeyData));
		      			Other -> Other
					end,
					ets:insert(esaml_privkey_cache, {PrivKeyPath, Key}),
					Key
			end
	end,
	Cert = case proplists:get_value(sp_certificate, Options) of
		undefined -> none;
		CertPath ->
			case ets:lookup(esaml_certbin_cache, CertPath) of
				[{_, CertBin}] -> CertBin;
				_ ->
					{ok, CertFile} = file:read_file(CertPath),
   					[{'Certificate', CertBin, not_encrypted}] = public_key:pem_decode(CertFile),
   					ets:insert(esaml_certbin_cache, {CertPath, CertBin}),
   					CertBin
   			end
	end,
	FPSources = proplists:get_value(trusted_fingerprints, Options, []) ++ esaml:config(trusted_fingerprints, []),
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
	{ok, Req, #state{
		module = proplists:get_value(module, Options, esaml_sp_default),
		idp_target = proplists:get_value(idp_sso_target, Options, esaml:config(idp_sso_target)),
		base_uri = proplists:get_value(base_uri, Options),
		sign_req = proplists:get_value(sign_authn_requests, Options, (not (PrivKey =:= none)) and (not (Cert =:= none))),
		sign_ass = proplists:get_value(require_signed_assertions, Options, (length(Fingerprints) > 0)),
		org_name = proplists:get_value(org_name, Options, esaml:config(org_name, "undefined")),
		org_displayname = proplists:get_value(org_displayname, Options, esaml:config(org_displayname, "undefined")),
		org_url = proplists:get_value(org_url, Options, esaml:config(org_url, "undefined")),
		tech_contact = proplists:get_value(tech_contact, Options, esaml:config(tech_contact, [{name, "undefined"}, {email, "undefined"}])),
		spkey = PrivKey,
		spcert = Cert,
		trusted = Fingerprints
	}}.

terminate(_Reason, _Req, _State) ->
	ok.

handle(Req, State) ->
	{Method, Req2} = cowboy_req:method(Req),
	{Path, Req3} = cowboy_req:path(Req2),
	SplitPath = case binary:split(Path, <<"/">>, [global, trim]) of
		[<<>> | Rest] -> Rest;
		Else -> Else
	end,
	MethodAtom = list_to_atom(string:to_lower(binary_to_list(Method))),
	{ok, Req4} = apply(?MODULE, MethodAtom, [SplitPath, Req3, State]),
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

post([_ | [<<"consume">>]], Req, S = #state{}) ->
	{ok, PostVals, Req2} = cowboy_req:body_qs(Req),

	Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
		  {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],

	case decode_saml_response(PostVals) of
		{error, Reason} ->
			error_logger:warning_report("Failed to decode SAMLResponse value: ~p (req = ~p)", [Reason, Req2]),
			cowboy_req:reply(403, <<"Failed to decode SAMLResponse value">>, Req2);
		Xml ->
			case (catch begin
				[Assertion] = xmerl_xpath:string("/samlp:Response/saml:Assertion", Xml, [{namespace, Ns}]),
				if S#state.sign_ass ->
					case xmerl_dsig:verify(Xml, S#state.trusted) of
						ok -> ok;
						OuterError -> error({outer_sig, OuterError})
					end,
					case xmerl_dsig:verify(Assertion, S#state.trusted) of
						ok -> ok;
						InnerError -> error({inner_sig, InnerError})
					end;
				true ->
					ok
				end,
				ok = esaml:validate_assertion(Assertion, S#state.base_uri ++ "/metadata"),

				{ok, Req3, ModState} = apply(S#state.module, init, [Req2]),
				{ok, Req4, ModState2} = apply(S#state.module, handle_assertion, [Req3, Assertion, ModState]),
				ok = apply(S#state.module, terminate, [Req4, ModState2]),

				{ok, Req4}
			end) of
				{'EXIT', Reason} ->
					error_logger:warning_report("Rejected SAML assertion for reason: ~p (req = ~p)", [Reason, Req2]),
					cowboy_req:reply(403, <<"Invalid SAML assertion">>, Req2);
				Other -> Other
			end
	end.

get([_ | [<<"auth">>]], Req, S = #state{}) ->
	Now = erlang:localtime_to_universaltime(erlang:localtime()),
	Stamp = esaml:datetime_to_saml(Now),

	Xml = esaml:to_xml(#esaml_authnreq{issue_instant = Stamp,
									   destination = S#state.idp_target,
									   issuer = S#state.base_uri ++ "/metadata",
									   consumer_location = S#state.base_uri ++ "/consume"}),
	SignedXml = if S#state.sign_req ->
		xmerl_dsig:sign(Xml, S#state.spkey, S#state.spcert);
	true ->
		Xml
	end,
	AuthnReq = lists:flatten(xmerl:export([SignedXml], xmerl_xml)),
	Param = edoc_lib:escape_uri(base64:encode_to_string(zlib:zip(AuthnReq))),

	cowboy_req:reply(302, [{<<"Location">>, S#state.idp_target ++ "?SAMLEncoding=urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE&SAMLRequest=" ++ Param}], <<>>, Req);

get([_  | [<<"metadata">>]], Req, S = #state{}) ->
	Xml = esaml:to_xml(#esaml_metadata{org_name = S#state.org_name,
							 		   org_displayname = S#state.org_displayname,
							 		   org_url = S#state.org_url,
							 		   tech_name = proplists:get_value(name, S#state.tech_contact),
							 		   tech_email = proplists:get_value(email, S#state.tech_contact),
							 		   sign_req = S#state.sign_req,
							 		   sign_ass = S#state.sign_ass,
							 		   cert = S#state.spcert,
							 		   consumer_location = S#state.base_uri ++ "/consume",
							 		   entity_id = S#state.base_uri ++ "/metadata"}),
	SignedXml = xmerl_dsig:sign(Xml, S#state.spkey, S#state.spcert),
	Metadata = xmerl:export([SignedXml], xmerl_xml),
	cowboy_req:reply(200, [{<<"Content-Type">>, <<"text/xml">>}], Metadata, Req).


