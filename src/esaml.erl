%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(esaml).
-behaviour(application).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("esaml.hrl").

-export([start/2, stop/1]).
-export([datetime_to_saml/1, saml_to_datetime/1]).
-export([config/2, config/1, to_xml/1, decode_response/1, decode_assertion/1, validate_assertion/3]).
-export([build_nsinfo/2]).

start(_StartType, _StartArgs) ->
	Pid = spawn(fun() ->
		register(esaml_ets_table_owner, self()),
		ets:new(esaml_assertion_seen, [set, public, named_table]),
		ets_table_owner()
	end),
	{ok, Pid}.

stop(_State) ->
	ok.

%% @doc Converts a calendar:datetime() into SAML time string
-spec datetime_to_saml(Time :: calendar:datetime()) -> string().
datetime_to_saml(Time) ->
	{{Y,Mo,D}, {H, Mi, S}} = Time,
	lists:flatten(io_lib:format("~4.10.0B-~2.10.0B-~2.10.0BT~2.10.0B:~2.10.0B:~2.10.0BZ", [Y, Mo, D, H, Mi, S])).

-spec saml_to_datetime(Stamp :: binary() | string()) -> calendar:datetime().
saml_to_datetime(Stamp) ->
	StampBin = if is_list(Stamp) -> list_to_binary(Stamp); true -> Stamp end,
	<<YBin:4/binary-unit:8, "-", MoBin:2/binary-unit:8, "-", DBin:2/binary-unit:8, "T", HBin:2/binary-unit:8, ":", MiBin:2/binary-unit:8, ":", SBin:2/binary-unit:8, "Z">> = StampBin,
	F = fun(B) -> list_to_integer(binary_to_list(B)) end,
	{{F(YBin), F(MoBin), F(DBin)}, {F(HBin), F(MiBin), F(SBin)}}.

%% @doc Retrieve a config record
config(N) -> config(N, undefined).
config(N, D) ->
	case application:get_env(esaml, N) of
		{ok, V} -> V;
		_ -> D
	end.

-spec folduntil(F :: fun(), Acc :: term(), List :: []) -> AccOut :: term().
folduntil(F, Acc, []) -> Acc;
folduntil(F, Acc, [Next | Rest]) ->
	case F(Next, Acc) of
		{stop, AccOut} -> AccOut;
		NextAcc -> folduntil(F, NextAcc, Rest)
	end.

thread([], Acc) -> Acc;
thread([F | Rest], Acc) ->
	thread(Rest, F(Acc)).

threaduntil([], Acc) -> {ok, Acc};
threaduntil([F | Rest], Acc) ->
	case (catch F(Acc)) of
		{'EXIT', Reason} ->
			{error, Reason};
		{error, Reason} ->
			{error, Reason};
		{stop, LastAcc} ->
			{ok, LastAcc};
		NextAcc ->
			threaduntil(Rest, NextAcc)
	end.

response_map_status_code(R = #esaml_response{status = Code}) ->
	R#esaml_response{status = status_code_map(Code)}.
subject_map_method(R = #esaml_subject{confirmation_method = Method}) ->
	R#esaml_subject{confirmation_method = subject_method_map(Method)}.

subject_method_map("urn:oasis:names:tc:SAML:2.0:cm:bearer") -> bearer;
subject_method_map(_) -> unknown.

status_code_map("urn:oasis:names:tc:SAML:2.0:status:Success") -> success;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch") -> bad_version;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed") -> authn_failed;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue") -> bad_attr;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:RequestDenied") -> denied;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding") -> bad_binding;
status_code_map(Urn = "urn:" ++ _) -> list_to_atom(lists:last(string:tokens(Urn, ":")));
status_code_map(_) -> unknown.

common_attrib_map("urn:oid:2.16.840.1.113730.3.1.3") -> employeeNumber;
common_attrib_map("urn:oid:1.3.6.1.4.1.5923.1.1.1.6") -> eduPersonPrincipalName;
common_attrib_map("urn:oid:0.9.2342.19200300.100.1.3") -> mail;
common_attrib_map("urn:oid:2.5.4.42") -> givenName;
common_attrib_map("urn:oid:2.16.840.1.113730.3.1.241") -> displayName;
common_attrib_map("urn:oid:2.5.4.3") -> commonName;
common_attrib_map("urn:oid:2.5.4.20") -> telephoneNumber;
common_attrib_map("urn:oid:2.5.4.10") -> organizationName;
common_attrib_map("urn:oid:2.5.4.11") -> organizationalUnitName;
common_attrib_map("urn:oid:1.3.6.1.4.1.5923.1.1.1.9") -> eduPersonScopedAffiliation;
common_attrib_map("urn:oid:2.16.840.1.113730.3.1.4") -> employeeType;
common_attrib_map("urn:oid:0.9.2342.19200300.100.1.1") -> uid;
common_attrib_map("urn:oid:2.5.4.4") -> surName;
common_attrib_map(Uri = "http://" ++ _) -> list_to_atom(lists:last(string:tokens(Uri, "/")));
common_attrib_map(Other) -> list_to_atom(Other).

-define(xpath_attr_required(XPath, Record, Field, Error),
	fun(Resp) ->
		case xmerl_xpath:string(XPath, Xml, [{namespace, Ns}]) of
			[#xmlAttribute{value = V}] -> Resp#Record{Field = V};
			_ -> {error, Error}
		end
	end).
-define(xpath_attr(XPath, Record, Field),
	fun(Resp) ->
		case xmerl_xpath:string(XPath, Xml, [{namespace, Ns}]) of
			[#xmlAttribute{value = V}] -> Resp#Record{Field = V};
			_ -> Resp
		end
	end).
-define(xpath_text(XPath, Record, Field),
	fun(Resp) ->
		case xmerl_xpath:string(XPath, Xml, [{namespace, Ns}]) of
			[#xmlText{value = V}] -> Resp#Record{Field = V};
			_ -> Resp
		end
	end).
-define(xpath_recurse(XPath, Record, Field, F),
	fun(Resp) ->
		case xmerl_xpath:string(XPath, Xml, [{namespace, Ns}]) of
			[E = #xmlElement{}] ->
				case F(E) of
					{error, V} -> {error, V};
					{ok, V} -> Resp#Record{Field = V};
					_ -> {error, bad_recurse}
				end;
			_ -> Resp
		end
	end).

decode_response(Xml) ->
	Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
		  {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
	threaduntil([
		?xpath_attr_required("/samlp:Response/@Version", esaml_response, version, bad_version),
		?xpath_attr_required("/samlp:Response/@IssueInstant", esaml_response, issue_instant, bad_response),
		?xpath_attr("/samlp:Response/@Destination", esaml_response, destination),
		?xpath_text("/samlp:Response/saml:Issuer/text()", esaml_response, issuer),
		?xpath_attr("/samlp:Response/samlp:Status/samlp:StatusCode/@Value", esaml_response, status),
		fun response_map_status_code/1,
		?xpath_recurse("/samlp:Response/saml:Assertion", esaml_response, assertion, decode_assertion)
	], #esaml_response{}).

decode_assertion(Xml) ->
	Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
		  {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
	threaduntil([
		?xpath_attr_required("/saml:Assertion/@Version", esaml_assertion, version, bad_version),
		?xpath_attr_required("/saml:Assertion/@IssueInstant", esaml_assertion, issue_instant, bad_assertion),
		?xpath_attr_required("/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient", esaml_assertion, recipient, bad_recipient),
		?xpath_text("/saml:Assertion/saml:Issuer/text()", esaml_assertion, issuer),
		?xpath_recurse("/saml:Assertion/saml:Subject", esaml_assertion, subject, decode_assertion_subject),
		?xpath_recurse("/saml:Assertion/saml:Conditions", esaml_assertion, conditions, decode_assertion_conditions),
		?xpath_recurse("/saml:Assertion/saml:AttributeStatement", esaml_assertion, attributes, decode_assertion_attributes)
	], #esaml_assertion{}).

decode_assertion_subject(Xml) ->
	Ns = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
	threaduntil([
		?xpath_text("/saml:Subject/saml:NameID/text()", esaml_subject, name),
		?xpath_attr("/saml:Subject/saml:SubjectConfirmation/@Method", esaml_subject, confirmation_method),
		?xpath_attr("/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter", esaml_subject, notonorafter),
		fun subject_map_method/1
	], #esaml_subject{}).

decode_assertion_conditions(Xml) ->
	Ns = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
	threaduntil([
		fun(C) ->
			case xmerl_xpath:string("/saml:Conditions/@NotBefore", Xml, [{namespace, Ns}]) of
				[#xmlAttribute{value = V}] -> [{not_before, V} | C]; _ -> C
			end
		end,
		fun(C) ->
			case xmerl_xpath:string("/saml:Conditions/@NotOnOrAfter", Xml, [{namespace, Ns}]) of
				[#xmlAttribute{value = V}] -> [{not_on_or_after, V} | C]; _ -> C
			end
		end,
		fun(C) ->
			case xmerl_xpath:string("/saml:Conditions/saml:AudienceRestriction/saml:Audience/text()", Xml, [{namespace, Ns}]) of
				[#xmlText{value = V}] -> [{audience, V} | C]; _ -> C
			end
		end
	], []).

decode_assertion_attributes(Xml) ->
	Ns = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
	Attrs = xmerl_xpath:string("/saml:AttributeStatement/saml:Attribute", Xml, [{namespace, Ns}]),
	{ok, lists:foldl(fun(AttrElem, In) ->
		case [X#xmlAttribute.value || X <- AttrElem#xmlElement.attributes, X#xmlAttribute.name =:= 'Name'] of
			[Name] ->
				case xmerl_xpath:string("saml:AttributeValue/text()", AttrElem, [{namespace, Ns}]) of
					[#xmlText{value = Value}] ->
						[{common_attrib_map(Name), Value} | In];
					List ->
						if (length(List) > 0) ->
							Value = [X#xmlText.value || X <- List, element(1, X) =:= xmlText],
							[{common_attrib_map(Name), Value} | In];
						true ->
							In
						end
				end;
			_ -> In
		end
	end, [], Attrs)}.

ets_table_owner() ->
	receive
		stop -> ok;
		_ -> ets_table_owner()
	end.

stale_time(A) ->
	thread([
		fun(T) ->
			case A#esaml_assertion.subject of
				#esaml_subject{notonorafter = undefined} -> T;
				#esaml_subject{notonorafter = Restrict} ->
					Secs = calendar:datetime_to_gregorian_seconds(saml_to_datetime(Restrict)),
					if (Secs < T) -> Secs; true -> T end;
				_ -> T
			end
		end,
		fun(T) ->
			Conds = A#esaml_assertion.conditions,
			case proplists:get_value(not_on_or_after, Conds) of
				undefined -> T;
				Restrict ->
					Secs = calendar:datetime_to_gregorian_seconds(saml_to_datetime(Restrict)),
					if (Secs < T) -> Secs; true -> T end
			end
		end,
		fun(T) ->
			if (T =:= none) ->
				II = A#esaml_assertion.issue_instant,
				IISecs = calendar:datetime_to_gregorian_seconds(saml_to_datetime(II)),
				IISecs + 5*60;
			true ->
				T
			end
		end
	], none).

check_stale(A) ->
	Now = erlang:localtime_to_universaltime(erlang:localtime()),
	NowSecs = calendar:datetime_to_gregorian_seconds(Now),
	T = stale_time(A),
	if (NowSecs > T) ->
		{error, stale_assertion};
	true ->
		A
	end.

check_dupe(A, Xml) ->
	Now = erlang:localtime_to_universaltime(erlang:localtime()),
	NowSecs = calendar:datetime_to_gregorian_seconds(Now),
	DeathSecs = stale_time(A),
	Digest = crypto:sha(
		unicode:characters_to_binary(xmerl_c14n:c14n(xmerl_dsig:strip(Xml)))),
	{ResL, _BadNodes} = rpc:multicall(erlang, apply, [fun() ->
		case (catch ets:lookup(esaml_assertion_seen, Digest)) of
			[{Digest, seen} | _] -> seen;
			_ -> ok
		end
	end, []]),
	case lists:member(seen, ResL) of
		true ->
			{error, duplicate_assertion};
		_ ->
			Until = DeathSecs - NowSecs + 1,
			rpc:multicall(erlang, apply, [fun() ->
				case ets:info(esaml_assertion_seen) of
					undefined ->
						Me = self(),
						Pid = spawn(fun() ->
							register(esaml_ets_table_owner, self()),
							ets:new(esaml_assertion_seen, [set, public, named_table]),
							ets:insert(esaml_assertion_seen, {Digest, seen}),
							Me ! {self(), ping},
							ets_table_owner()
						end),
						receive
							{Pid, ping} -> ok
						end;
					_ ->
						ets:insert(esaml_assertion_seen, {Digest, seen})
				end,
				{ok, _} = timer:apply_after(Until * 1000, erlang, apply, [fun() ->
					ets:delete(esaml_assertion_seen, Digest)
				end, []])
			end, []]),
			ok
	end.

validate_assertion(AssertionXml, Recipient, Audience) ->
	case decode_assertion(AssertionXml) of
		{error, Reason} ->
			{error, Reason};
		{ok, Assertion} ->
			threaduntil([
				fun(A) -> case A of
					#esaml_assertion{version = "2.0"} -> A;
					_ -> {error, bad_version}
				end end,
				fun(A) -> case A of
					#esaml_assertion{recipient = Recipient} -> A;
					_ -> {error, bad_recipient}
				end	end,
				fun(A) -> case A of
					#esaml_assertion{conditions = Conds} ->
						case proplists:get_value(audience, Conds) of
							undefined -> A;
							Audience -> A;
							_ -> {error, bad_audience}
						end;
					_ -> A
				end end,
				fun check_stale/1,
				fun(A) -> case check_dupe(A, AssertionXml) of ok -> A; _ -> {error, duplicate_assertion} end end
			], Assertion)
	end.

%% @internal
-spec build_nsinfo(#xmlNamespace{}, #xmlElement{}) -> #xmlElement{}.
build_nsinfo(Ns, Attr = #xmlAttribute{name = Name}) ->
	case string:tokens(atom_to_list(Name), ":") of
		[NsPrefix, Rest] -> Attr#xmlAttribute{namespace = Ns, nsinfo = {NsPrefix, Rest}};
		_ -> Attr#xmlAttribute{namespace = Ns}
	end;
build_nsinfo(Ns, Elem = #xmlElement{name = Name, content = Kids, attributes = Attrs}) ->
	Elem2 = case string:tokens(atom_to_list(Name), ":") of
		[NsPrefix, Rest] -> Elem#xmlElement{namespace = Ns, nsinfo = {NsPrefix, Rest}};
		_ -> Elem#xmlElement{namespace = Ns}
	end,
	Elem2#xmlElement{attributes = [build_nsinfo(Ns, Attr) || Attr <- Attrs],
					content = [build_nsinfo(Ns, Kid) || Kid <- Kids]};
build_nsinfo(_Ns, Other) -> Other.

%% @doc Convert a SAML request/metadata record into XML
to_xml(#esaml_authnreq{issue_instant = Time, destination = Dest, issuer = Issuer, consumer_location = Consumer}) ->
	Ns = #xmlNamespace{nodes = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
		  						{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},

	build_nsinfo(Ns, #xmlElement{name = 'samlp:AuthnRequest',
		attributes = [#xmlAttribute{name = 'xmlns:samlp', value = proplists:get_value("samlp", Ns#xmlNamespace.nodes)},
					  #xmlAttribute{name = 'xmlns:saml', value = proplists:get_value("saml", Ns#xmlNamespace.nodes)},
					  #xmlAttribute{name = 'IssueInstant', value = Time},
					  #xmlAttribute{name = 'Version', value = "2.0"},
					  #xmlAttribute{name = 'Destination', value = Dest},
					  #xmlAttribute{name = 'AssertionConsumerServiceURL', value = Consumer},
					  #xmlAttribute{name = 'ProtocolBinding', value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}],
		content = [
			#xmlElement{name = 'saml:Issuer', content = [#xmlText{value = Issuer}]},
			#xmlElement{name = 'saml:Subject', content = [
				#xmlElement{name = 'saml:SubjectConfirmation', attributes = [#xmlAttribute{name = 'Method', value = "urn:oasis:names:tc:SAML:2.0:cm:bearer"}]}
			]}
		]
	});

to_xml(#esaml_sp_metadata{org = #esaml_org{name = OrgName, displayname = OrgDisplayName,
										   url = OrgUrl },
					   tech = #esaml_contact{name = TechName, email = TechEmail},
					   signed_requests = SignReq, signed_assertions = SignAss,
					   certificate = CertBin, entity_id = EntityID,
					   consumer_location = ConsumerLoc
					   }) ->
	Ns = #xmlNamespace{nodes = [{"md", 'urn:oasis:names:tc:SAML:2.0:metadata'},
		  						{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
		  						{"dsig", 'http://www.w3.org/2000/09/xmldsig#'}]},

	MdOrg = #xmlElement{name = 'md:Organization',
		content = [
			#xmlElement{name = 'md:OrganizationName', content = [#xmlText{value = OrgName}]},
			#xmlElement{name = 'md:OrganizationDisplayName', content = [#xmlText{value = OrgDisplayName}]},
			#xmlElement{name = 'md:OrganizationURL', content = [#xmlText{value = OrgUrl}]}
		]
	},

	MdContact = #xmlElement{name = 'md:ContactPerson',
		attributes = [#xmlAttribute{name = 'contactType', value = "technical"}],
		content = [
			#xmlElement{name = 'md:SurName', content = [#xmlText{value = TechName}]},
			#xmlElement{name = 'md:EmailAddress', content = [#xmlText{value = TechEmail}]}
		]
	},

	SpSso = #xmlElement{name = 'md:SPSSODescriptor',
		attributes = [#xmlAttribute{name = 'protocolSupportEnumeration', value = "urn:oasis:names:tc:SAML:2.0:protocol"},
					  #xmlAttribute{name = 'AuthnRequestsSigned', value = atom_to_list(SignReq)},
					  #xmlAttribute{name = 'WantAssertionsSigned', value = atom_to_list(SignAss)}],
		content = [
			#xmlElement{name = 'md:KeyDescriptor',
				attributes = [#xmlAttribute{name = 'use', value = "signing"}],
				content = [#xmlElement{name = 'dsig:KeyInfo',
					content = [#xmlElement{name = 'dsig:X509Data',
						content = [#xmlElement{name = 'dsig:X509Certificate',
							content = [#xmlText{value = base64:encode_to_string(CertBin)}]}]}]}]},
			#xmlElement{name = 'md:AssertionConsumerService',
				attributes = [#xmlAttribute{name = 'isDefault', value = "true"},
							  #xmlAttribute{name = 'index', value = "0"},
							  #xmlAttribute{name = 'Binding', value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"},
							  #xmlAttribute{name = 'Location', value = ConsumerLoc}]},
			#xmlElement{name = 'md:AttributeConsumingService',
				attributes = [#xmlAttribute{name = 'isDefault', value = "true"},
							  #xmlAttribute{name = 'index', value = "0"}],
				content = [#xmlElement{name = 'md:ServiceName', content = [#xmlText{value = "SAML SP"}]}]}
		]
	},

	build_nsinfo(Ns, #xmlElement{
		name = 'md:EntityDescriptor',
		attributes = [
			#xmlAttribute{name = 'xmlns:md', value = atom_to_list(proplists:get_value("md", Ns#xmlNamespace.nodes))},
			#xmlAttribute{name = 'xmlns:saml', value = atom_to_list(proplists:get_value("saml", Ns#xmlNamespace.nodes))},
			#xmlAttribute{name = 'xmlns:dsig', value = atom_to_list(proplists:get_value("dsig", Ns#xmlNamespace.nodes))},
			#xmlAttribute{name = 'entityID', value = EntityID}
		], content = [
			SpSso,
			MdOrg,
			MdContact
		]
	});

to_xml(_) -> error("unknown record").



-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

build_nsinfo_test() ->
	EmptyNs = #xmlNamespace{},
	FooNs = #xmlNamespace{nodes = [{"foo", 'urn:foo:'}]},

	E1 = #xmlElement{name = 'foo', content = [#xmlText{value = 'bar'}]},
	E1 = build_nsinfo(EmptyNs, E1),

	E2 = #xmlElement{name = 'foo:Blah', content = [#xmlText{value = 'bar'}]},
	E2Ns = E2#xmlElement{nsinfo = {"foo", "Blah"}, namespace = FooNs},
	E2Ns = build_nsinfo(FooNs, E2),

	E3 = #xmlElement{name = 'blah:George', content = [E2]},
	E3Ns = E3#xmlElement{nsinfo = {"blah", "George"}, namespace = FooNs, content = [E2Ns]},
	E3Ns = build_nsinfo(FooNs, E3).

datetime_test() ->
	"2013-05-02T17:26:53Z" = datetime_to_saml({{2013,5,2},{17,26,53}}),
	{{1990,11,23},{18,1,1}} = saml_to_datetime("1990-11-23T18:01:01Z").

decode_response_test() ->
	{Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\" Destination=\"foo\"></samlp:Response>", [{namespace_conformant, true}]),
	Resp = decode_response(Doc),
	{ok, #esaml_response{issue_instant = "2013-01-01T01:01:01Z", destination = "foo", status = unknown}} = Resp.

decode_response_no_version_test() ->
	{Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" IssueInstant=\"2013-01-01T01:01:01Z\" Destination=\"foo\"></samlp:Response>", [{namespace_conformant, true}]),
	Resp = decode_response(Doc),
	{error, bad_version} = Resp.

decode_response_no_issue_instant_test() ->
	{Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" Destination=\"foo\"></samlp:Response>", [{namespace_conformant, true}]),
	Resp = decode_response(Doc),
	{error, bad_response} = Resp.

decode_response_destination_optional_test() ->
	{Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"></samlp:Response>", [{namespace_conformant, true}]),
	Resp = decode_response(Doc),
	{ok, #esaml_response{issue_instant = "2013-01-01T01:01:01Z", status = unknown}} = Resp.

decode_response_status_test() ->
	{Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status></samlp:Response>", [{namespace_conformant, true}]),
	Resp = decode_response(Doc),
	{ok, #esaml_response{issue_instant = "2013-01-01T01:01:01Z", status = success, issuer = "foo"}} = Resp.

decode_response_bad_assertion_test() ->
	{Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
	Resp = decode_response(Doc),
	{error, bad_version} = Resp.

decode_assertion_no_recipient_test() ->
	{Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion Version=\"2.0\" IssueInstant=\"test\"><saml:Issuer>foo</saml:Issuer><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\" /></saml:Subject></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
	Resp = decode_response(Doc),
	{error, bad_recipient} = Resp.

decode_assertion_test() ->
	{Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion Version=\"2.0\" IssueInstant=\"test\"><saml:Issuer>foo</saml:Issuer><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"foobar123\" /></saml:SubjectConfirmation></saml:Subject></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
	Resp = decode_response(Doc),
	{ok, #esaml_response{issue_instant = "2013-01-01T01:01:01Z", issuer = "foo", status = success, assertion = #esaml_assertion{issue_instant = "test", issuer = "foo", recipient = "foobar123", subject = #esaml_subject{name = "foobar", confirmation_method = bearer}}}} = Resp.

decode_conditions_test() ->
	{Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion Version=\"2.0\" IssueInstant=\"test\"><saml:Issuer>foo</saml:Issuer><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"foobar123\" /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"before\" NotOnOrAfter=\"notafter\"><saml:AudienceRestriction><saml:Audience>foobaraudience</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
	Resp = decode_response(Doc),
	{ok, #esaml_response{assertion = #esaml_assertion{conditions = Conds}}} = Resp,
	[{audience, "foobaraudience"}, {not_before, "before"}, {not_on_or_after, "notafter"}] = lists:sort(Conds).

decode_attributes_test() ->
	{Doc, _} = xmerl_scan:string("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"test\"><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"foobar123\" /></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name=\"urn:oid:0.9.2342.19200300.100.1.3\"><saml:AttributeValue>test@test.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"foo\"><saml:AttributeValue>george</saml:AttributeValue><saml:AttributeValue>bar</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress\"><saml:AttributeValue>test@test.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>", [{namespace_conformant, true}]),
	Assertion = decode_assertion(Doc),
	{ok, #esaml_assertion{attributes = Attrs}} = Assertion,
	[{emailaddress, "test@test.com"}, {foo, ["george", "bar"]}, {mail, "test@test.com"}] = lists:sort(Attrs).

validate_assertion_test() ->
	Now = erlang:localtime_to_universaltime(erlang:localtime()),
	DeathSecs = calendar:datetime_to_gregorian_seconds(Now) + 1,
	Death = esaml:datetime_to_saml(calendar:gregorian_seconds_to_datetime(DeathSecs)),

	Ns = #xmlNamespace{nodes = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},

	E1 = build_nsinfo(Ns, #xmlElement{name = 'saml:Assertion',
		attributes = [#xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"}, #xmlAttribute{name = 'Version', value = "2.0"}, #xmlAttribute{name = 'IssueInstant', value = "now"}],
		content = [
			#xmlElement{name = 'saml:Subject', content = [
				#xmlElement{name = 'saml:SubjectConfirmation', content = [
					#xmlElement{name = 'saml:SubjectConfirmationData',
						attributes = [#xmlAttribute{name = 'Recipient', value = "foobar"},
									  #xmlAttribute{name = 'NotOnOrAfter', value = Death}]
					} ]} ]},
			#xmlElement{name = 'saml:Conditions', content = [
				#xmlElement{name = 'saml:AudienceRestriction', content = [
					#xmlElement{name = 'saml:Audience', content = [#xmlText{value = "foo"}]}] }] } ]
	}),
	{ok, Assertion} = validate_assertion(E1, "foobar", "foo"),
	#esaml_assertion{issue_instant = "now", recipient = "foobar", subject = #esaml_subject{notonorafter = Death}, conditions = [{audience, "foo"}]} = Assertion,
	{error, bad_recipient} = validate_assertion(E1, "foo", "something"),
	{error, bad_audience} = validate_assertion(E1, "foobar", "something"),

	E2 = build_nsinfo(Ns, #xmlElement{name = 'saml:Assertion',
		attributes = [#xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"}, #xmlAttribute{name = 'Version', value = "2.0"}, #xmlAttribute{name = 'IssueInstant', value = "now"}],
		content = [
			#xmlElement{name = 'saml:Subject', content = [
				#xmlElement{name = 'saml:SubjectConfirmation', content = [ ]} ]},
			#xmlElement{name = 'saml:Conditions', content = [
				#xmlElement{name = 'saml:AudienceRestriction', content = [
					#xmlElement{name = 'saml:Audience', content = [#xmlText{value = "foo"}]}] }] } ]
	}),
	{error, bad_recipient} = validate_assertion(E2, "", "").

validate_duplicate_assertion_test() ->
	Now = erlang:localtime_to_universaltime(erlang:localtime()),
	DeathSecs = calendar:datetime_to_gregorian_seconds(Now) + 1,
	Death = esaml:datetime_to_saml(calendar:gregorian_seconds_to_datetime(DeathSecs)),

	Ns = #xmlNamespace{nodes = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},

	E1 = build_nsinfo(Ns, #xmlElement{name = 'saml:Assertion',
		attributes = [#xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"}, #xmlAttribute{name = 'Version', value = "2.0"}, #xmlAttribute{name = 'IssueInstant', value = "now"}],
		content = [
			#xmlElement{name = 'saml:Subject', content = [
				#xmlElement{name = 'saml:SubjectConfirmation', content = [
					#xmlElement{name = 'saml:SubjectConfirmationData',
						attributes = [#xmlAttribute{name = 'Recipient', value = "foobar"},
									  #xmlAttribute{name = 'NotOnOrAfter', value = Death}]
					} ]} ]},
			#xmlElement{name = 'saml:Conditions', content = [
				#xmlElement{name = 'saml:AudienceRestriction', content = [
					#xmlElement{name = 'saml:Audience', content = [#xmlText{value = "testAudience"}]}] }] } ]
	}),
	Digest = crypto:sha(
		unicode:characters_to_binary(xmerl_c14n:c14n(xmerl_dsig:strip(E1)))),

	[] = ets:lookup(esaml_assertion_seen, Digest),
	{ok, _} = validate_assertion(E1, "foobar", "testAudience"),
	[_] = ets:lookup(esaml_assertion_seen, Digest),
	receive
	after 500 ->
		[_] = ets:lookup(esaml_assertion_seen, Digest),
		{error, duplicate_assertion} = validate_assertion(E1, "foobar", "testAudience"),
		receive
		after 2000 ->
			[] = ets:lookup(esaml_assertion_seen, Digest),
			{error, stale_assertion} = validate_assertion(E1, "foobar", "testAudience")
		end
	end.

validate_stale_assertion_test() ->
	Ns = #xmlNamespace{nodes = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},
	OldStamp = esaml:datetime_to_saml({{1990,1,1}, {1,1,1}}),
	E1 = build_nsinfo(Ns, #xmlElement{name = 'saml:Assertion',
		attributes = [#xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"}, #xmlAttribute{name = 'Version', value = "2.0"}, #xmlAttribute{name = 'IssueInstant', value = "now"}],
		content = [
			#xmlElement{name = 'saml:Subject', content = [
				#xmlElement{name = 'saml:SubjectConfirmation', content = [
					#xmlElement{name = 'saml:SubjectConfirmationData',
						attributes = [#xmlAttribute{name = 'Recipient', value = "foobar"},
									  #xmlAttribute{name = 'NotOnOrAfter', value = OldStamp}]
					} ]} ]} ]
	}),
	{error, stale_assertion} = validate_assertion(E1, "foobar", "foo").

-endif.
