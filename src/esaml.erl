%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(esaml).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("esaml.hrl").

-export([datetime_to_saml/1, saml_to_datetime/1]).
-export([config/2, config/1, to_xml/1, decode_attributes/1, validate_assertion/2]).
-export([build_nsinfo/2]).

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
common_attrib_map(Other) -> list_to_atom(Other).

%% @doc Decodes the attributes of a SAML assertion as a property list.
-spec decode_attributes(#xmlElement{}) -> [{K :: atom(), V :: string()}].
decode_attributes(Assertion = #xmlElement{nsinfo = {_, "Assertion"}}) ->
	Ns = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
	Attrs = xmerl_xpath:string("saml:AttributeStatement/saml:Attribute", Assertion, [{namespace, Ns}]),
	lists:foldl(fun(AttrElem, In) ->
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
	end, [], Attrs).

ets_table_owner() ->
	receive
		stop -> ok;
		_ -> ets_table_owner()
	end.

%% @doc Validates a SAML assertion
-spec validate_assertion(Assertion :: #xmlElement{}, Audience :: string()) -> ok.
validate_assertion(Assertion, Audience) ->
	Ns = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
	case xmerl_xpath:string("saml:Conditions/saml:AudienceRestriction/saml:Audience/text()", Assertion, [{namespace, Ns}]) of
		[] -> ok;
		[#xmlText{value = Audience} | _] -> ok;
		_ -> error(bad_audience)
	end,
	Now = erlang:localtime_to_universaltime(erlang:localtime()),
	NowSecs = calendar:datetime_to_gregorian_seconds(Now),
	DeathSecs = case xmerl_xpath:string("saml:Conditions/@NotOnOrAfter", Assertion, [{namespace, Ns}]) of
		[#xmlAttribute{value = MaxTime} | _] ->
			DSecs = calendar:datetime_to_gregorian_seconds(saml_to_datetime(MaxTime)),
			if (NowSecs > DSecs) ->
				error(stale_assertion);
			true ->
				DSecs
			end;
		_ ->
			NowSecs + 10*3600
	end,
	Digest = crypto:sha(xmerl_c14n:c14n(xmerl_dsig:strip(Assertion))),
	{ResL, _BadNodes} = rpc:multicall(erlang, apply, [fun() ->
		case (catch ets:lookup(esaml_assertion_seen, Digest)) of
			[{Digest, seen} | _] -> seen;
			_ -> ok
		end
	end, []]),
	case lists:member(seen, ResL) of
		true ->
			error(duplicate_assertion);
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
			#xmlElement{name = 'saml:Issuer', content = [#xmlText{value = Issuer}]}
		]
	});

to_xml(#esaml_metadata{org_name = OrgName, org_displayname = OrgDisplayName, org_url = OrgUrl,
					   tech_name = TechName, tech_email = TechEmail, sign_req = SignReq, sign_ass = SignAss,
					   cert = CertBin, entity_id = EntityID, consumer_location = ConsumerLoc
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

attributes_test() ->
	{Doc, _} = xmerl_scan:string("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:AttributeStatement><saml:Attribute Name=\"urn:oid:0.9.2342.19200300.100.1.3\"><saml:AttributeValue>test@test.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"foo\"><saml:AttributeValue>george</saml:AttributeValue><saml:AttributeValue>bar</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>", [{namespace_conformant, true}]),
	[{foo, ["george", "bar"]}, {mail, "test@test.com"}] = lists:sort(decode_attributes(Doc)).

validate_assertion_test() ->
	Now = erlang:localtime_to_universaltime(erlang:localtime()),
	DeathSecs = calendar:datetime_to_gregorian_seconds(Now) + 1,
	Death = esaml:datetime_to_saml(calendar:gregorian_seconds_to_datetime(DeathSecs)),

	Ns = #xmlNamespace{nodes = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},

	E1 = build_nsinfo(Ns, #xmlElement{name = 'saml:Assertion',
		attributes = [#xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"}],
		content = [
			#xmlElement{name = 'saml:Conditions',
				attributes = [#xmlAttribute{name = 'NotOnOrAfter', value = Death}],
				content = [#xmlElement{name = 'saml:AudienceRestriction',
					content = [#xmlElement{name = 'saml:Audience',
						content = [#xmlText{value = "foo"}]}] }] } ]
	}),
	ok = validate_assertion(E1, "foo"),
	{'EXIT', {bad_audience, _}} = (catch validate_assertion(E1, "something")).

validate_duplicate_assertion_test() ->
	Now = erlang:localtime_to_universaltime(erlang:localtime()),
	DeathSecs = calendar:datetime_to_gregorian_seconds(Now) + 1,
	Death = esaml:datetime_to_saml(calendar:gregorian_seconds_to_datetime(DeathSecs)),

	Ns = #xmlNamespace{nodes = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},

	E1 = build_nsinfo(Ns, #xmlElement{name = 'saml:Assertion',
		attributes = [#xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"}],
		content = [
			#xmlElement{name = 'saml:Conditions',
				attributes = [#xmlAttribute{name = 'NotOnOrAfter', value = Death}],
				content = [#xmlElement{name = 'saml:AudienceRestriction',
					content = [#xmlElement{name = 'saml:Audience',
						content = [#xmlText{value = "testAudience"}]}] }] } ]
	}),
	Digest = crypto:sha(xmerl_c14n:c14n(xmerl_dsig:strip(E1))),

	[] = ets:lookup(esaml_assertion_seen, Digest),
	ok = validate_assertion(E1, "testAudience"),
	[_] = ets:lookup(esaml_assertion_seen, Digest),
	receive
	after 500 ->
		[_] = ets:lookup(esaml_assertion_seen, Digest),
		{'EXIT', {duplicate_assertion, _}} = (catch validate_assertion(E1, "testAudience")),
		receive
		after 2000 ->
			[] = ets:lookup(esaml_assertion_seen, Digest),
			{'EXIT', {stale_assertion, _}} = (catch validate_assertion(E1, "testAudience"))
		end
	end.

validate_stale_assertion_test() ->
	Ns = #xmlNamespace{nodes = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},
	OldStamp = esaml:datetime_to_saml({{1990,1,1}, {1,1,1}}),
	E2 = build_nsinfo(Ns, #xmlElement{name = 'saml:Assertion',
		attributes = [#xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"}],
		content = [
			#xmlElement{name = 'saml:Conditions',
				attributes = [#xmlAttribute{name = 'NotOnOrAfter', value = OldStamp}],
				content = [] } ]
	}),
	{'EXIT', {stale_assertion, _}} = (catch validate_assertion(E2, "foo")).


-endif.
