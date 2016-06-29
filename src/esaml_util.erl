%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc Utility functions
-module(esaml_util).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("esaml.hrl").

-export([datetime_to_saml/1, saml_to_datetime/1]).
-export([start_ets/0, check_dupe_ets/2]).
-export([folduntil/3, thread/2, threaduntil/2]).
-export([build_nsinfo/2]).
-export([load_private_key/1, load_certificate_chain/1, load_certificate/1, load_metadata/2, load_metadata/1]).
-export([convert_fingerprints/1]).
-export([unique_id/0]).

%% @doc Converts various ascii hex/base64 fingerprint formats to binary
-spec convert_fingerprints([string() | binary()]) -> [binary()].
convert_fingerprints(FPs) ->
    FPSources = FPs ++ esaml:config(trusted_fingerprints, []),
    lists:map(fun(Print) ->
        if is_list(Print) ->
            case string:tokens(Print, ":") of
                [Type, Base64] ->
                    Hash = base64:decode(Base64),
                    case string:to_lower(Type) of
                        "sha" -> {sha, Hash};
                        "sha1" -> {sha, Hash};
                        "md5" -> {md5, Hash};
                        "sha256" -> {sha256, Hash};
                        "sha384" -> {sha384, Hash};
                        "sha512" -> {sha512, Hash}
                    end;
                [_] -> error("unknown fingerprint format");
                HexParts ->
                    list_to_binary([list_to_integer(P, 16) || P <- HexParts])
            end;
        is_binary(Print) ->
            Print;
        true ->
            error("unknown fingerprint format")
        end
    end, FPSources).

%% @doc Converts a calendar:datetime() into SAML time string
-spec datetime_to_saml(calendar:datetime()) -> esaml:datetime().
datetime_to_saml(Time) ->
    {{Y,Mo,D}, {H, Mi, S}} = Time,
    lists:flatten(io_lib:format("~4.10.0B-~2.10.0B-~2.10.0BT~2.10.0B:~2.10.0B:~2.10.0BZ", [Y, Mo, D, H, Mi, S])).

%% @doc Converts a SAML time string into a calendar:datetime()
%%
%% Inverse of datetime_to_saml/1
-spec saml_to_datetime(esaml:datetime()) -> calendar:datetime().
saml_to_datetime(Stamp) ->
    StampBin = if is_list(Stamp) -> list_to_binary(Stamp); true -> Stamp end,
    <<YBin:4/binary, "-", MoBin:2/binary, "-", DBin:2/binary, "T",
        HBin:2/binary, ":", MiBin:2/binary, ":", SBin:2/binary, Rest/binary>> = StampBin,
    %% check that time in UTC timezone because we don't handle another timezones properly
    $Z = binary:last(Rest),
    F = fun(B) -> list_to_integer(binary_to_list(B)) end,
    {{F(YBin), F(MoBin), F(DBin)}, {F(HBin), F(MiBin), F(SBin)}}.

%% @private
-spec folduntil(F :: fun(), Acc :: term(), List :: []) -> AccOut :: term().
folduntil(_F, Acc, []) -> Acc;
folduntil(F, Acc, [Next | Rest]) ->
    case F(Next, Acc) of
        {stop, AccOut} -> AccOut;
        NextAcc -> folduntil(F, NextAcc, Rest)
    end.

%% @private
thread([], Acc) -> Acc;
thread([F | Rest], Acc) ->
    thread(Rest, F(Acc)).

%% @private
-spec threaduntil([fun((Acc :: term()) -> {error, term()} | {stop, term()} | term())], InitAcc::term()) -> {ok, term()} | {error, term()}.
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

%% @private
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

%% @private
start_ets() ->
    {ok, spawn_link(fun() ->
        register(esaml_ets_table_owner, self()),
        ets:new(esaml_assertion_seen, [set, public, named_table]),
        ets:new(esaml_privkey_cache, [set, public, named_table]),
        ets:new(esaml_certbin_cache, [set, public, named_table]),
        ets:new(esaml_idp_meta_cache, [set, public, named_table]),
        ets_table_owner()
    end)}.

%% @private
ets_table_owner() ->
    receive
        stop -> ok;
        _ -> ets_table_owner()
    end.

%% @doc Loads a private key from a file on disk (or ETS memory cache)
-spec load_private_key(Path :: string()) -> #'RSAPrivateKey'{}.
load_private_key(Path) ->
    case ets:lookup(esaml_privkey_cache, Path) of
        [{_, Key}] -> Key;
        _ ->
            {ok, KeyFile} = file:read_file(Path),
            [KeyEntry] = public_key:pem_decode(KeyFile),
            Key = case public_key:pem_entry_decode(KeyEntry) of
                #'PrivateKeyInfo'{privateKey = KeyData} when is_list(KeyData) ->
                    public_key:der_decode('RSAPrivateKey', list_to_binary(KeyData));
                #'PrivateKeyInfo'{privateKey = KeyData} when is_binary(KeyData) ->
                    public_key:der_decode('RSAPrivateKey', KeyData);
                Other -> Other
            end,
            ets:insert(esaml_privkey_cache, {Path, Key}),
            Key
    end.

-spec load_certificate(Path :: string()) -> binary().
load_certificate(CertPath) ->
    [CertBin] = load_certificate_chain(CertPath),
    CertBin.

%% @doc Loads certificate chain from a file on disk (or ETS memory cache)
-spec load_certificate_chain(Path :: string()) -> [binary()].
load_certificate_chain(CertPath) ->
    case ets:lookup(esaml_certbin_cache, CertPath) of
        [{_, CertChain}] -> CertChain;
        _ ->
            {ok, CertFile} = file:read_file(CertPath),
            CertChain = [CertBin || {'Certificate', CertBin, not_encrypted} <- public_key:pem_decode(CertFile)],
            ets:insert(esaml_certbin_cache, {CertPath, CertChain}),
            CertChain
    end.

%% @doc Reads IDP metadata from a URL (or ETS memory cache) and validates the signature
-spec load_metadata(Url :: string(), Fingerprints :: [string() | binary()]) -> esaml:idp_metadata().
load_metadata(Url, FPs) ->
    Fingerprints = convert_fingerprints(FPs),
    case ets:lookup(esaml_idp_meta_cache, Url) of
        [{Url, Meta}] -> Meta;
        _ ->
            {ok, {{_Ver, 200, _}, _Headers, Body}} = httpc:request(get, {Url, []}, [{autoredirect, true}], []),
            {Xml, _} = xmerl_scan:string(Body, [{namespace_conformant, true}]),
            case xmerl_dsig:verify(Xml, Fingerprints) of
                ok -> ok;
                Err -> error(Err)
            end,
            {ok, Meta = #esaml_idp_metadata{}} = esaml:decode_idp_metadata(Xml),
            ets:insert(esaml_idp_meta_cache, {Url, Meta}),
            Meta
    end.

%% @doc Reads IDP metadata from a URL (or ETS memory cache)
-spec load_metadata(Url :: string()) -> esaml:idp_metadata().
load_metadata(Url) ->
    case ets:lookup(esaml_idp_meta_cache, Url) of
        [{Url, Meta}] -> Meta;
        _ ->
            {ok, {{_Ver, 200, _}, _Headers, Body}} = httpc:request(get, {Url, []}, [{autoredirect, true}], []),
            {Xml, _} = xmerl_scan:string(Body, [{namespace_conformant, true}]),
            {ok, Meta = #esaml_idp_metadata{}} = esaml:decode_idp_metadata(Xml),
            ets:insert(esaml_idp_meta_cache, {Url, Meta}),
            Meta
    end.

%% @doc Checks for a duplicate assertion using ETS tables in memory on all available nodes.
%%
%% This is a helper to be used as a DuplicateFun with esaml_sp:validate_assertion/3.
%% If you aren't using standard erlang distribution for your app, you probably don't
%% want to use this.
-spec check_dupe_ets(esaml:assertion(), Digest :: binary()) -> ok | {error, duplicate_assertion}.
check_dupe_ets(A, Digest) ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    NowSecs = calendar:datetime_to_gregorian_seconds(Now),
    DeathSecs = esaml:stale_time(A),
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
                            ets:new(esaml_privkey_cache, [set, public, named_table]),
                            ets:new(esaml_certbin_cache, [set, public, named_table]),
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

%% @doc Returns a unique xsd:ID string suitable for SAML use.
-spec unique_id() -> string().
unique_id() ->
    <<R:64>> = crypto:rand_bytes(8),
    T = try
        erlang:system_time() % needs ERTS-7.0
    catch
        error:undef ->
            {Mega, Sec, Micro} = erlang:timestamp(),
            Mega * 1000000 * 1000000 + Sec * 1000000 + Micro
    end,
    lists:flatten(io_lib:format("_~.16b~.16b", [R, T])).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

fingerprints_test() ->
    [<<0:128>>] = convert_fingerprints([<<0:128>>]),
    {'EXIT', _} = (catch convert_fingerprints(["testing"])),
    [<<0:32,1,10,3>>] = convert_fingerprints(["00:00:00:00:01:0a:03"]),
    Hash = crypto:hash(sha, <<"testing1234">>),
    [{sha,Hash}] = convert_fingerprints(["SHA:" ++ base64:encode_to_string(Hash)]),
    Sha256 = crypto:hash(sha256, <<"testing1234">>),
    [{sha256,Sha256},{md5,Hash}] = convert_fingerprints(["SHA256:" ++ base64:encode_to_string(Sha256), "md5:" ++ base64:encode_to_string(Hash)]),
    {'EXIT', _} = (catch convert_fingerprints(["SOMEALGO:AAAAA="])).

datetime_test() ->
    "2013-05-02T17:26:53Z" = datetime_to_saml({{2013,5,2},{17,26,53}}),
    {{1990,11,23},{18,1,1}} = saml_to_datetime("1990-11-23T18:01:01Z").

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

-include("xmerl_xpath_macros.hrl").

-record(b, {name, ctext}).

xpath_attr_test() ->
    {Xml, _} = xmerl_scan:string("<a><b name=\"foo\"><c name=\"bar\">hi</c></b><b name=\"foobar\"><c name=\"foofoo\"></c></b></a>", [{namespace_conformant, true}]),
    Ns = [],
    Fun = ?xpath_attr("/a/b[@name='foo']/c/@name", b, name),
    Rec = Fun(#b{}),
    ?assertMatch(#b{name = "bar"}, Rec),
    Fun2 = ?xpath_attr("/a/b[@name='foobar']/c/@name", b, name),
    Rec2 = Fun2(Rec),
    ?assertMatch(#b{name = "foofoo"}, Rec2),
    Fun3 = ?xpath_attr("/a/b[@name='bar']/c/@name", b, name),
    Rec3 = Fun3(Rec2),
    ?assertMatch(Rec2, Rec3).

xpath_attr_trans_test() ->
    {Xml, _} = xmerl_scan:string("<a><b name=\"foo\"><c name=\"bar\">hi</c></b><b name=\"foobar\"><c name=\"foofoo\"></c></b></a>", [{namespace_conformant, true}]),
    Ns = [],
    Fun = ?xpath_attr("/a/b[@name='foobar']/c/@name", b, name, fun(X) -> list_to_atom(X) end),
    Rec = Fun(#b{}),
    ?assertMatch(#b{name = foofoo}, Rec).

xpath_text_test() ->
    {Xml, _} = xmerl_scan:string("<a><b name=\"foo\"><c name=\"bar\">hi</c></b><b name=\"foobar\"><c name=\"foofoo\"></c></b></a>", [{namespace_conformant, true}]),
    Ns = [],
    Fun = ?xpath_text("/a/b[@name='foo']/c/text()", b, ctext),
    Rec = Fun(#b{}),
    ?assertMatch(#b{ctext = "hi"}, Rec),
    Fun2 = ?xpath_text("/a/b[@name='foobar']/c/text()", b, ctext),
    Rec2 = Fun2(Rec),
    ?assertMatch(Rec, Rec2),
    Fun3 = ?xpath_text("/a/b[@name='bar']/c/text()", b, name),
    Rec3 = Fun3(Rec2),
    ?assertMatch(Rec2, Rec3).

-endif.
