%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(esaml_sp_default).
-behaviour(esaml_sp).

-include("esaml.hrl").

-export([init/1, handle_assertion/3, terminate/2]).

init(Req) -> {ok, Req, none}.

handle_assertion(Req, Assertion, State) ->
	Attrs = Assertion#esaml_assertion.attributes,
	Uid = proplists:get_value(uid, Attrs),
	Output = io_lib:format("Hi there!\nYou appear to be ~p\nYour attributes: ~p\n\nThe assertion I got was:\n~p\n", [Uid, Attrs, Assertion]),
	{ok, Req2} = cowboy_req:reply(200, [{<<"Content-Type">>, <<"text/plain">>}], Output, Req),
	{ok, Req2, State}.

terminate(_Req, _State) ->
	ok.
