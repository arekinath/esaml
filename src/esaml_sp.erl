%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(esaml_sp).

-export([behaviour_info/1]).

behaviour_info(callbacks) ->
	[{init, 1}, {handle_assertion, 3}, {terminate, 2}];
behaviour_info(_) ->
	undefined.
