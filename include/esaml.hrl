%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-record(esaml_metadata, {org_name, org_displayname, org_url, tech_name, tech_email, sign_req, sign_ass, cert, entity_id, consumer_location}).
-record(esaml_authnreq, {issue_instant, destination, issuer, consumer_location}).
