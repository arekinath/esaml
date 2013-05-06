%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% data types / message records

-record(esaml_org, {name :: string(), displayname :: string(), url :: string()}).

-record(esaml_contact, {name :: string(), email :: string()}).

-record(esaml_sp_metadata, {org :: #esaml_org{},
	tech :: #esaml_contact{},
	signed_requests :: boolean(),
	signed_assertions :: boolean(),
	certificate :: binary(),
	entity_id :: string(),
	consumer_location :: string()}).

-record(esaml_authnreq, {issue_instant :: string(),
	destination :: string(), issuer :: string(), consumer_location :: string()}).

-record(esaml_subject, {name :: string(),
	confirmation_method = bearer :: atom(), notonorafter :: string()}).

-record(esaml_assertion, {version = "2.0" :: string(), issue_instant :: string(), recipient :: string(), issuer :: string(), subject :: #esaml_subject{}, conditions = [], attributes = []}).

-type esaml_status_code() :: success | request_error | response_error | bad_version | authn_failed | bad_attr | denied | bad_binding.
-record(esaml_response, {version = "2.0" :: string(), issue_instant :: string(), destination :: string(), issuer :: string(), status :: esaml_status_code(), assertion :: #esaml_assertion{}}).

%% state records

-record(esaml_sp, {module, org = #esaml_org{}, tech = #esaml_contact{}, key, certificate, sign_requests = false, sign_assertions = true, sign_metadata = false, trusted_fingerprints = [], metadata_uri, consume_uri}).
