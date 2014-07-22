%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% data types / message records


-record(esaml_org, {name :: string() | esaml:localized_strings(),
	displayname :: string() | esaml:localized_strings(),
	url :: string() | esaml:localized_strings()}).

-record(esaml_contact, {name :: string(), email :: string()}).

-record(esaml_sp_metadata, {org :: esaml:org(),
	tech :: esaml:contact(),
	signed_requests :: boolean(),
	signed_assertions :: boolean(),
	certificate :: binary(),
	entity_id :: string(),
	consumer_location :: string(),
	logout_location :: string()}).

-record(esaml_idp_metadata, {org :: esaml:org(),
	tech :: esaml:contact(),
	signed_requests :: boolean(),
	certificate :: binary(),
	entity_id :: string(),
	login_location :: string(),
	logout_location :: string(),
	name_format = unknown :: esaml:name_format()}).

-record(esaml_authnreq, {version = "2.0", issue_instant :: string(),
	destination :: string(), issuer :: string(), consumer_location :: string()}).

-record(esaml_subject, {name :: string(),
	confirmation_method = bearer :: atom(), notonorafter :: string()}).

-record(esaml_assertion, {version = "2.0" :: string(), issue_instant :: string(),
	recipient :: string(), issuer :: string(), subject :: esaml:subject(),
	conditions = [], attributes = []}).

-record(esaml_logoutreq, {version = "2.0", issue_instant :: string(),
	destination :: string(), issuer :: string(), name :: string(),
	reason :: esaml:logout_reason()}).

-record(esaml_logoutresp, {version = "2.0", issue_instant :: string(),
	destination :: string(), issuer :: string(), status :: esaml:status_code()}).

-record(esaml_response, {version = "2.0" :: string(), issue_instant :: string(),
	destination :: string(), issuer :: string(), status :: esaml:status_code(),
	assertion :: esaml:assertion()}).

%% state records

-record(esaml_sp, {
	org = #esaml_org{} :: esaml:org(), tech = #esaml_contact{} :: esaml:contact(),
	key :: binary(), certificate :: binary(),
	sp_sign_requests = false, idp_signs_assertions = true, idp_signs_envelopes = true,
	idp_signs_logout_requests = true, sp_sign_metadata = false,
	trusted_fingerprints :: [string() | binary()],
	metadata_uri :: string(), consume_uri :: string(), logout_uri :: string()}).
