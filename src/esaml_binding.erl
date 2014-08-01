%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc SAML HTTP binding handlers
-module(esaml_binding).

-export([decode_response/2, encode_http_redirect/3, encode_http_post/3]).

-include_lib("xmerl/include/xmerl.hrl").
-define(deflate, <<"urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE">>).

-type uri() :: binary() | string().
-type html_doc() :: binary().
-type xml() :: #xmlElement{} | #xmlDocument{}.

%% @private
-spec xml_payload_type(xml()) -> binary().
xml_payload_type(Xml) ->
    case Xml of
        #xmlDocument{content = [#xmlElement{name = Atom}]} ->
            case lists:suffix("Response", atom_to_list(Atom)) of
                true -> <<"SAMLResponse">>;
                _ -> <<"SAMLRequest">>
            end;
        #xmlElement{name = Atom} ->
            case lists:suffix("Response", atom_to_list(Atom)) of
                true -> <<"SAMLResponse">>;
                _ -> <<"SAMLRequest">>
            end;
        _ -> <<"SAMLRequest">>
    end.

%% @doc Unpack and parse a SAMLResponse with given encoding
-spec decode_response(SAMLEncoding :: binary(), SAMLResponse :: binary()) -> #xmlDocument{}.
decode_response(?deflate, SAMLResponse) ->
	XmlData = binary_to_list(zlib:unzip(base64:decode(SAMLResponse))),
	{Xml, _} = xmerl_scan:string(XmlData, [{namespace_conformant, true}]),
    Xml;
decode_response(_, SAMLResponse) ->
	Data = base64:decode(SAMLResponse),
    XmlData = case (catch zlib:unzip(Data)) of
        {'EXIT', _} -> binary_to_list(Data);
        Bin -> binary_to_list(Bin)
    end,
	{Xml, _} = xmerl_scan:string(XmlData, [{namespace_conformant, true}]),
    Xml.

%% @doc Encode a SAMLRequest (or SAMLResponse) as an HTTP-REDIRECT binding
%%
%% Returns the URI that should be the target of redirection.
-spec encode_http_redirect(IDPTarget :: uri(), SignedXml :: xml(), RelayState :: binary()) -> uri().
encode_http_redirect(IdpTarget, SignedXml, RelayState) ->
    Type = xml_payload_type(SignedXml),
	Req = lists:flatten(xmerl:export([SignedXml], xmerl_xml)),
    Param = edoc_lib:escape_uri(base64:encode_to_string(zlib:zip(Req))),
    RelayStateEsc = edoc_lib:escape_uri(binary_to_list(RelayState)),
    iolist_to_binary([IdpTarget, "?SAMLEncoding=", ?deflate, "&", Type, "=", Param, "&RelayState=", RelayStateEsc]).

%% @doc Encode a SAMLRequest (or SAMLResponse) as an HTTP-POST binding
%%
%% Returns the HTML document to be sent to the browser, containing a
%% form and javascript to automatically submit it.
-spec encode_http_post(IDPTarget :: uri(), SignedXml :: xml(), RelayState :: binary()) -> html_doc().
encode_http_post(IdpTarget, SignedXml, RelayState) ->
    Type = xml_payload_type(SignedXml),
	Req = lists:flatten(xmerl:export([SignedXml], xmerl_xml)),
    generate_post_html(Type, IdpTarget, base64:encode(Req), RelayState).

generate_post_html(Type, Dest, Req, RelayState) ->
    iolist_to_binary([<<"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">
<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">
<head>
<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\" />
<title>POST data</title>
</head>
<body onload=\"document.forms[0].submit()\">
<noscript>
<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>
</noscript>
<form method=\"post\" action=\"">>,Dest,<<"\">
<input type=\"hidden\" name=\"">>,Type,<<"\" value=\"">>,Req,<<"\" />
<input type=\"hidden\" name=\"RelayState\" value=\"">>,RelayState,<<"\" />
<noscript><input type=\"submit\" value=\"Submit\" /></noscript>
</form>
</body>
</html>">>]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-endif.