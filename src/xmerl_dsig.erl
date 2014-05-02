%% -*- coding: utf-8 -*-
%%
%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(xmerl_dsig).

-export([verify/1, verify/2, sign/3, strip/1, digest/1]).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("public_key/include/public_key.hrl").

-type xml_thing() :: #xmlDocument{} | #xmlElement{} | #xmlAttribute{} | #xmlPI{} | #xmlText{} | #xmlComment{}.

%% @doc Returns an xmlelement without any ds:Signature elements that are inside it.
-spec strip(Element :: #xmlElement{} | #xmlDocument{}) -> #xmlElement{}.
strip(#xmlDocument{content = Kids} = Doc) ->
    NewKids = [if (element(1,K) =:= xmlElement) -> strip(K); true -> K end || K <- Kids],
    Doc#xmlDocument{content = NewKids};

strip(#xmlElement{content = Kids} = Elem) ->
    NewKids = lists:filter(fun(Kid) ->
        case xmerl_c14n:canon_name(Kid) of
            "http://www.w3.org/2000/09/xmldsig#Signature" -> false;
            _Name -> true
        end
    end, Kids),
    Elem#xmlElement{content = NewKids}.

%% @doc Signs the given XML element by creating a ds:Signature element within it, returning
%%      the element with the signature added.
%%
%% Don't use "ds" as a namespace prefix in the envelope document, or things will go baaaad.
-spec sign(Element :: #xmlElement{}, PrivateKey :: rsa_private_key(), CertBin :: binary()) -> #xmlElement{}.
sign(ElementIn, PrivateKey, CertBin) ->
    % get rid of any previous signature
    ElementStrip = strip(ElementIn),

    % make sure the root element has an ID... if it doesn't yet, add one
    {Element, Id} = case lists:keyfind('ID', 2, ElementStrip#xmlElement.attributes) of
        #xmlAttribute{value = CapId} -> {ElementStrip, CapId};
        _ ->
            case lists:keyfind('id', 2, ElementStrip#xmlElement.attributes) of
                #xmlAttribute{value = LowId} -> {ElementStrip, LowId};
                _ ->
                    NewId = uuid:to_string(uuid:uuid1()),
                    Attr = #xmlAttribute{name = 'ID', value = NewId, namespace = #xmlNamespace{}},
                    NewAttrs = [Attr | ElementStrip#xmlElement.attributes],
                    Elem = ElementStrip#xmlElement{attributes = NewAttrs},
                    {Elem, NewId}
            end
    end,

    % first we need the digest, to generate our SignedInfo element
    CanonXml = xmerl_c14n:c14n(Element),
    DigestValue = base64:encode_to_string(
        crypto:sha(unicode:characters_to_binary(CanonXml, unicode, utf8))),

    Ns = #xmlNamespace{nodes = [{"ds", 'http://www.w3.org/2000/09/xmldsig#'}]},
    SigInfo = esaml_util:build_nsinfo(Ns, #xmlElement{
        name = 'ds:SignedInfo',
        content = [
            #xmlElement{name = 'ds:CanonicalizationMethod',
                attributes = [#xmlAttribute{name = 'Algorithm', value = "http://www.w3.org/2001/10/xml-exc-c14n#"}]},
            #xmlElement{name = 'ds:SignatureMethod',
                attributes = [#xmlAttribute{name = 'Algorithm', value = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"}]},
            #xmlElement{name = 'ds:Reference',
                attributes = [#xmlAttribute{name = 'URI', value = lists:flatten(["#" | Id])}],
                content = [
                    #xmlElement{name = 'ds:Transforms', content = [
                        #xmlElement{name = 'ds:Transform',
                            attributes = [#xmlAttribute{name = 'Algorithm', value = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"}]},
                        #xmlElement{name = 'ds:Transform',
                            attributes = [#xmlAttribute{name = 'Algorithm', value = "http://www.w3.org/2001/10/xml-exc-c14n#"}]}]},
                    #xmlElement{name = 'ds:DigestMethod',
                        attributes = [#xmlAttribute{name = 'Algorithm', value = "http://www.w3.org/2000/09/xmldsig#sha1"}]},
                    #xmlElement{name = 'ds:DigestValue',
                        content = [#xmlText{value = DigestValue}]}
                ]}
        ]
    }),

    % now we sign the SignedInfo element...
    SigInfoCanon = xmerl_c14n:c14n(SigInfo),
    Data = unicode:characters_to_binary(SigInfoCanon, unicode, utf8),

    Signature = public_key:sign(Data, sha, PrivateKey),
    Sig64 = base64:encode_to_string(Signature),
    Cert64 = base64:encode_to_string(CertBin),

    % and wrap it all up with the signature and certificate
    SigElem = esaml_util:build_nsinfo(Ns, #xmlElement{
        name = 'ds:Signature',
        attributes = [#xmlAttribute{name = 'xmlns:ds', value = "http://www.w3.org/2000/09/xmldsig#"}],
        content = [
            SigInfo,
            #xmlElement{name = 'ds:SignatureValue', content = [#xmlText{value = Sig64}]},
            #xmlElement{name = 'ds:KeyInfo', content = [
                #xmlElement{name = 'ds:X509Data', content = [
                    #xmlElement{name = 'ds:X509Certificate', content = [#xmlText{value = Cert64} ]}]}]}
        ]
    }),

    Element#xmlElement{content = [SigElem | Element#xmlElement.content]}.

%% @doc Returns the canonical SHA-1 digest of an (optionally signed) element
%%
%% Strips any XML digital signatures and applies any relevant InclusiveNamespaces
%% before generating the digest.
-spec digest(Element :: #xmlElement{}) -> binary().
digest(Element) ->
    DsNs = [{"ds", 'http://www.w3.org/2000/09/xmldsig#'},
        {"ec", 'http://www.w3.org/2001/10/xml-exc-c14n#'}],

    Txs = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform[@Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#']", Element, [{namespace, DsNs}]),
    InclNs = case Txs of
        [C14nTx = #xmlElement{}] ->
            case xmerl_xpath:string("ec:InclusiveNamespaces/@PrefixList", C14nTx, [{namespace, DsNs}]) of
                [] -> [];
                [#xmlAttribute{value = NsList}] -> string:tokens(NsList, " ,")
            end;
        _ -> []
    end,

    CanonXml = xmerl_c14n:c14n(strip(Element), false, InclNs),
    CanonXmlUtf8 = unicode:characters_to_binary(CanonXml, unicode, utf8),
    crypto:sha(CanonXmlUtf8).

%% @doc Verifies an XML digital signature on the given element.
%%
%% Fingerprints is a list of valid cert fingerprints that can be
%% accepted.
%%
%% Will throw badmatch errors if you give it XML that is not signed
%% according to the xml-dsig spec. If you're using something other
%% than rsa+sha1 this will asplode. Don't say I didn't warn you.
-spec verify(Element :: #xmlElement{}, Fingerprints :: [binary()] | any) -> ok | {error, bad_digest | bad_signature | cert_not_accepted}.
verify(Element, Fingerprints) ->
    DsNs = [{"ds", 'http://www.w3.org/2000/09/xmldsig#'},
        {"ec", 'http://www.w3.org/2001/10/xml-exc-c14n#'}],

    [#xmlAttribute{value = "http://www.w3.org/2001/10/xml-exc-c14n#"}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm", Element, [{namespace, DsNs}]),
    [#xmlAttribute{value = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm", Element, [{namespace, DsNs}]),
    [C14nTx = #xmlElement{}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform[@Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#']", Element, [{namespace, DsNs}]),
    InclNs = case xmerl_xpath:string("ec:InclusiveNamespaces/@PrefixList", C14nTx, [{namespace, DsNs}]) of
        [] -> [];
        [#xmlAttribute{value = NsList}] -> string:tokens(NsList, " ,")
    end,

    CanonXml = xmerl_c14n:c14n(strip(Element), false, InclNs),
    CanonXmlUtf8 = unicode:characters_to_binary(CanonXml, unicode, utf8),
    CanonSha = crypto:sha(CanonXmlUtf8),

    [#xmlText{value = Sha64}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue/text()", Element, [{namespace, DsNs}]),
    CanonSha2 = base64:decode(Sha64),

    if not (CanonSha =:= CanonSha2) ->
        {error, bad_digest};

    true ->
        [SigInfo] = xmerl_xpath:string("ds:Signature/ds:SignedInfo", Element, [{namespace, DsNs}]),
        SigInfoCanon = xmerl_c14n:c14n(SigInfo),
        Data = list_to_binary(SigInfoCanon),

        [#xmlText{value = Sig64}] = xmerl_xpath:string("ds:Signature//ds:SignatureValue/text()", Element, [{namespace, DsNs}]),
        Sig = base64:decode(Sig64),

        [#xmlText{value = Cert64}] = xmerl_xpath:string("ds:Signature//ds:X509Certificate/text()", Element, [{namespace, DsNs}]),
        CertBin = base64:decode(Cert64),
        CertHash = crypto:sha(CertBin),

        Cert = public_key:pkix_decode_cert(CertBin, plain),
        {_, KeyBin} = Cert#'Certificate'.tbsCertificate#'TBSCertificate'.subjectPublicKeyInfo#'SubjectPublicKeyInfo'.subjectPublicKey,
        Key = public_key:pem_entry_decode({'RSAPublicKey', KeyBin, not_encrypted}),

        case public_key:verify(Data, sha, Sig, Key) of
            true ->
                case Fingerprints of
                    any ->
                        ok;
                    _ ->
                        case lists:member(CertHash, Fingerprints) of
                            true ->
                                ok;
                            false ->
                                {error, cert_not_accepted}
                        end
                end;
            false ->
                {error, bad_signature}
        end
    end.

%% @doc Verifies an XML digital signature, trusting any valid certificate.
%%
%% This is really not recommended for production use, but it's handy in
%% testing/development.
-spec verify(Element :: xml_thing()) -> ok | {error, bad_digest | bad_signature | cert_not_accepted}.
verify(Element) ->
    verify(Element, any).


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

verify_valid_test() ->
    {Doc, _} = xmerl_scan:string("<?xml version=\"1.0\"?><x:foo ID=\"9616e6c0-f525-11b7-afb7-5cf9dd711ed3\" xmlns:x=\"urn:foo:x:\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#9616e6c0-f525-11b7-afb7-5cf9dd711ed3\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>xPVYXCs5uMMmIbfTiTZ5R5DVhTU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>rYk+WAghakHfR9VtpLz3AkMD1xLD1wISfNgch9+i+PC72RqhmfeMCZMkBaw0EO+CTKEoFBQIQaJYlEj8rIG+XN+8HyBV75BrMKZs1rdN+459Rpn2FOOJuHVb2jLDPecC9Ok/DGaNu6lol60hG9di66EZkL8ErQCuCeZqiw9tiXMUPQyVa2GxqT2UeXvJ5YtkNMDweUc3HhEnTG3ovYt1vOZt679w4N0HAwUa9rk40Z12fOTx77BbMICZ9Q4N2m3UbaFU24YHYpHR+WUTiwzXcmdkrHiE5IF37h7rTKAEixD2bTojaefmrobAz0+mBhCqBPcbfNLhLrpT43xhMenjpA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDfTCCAmWgAwIBAgIJANCSQXrTqpDjMA0GCSqGSIb3DQEBBQUAMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApRdWVlbnNsYW5kMREwDwYDVQQHDAhCcmlzYmFuZTEMMAoGA1UECgwDRm9vMRAwDgYDVQQDDAdzYW1saWRwMB4XDTEzMDQyOTA2MTAyOVoXDTIzMDQyOTA2MTAyOVowVTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClF1ZWVuc2xhbmQxETAPBgNVBAcMCEJyaXNiYW5lMQwwCgYDVQQKDANGb28xEDAOBgNVBAMMB3NhbWxpZHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFhBuEO3fX+FlyT2YYzozxmXNXEmQjksigJSKD4hvsgsyGyl1iLkqNT6IbkuMXoyJG6vXufMNVLoktcLBd6eu6LQwwRjSU62AVCWZhIJP8U6lHqVsxiP90h7/b1zM7Hm9uM9RHtG+nKB7W0xNRihG8BUQOocSaLIMZZXqDPW1h/UvUqmpEzCtT0kJyXX0UAmDHzTYWHt8dqOYdcO2RAlJX0UKnwG1bHjTAfw01lJeOZiF66kH777nStYSElrHXr0NmCO/2gt6ouEnnUqJWDWRzaLbzhMLmGj83lmPgwZCBbIbnbQWLYPQ438EWfEYELq9nSQrgfUmmDPb4rtsQOXqZAgMBAAGjUDBOMB0GA1UdDgQWBBT64y2JSqY96YTYv1QbFyCPp3To/zAfBgNVHSMEGDAWgBT64y2JSqY96YTYv1QbFyCPp3To/zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAecr+C4w3LYAU4pCbLAW2BbFWGZRqBAr6ZKZKQrrqSMUJUiRDoKc5FYJrkjl/sGHAe3b5vBrU3lb/hpSiKXVf4/zBP7uqAF75B6LwnMwYpPcXlnRyPngQcdTL5EyQT5vwqv+H3zB64TblMYbsvqm6+1ippRNq4IXQX+3NGTEkhh0xgH+e3wE8BjjiygDu0MqopaIVPemMVQIm3HI+4jmf60bz8GLD1J4dj5CvyW1jQCXu2K2fcS1xJS0FLrxh/QxR0+3prGkYiZeOWE/dHlTTvQLB+NftyamUthVxMFe8dvXMTix/egox+ps2NuO2XTkDaeeRFjUhPhS8SvZO9l0lZ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><x:name>blah</x:name></x:foo>", [{namespace_conformant, true}]),
    ok = verify(Doc),
    ok = verify(Doc, [<<198,86,10,182,119,241,20,3,198,88,35,42,145,76,251,113,52,21,246,156>>]).

verify_invalid_test() ->
    {Doc, _} = xmerl_scan:string("<x:foo xmlns:x=\"urn:foo:x:\"><x:name>blah</x:name></x:foo>", [{namespace_conformant, true}]),
    {'EXIT', _} = (catch verify(Doc)).

verify_unknown_cert_test() ->
    {Doc, _} = xmerl_scan:string("<?xml version=\"1.0\"?><x:foo ID=\"9616e6c0-f525-11b7-afb7-5cf9dd711ed3\" xmlns:x=\"urn:foo:x:\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#9616e6c0-f525-11b7-afb7-5cf9dd711ed3\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>xPVYXCs5uMMmIbfTiTZ5R5DVhTU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>rYk+WAghakHfR9VtpLz3AkMD1xLD1wISfNgch9+i+PC72RqhmfeMCZMkBaw0EO+CTKEoFBQIQaJYlEj8rIG+XN+8HyBV75BrMKZs1rdN+459Rpn2FOOJuHVb2jLDPecC9Ok/DGaNu6lol60hG9di66EZkL8ErQCuCeZqiw9tiXMUPQyVa2GxqT2UeXvJ5YtkNMDweUc3HhEnTG3ovYt1vOZt679w4N0HAwUa9rk40Z12fOTx77BbMICZ9Q4N2m3UbaFU24YHYpHR+WUTiwzXcmdkrHiE5IF37h7rTKAEixD2bTojaefmrobAz0+mBhCqBPcbfNLhLrpT43xhMenjpA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDfTCCAmWgAwIBAgIJANCSQXrTqpDjMA0GCSqGSIb3DQEBBQUAMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApRdWVlbnNsYW5kMREwDwYDVQQHDAhCcmlzYmFuZTEMMAoGA1UECgwDRm9vMRAwDgYDVQQDDAdzYW1saWRwMB4XDTEzMDQyOTA2MTAyOVoXDTIzMDQyOTA2MTAyOVowVTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClF1ZWVuc2xhbmQxETAPBgNVBAcMCEJyaXNiYW5lMQwwCgYDVQQKDANGb28xEDAOBgNVBAMMB3NhbWxpZHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFhBuEO3fX+FlyT2YYzozxmXNXEmQjksigJSKD4hvsgsyGyl1iLkqNT6IbkuMXoyJG6vXufMNVLoktcLBd6eu6LQwwRjSU62AVCWZhIJP8U6lHqVsxiP90h7/b1zM7Hm9uM9RHtG+nKB7W0xNRihG8BUQOocSaLIMZZXqDPW1h/UvUqmpEzCtT0kJyXX0UAmDHzTYWHt8dqOYdcO2RAlJX0UKnwG1bHjTAfw01lJeOZiF66kH777nStYSElrHXr0NmCO/2gt6ouEnnUqJWDWRzaLbzhMLmGj83lmPgwZCBbIbnbQWLYPQ438EWfEYELq9nSQrgfUmmDPb4rtsQOXqZAgMBAAGjUDBOMB0GA1UdDgQWBBT64y2JSqY96YTYv1QbFyCPp3To/zAfBgNVHSMEGDAWgBT64y2JSqY96YTYv1QbFyCPp3To/zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAecr+C4w3LYAU4pCbLAW2BbFWGZRqBAr6ZKZKQrrqSMUJUiRDoKc5FYJrkjl/sGHAe3b5vBrU3lb/hpSiKXVf4/zBP7uqAF75B6LwnMwYpPcXlnRyPngQcdTL5EyQT5vwqv+H3zB64TblMYbsvqm6+1ippRNq4IXQX+3NGTEkhh0xgH+e3wE8BjjiygDu0MqopaIVPemMVQIm3HI+4jmf60bz8GLD1J4dj5CvyW1jQCXu2K2fcS1xJS0FLrxh/QxR0+3prGkYiZeOWE/dHlTTvQLB+NftyamUthVxMFe8dvXMTix/egox+ps2NuO2XTkDaeeRFjUhPhS8SvZO9l0lZ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><x:name>blah</x:name></x:foo>", [{namespace_conformant, true}]),
    {error, cert_not_accepted} = verify(Doc, [<<198>>]).

verify_bad_digest_test() ->
    {Doc, _} = xmerl_scan:string("<?xml version=\"1.0\"?><x:foo ID=\"9616e6c0-f525-11b7-afb7-5cf9dd711ed3\" xmlns:x=\"urn:foo:x:\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#9616e6c0-f525-11b7-afb7-5cf9dd711ed3\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>xPVYXCs5uMMmIbfTiTZ5R5DVhTU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate></ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><x:name>b1ah</x:name></x:foo>", [{namespace_conformant, true}]),
    {error, bad_digest} = verify(Doc).

verify_bad_signature_test() ->
    {Doc, _} = xmerl_scan:string("<?xml version=\"1.0\"?><x:foo ID=\"9616e6c0-f525-11b7-afb7-5cf9dd711ed3\" xmlns:x=\"urn:foo:x:\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#9616e6c0-f525-11b7-afb7-5cf9dd711ed3\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>FzMI9JNIp2IYjB5pnReqi+khe1k=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>rYk+WAghakHfR9VtpLz3AkMD1xLD1wISfNgch9+i+PC72RqhmfeMCZMkBaw0EO+CTKEoFBQIQaJYlEj8rIG+XN+8HyBV75BrMKZs1rdN+459Rpn2FOOJuHVb2jLDPecC9Ok/DGaNu6lol60hG9di66EZkL8ErQCuCeZqiw9tiXMUPQyVa2GxqT2UeXvJ5YtkNMDweUc3HhEnTG3ovYt1vOZt679w4N0HAwUa9rk40Z12fOTx77BbMICZ9Q4N2m3UbaFU24YHYpHR+WUTiwzXcmdkrHiE5IF37h7rTKAEixD2bTojaefmrobAz0+mBhCqBPcbfNLhLrpT43xhMenjpA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDfTCCAmWgAwIBAgIJANCSQXrTqpDjMA0GCSqGSIb3DQEBBQUAMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApRdWVlbnNsYW5kMREwDwYDVQQHDAhCcmlzYmFuZTEMMAoGA1UECgwDRm9vMRAwDgYDVQQDDAdzYW1saWRwMB4XDTEzMDQyOTA2MTAyOVoXDTIzMDQyOTA2MTAyOVowVTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClF1ZWVuc2xhbmQxETAPBgNVBAcMCEJyaXNiYW5lMQwwCgYDVQQKDANGb28xEDAOBgNVBAMMB3NhbWxpZHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFhBuEO3fX+FlyT2YYzozxmXNXEmQjksigJSKD4hvsgsyGyl1iLkqNT6IbkuMXoyJG6vXufMNVLoktcLBd6eu6LQwwRjSU62AVCWZhIJP8U6lHqVsxiP90h7/b1zM7Hm9uM9RHtG+nKB7W0xNRihG8BUQOocSaLIMZZXqDPW1h/UvUqmpEzCtT0kJyXX0UAmDHzTYWHt8dqOYdcO2RAlJX0UKnwG1bHjTAfw01lJeOZiF66kH777nStYSElrHXr0NmCO/2gt6ouEnnUqJWDWRzaLbzhMLmGj83lmPgwZCBbIbnbQWLYPQ438EWfEYELq9nSQrgfUmmDPb4rtsQOXqZAgMBAAGjUDBOMB0GA1UdDgQWBBT64y2JSqY96YTYv1QbFyCPp3To/zAfBgNVHSMEGDAWgBT64y2JSqY96YTYv1QbFyCPp3To/zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAecr+C4w3LYAU4pCbLAW2BbFWGZRqBAr6ZKZKQrrqSMUJUiRDoKc5FYJrkjl/sGHAe3b5vBrU3lb/hpSiKXVf4/zBP7uqAF75B6LwnMwYpPcXlnRyPngQcdTL5EyQT5vwqv+H3zB64TblMYbsvqm6+1ippRNq4IXQX+3NGTEkhh0xgH+e3wE8BjjiygDu0MqopaIVPemMVQIm3HI+4jmf60bz8GLD1J4dj5CvyW1jQCXu2K2fcS1xJS0FLrxh/QxR0+3prGkYiZeOWE/dHlTTvQLB+NftyamUthVxMFe8dvXMTix/egox+ps2NuO2XTkDaeeRFjUhPhS8SvZO9l0lZ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><x:name>b1ah</x:name></x:foo>", [{namespace_conformant, true}]),
    {error, bad_signature} = verify(Doc).

test_sign_key() ->
    CertBin = <<48,130,1,173,48,130,1,103,160,3,2,1,2,2,9,0,155,15,116,226,54,
                     209,145,118,48,13,6,9,42,134,72,134,247,13,1,1,5,5,0,48,66,49,
                     11,48,9,6,3,85,4,6,19,2,88,88,49,21,48,19,6,3,85,4,7,12,12,68,
                     101,102,97,117,108,116,32,67,105,116,121,49,28,48,26,6,3,85,4,
                     10,12,19,68,101,102,97,117,108,116,32,67,111,109,112,97,110,
                     121,32,76,116,100,48,30,23,13,49,51,48,53,48,50,48,54,48,48,51,
                     52,90,23,13,50,51,48,53,48,50,48,54,48,48,51,52,90,48,66,49,11,
                     48,9,6,3,85,4,6,19,2,88,88,49,21,48,19,6,3,85,4,7,12,12,68,101,
                     102,97,117,108,116,32,67,105,116,121,49,28,48,26,6,3,85,4,10,
                     12,19,68,101,102,97,117,108,116,32,67,111,109,112,97,110,121,
                     32,76,116,100,48,76,48,13,6,9,42,134,72,134,247,13,1,1,1,5,0,3,
                     59,0,48,56,2,49,0,205,22,207,74,179,213,185,209,141,250,249,
                     250,90,172,216,115,36,248,202,38,35,250,140,203,148,166,140,
                     157,135,4,125,142,129,148,170,140,171,183,154,14,45,63,60,99,
                     68,109,247,155,2,3,1,0,1,163,80,48,78,48,29,6,3,85,29,14,4,22,
                     4,20,217,116,226,255,194,252,218,129,177,246,103,26,72,200,32,
                     122,187,222,157,58,48,31,6,3,85,29,35,4,24,48,22,128,20,217,
                     116,226,255,194,252,218,129,177,246,103,26,72,200,32,122,187,
                     222,157,58,48,12,6,3,85,29,19,4,5,48,3,1,1,255,48,13,6,9,42,
                     134,72,134,247,13,1,1,5,5,0,3,49,0,66,238,235,142,200,32,210,
                     110,101,63,239,197,154,4,128,26,192,193,3,10,250,95,242,106,
                     110,98,1,100,8,229,143,141,180,42,219,11,94,149,187,74,164,45,
                     37,79,228,71,103,175>>,
    Key = {'RSAPrivateKey','two-prime',
                                    31566101599917470453416065772975030637050267921499643485243561060280673467204714198784209398028051515492879184033691,
                                    65537,
                                    18573989898799417322963879097353191425554564320258643998367520268996258880659389403428515182780052189009731243940089,
                                    6176779427556368800436097873318862403597526763704995657789,
                                    5110446628398630915379329225736384395133647699411033691319,
                                    3629707330424811560529090457257061337677158715287651140161,
                                    3337927863271614430989022488622788202360360154126504237157,
                                    3289563093010152325531764796397097457944832648507910197015,
                                    asn1_NOVALUE},
    {Key, CertBin}.

sign_and_verify_test() ->
    {Doc, _} = xmerl_scan:string("<x:foo id=\"test\" xmlns:x=\"urn:foo:x:\"><x:name>blah</x:name></x:foo>", [{namespace_conformant, true}]),
    {Key, CertBin} = test_sign_key(),
    SignedXml = sign(Doc, Key, CertBin),
    Doc = strip(SignedXml),
    false = (Doc =:= SignedXml),
    ok = verify(SignedXml, [crypto:sha(CertBin)]).

sign_generate_id_test() ->
    {Doc, _} = xmerl_scan:string("<x:foo xmlns:x=\"urn:foo:x:\"><x:name>blah</x:name></x:foo>", [{namespace_conformant, true}]),
    {Key, CertBin} = test_sign_key(),
    SignedXml = sign(Doc, Key, CertBin),
    Ns = [{"ds", 'http://www.w3.org/2000/09/xmldsig#'}],
    [#xmlAttribute{name = 'ID', value = RootId}] = xmerl_xpath:string("@ID", SignedXml, [{namespace, Ns}]),
    [#xmlAttribute{value = "#" ++ RootId}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:Reference/@URI", SignedXml, [{namespace, Ns}]).

utf8_test() ->
    Name = <<208,152,208,179,208,190,209,128,209,140,32,208,154,
      208,176,209,128,209,139,208,188,208,190,208,178,32>>,
    ThisPerson = <<227,129,157,227,129,174,228,186,186,10>>,
    XmlData = <<"<x:foo xmlns:x=\"urn:foo:x#\"><x:name attr=\"",Name/binary,"\">",ThisPerson/binary,"</x:name></x:foo>">>,
    {Doc, _} = xmerl_scan:string(binary_to_list(XmlData), [{namespace_conformant, true}]),
    {Key, CertBin} = test_sign_key(),
    SignedXml = sign(Doc, Key, CertBin),
    Ns = [{"ds", 'http://www.w3.org/2000/09/xmldsig#'}, {"x", 'urn:foo:x#'}],
    [#xmlAttribute{name = 'ID', value = RootId}] = xmerl_xpath:string("@ID", SignedXml, [{namespace, Ns}]),
    [#xmlAttribute{value = "#" ++ RootId}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:Reference/@URI", SignedXml, [{namespace, Ns}]),
    AttrValue = unicode:characters_to_list(Name),
    [#xmlAttribute{name = 'attr', value = AttrValue}] = xmerl_xpath:string("x:name/@attr", SignedXml, [{namespace, Ns}]),
    TextValue = unicode:characters_to_list(ThisPerson),
    [#xmlText{value = TextValue}] = xmerl_xpath:string("x:name/text()", SignedXml, [{namespace, Ns}]),
    ok = verify(SignedXml, [crypto:sha(CertBin)]).

-endif.
