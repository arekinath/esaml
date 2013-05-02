%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(xmerl_c14n).

-export([c14n/2, c14n/1, xml_safe_string/2, xml_safe_string/1, canon_name/1]).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("public_key/include/public_key.hrl").

%% @doc Returns the canonical namespace-URI-prefix-resolved version of an XML name.
%% @internal
-spec canon_name(Prefix :: string(), Name :: string() | atom(), Nsp :: #xmlNamespace{}) -> string().
canon_name(Ns, Name, Nsp) ->
   NsPart = case Ns of
      empty -> Nsp#xmlNamespace.default;
      [] -> Nsp#xmlNamespace.default;
      _ ->
         case proplists:get_value(Ns, Nsp#xmlNamespace.nodes) of
            undefined ->
               error({ns_not_found, Ns, Nsp});
            Uri -> atom_to_list(Uri)
         end
   end,
   NamePart = if is_atom(Name) -> atom_to_list(Name); true -> Name end,
   lists:flatten([NsPart | NamePart]).

%% @doc Returns the canonical URI name of an XML element or attribute.
%% @internal
-spec canon_name(#xmlElement{} | #xmlAttribute{}) -> string().
canon_name(#xmlAttribute{name = Name, nsinfo = Exp, namespace = Nsp}) ->
   case Exp of
      {Ns, Nme} -> canon_name(Ns, Nme, Nsp);
      _ -> canon_name([], Name, Nsp)
   end;
canon_name(#xmlElement{name = Name, nsinfo = Exp, namespace = Nsp}) ->
   case Exp of
      {Ns, Nme} -> canon_name(Ns, Nme, Nsp);
      _ -> canon_name([], Name, Nsp)
   end.

%% @doc Compares two XML attributes for c14n purposes
-spec attr_lte(A :: #xmlAttribute{}, B :: #xmlAttribute{}) -> true | false.
attr_lte(AttrA, AttrB) ->
   A = canon_name(AttrA), B = canon_name(AttrB),
   PrefixedA = case AttrA#xmlAttribute.nsinfo of {_, _} -> true; _ -> false end,
   PrefixedB = case AttrB#xmlAttribute.nsinfo of {_, _} -> true; _ -> false end,
   if (PrefixedA) andalso (not PrefixedB) ->
      false;
   (not PrefixedA) andalso (PrefixedB) ->
      true;
   true ->
      A =< B
   end.

%% @doc Cleans out all namespace definitions from an attribute list and returns it sorted.
%% @internal
-spec clean_sort_attrs(Attrs :: [#xmlAttribute{}]) -> [#xmlAttribute{}].
clean_sort_attrs(Attrs) ->
   lists:sort(fun(A,B) ->
      attr_lte(A, B)
   end, lists:filter(fun(Attr) ->
      case Attr#xmlAttribute.nsinfo of
         {"xmlns", _} -> false;
         _ -> case Attr#xmlAttribute.name of
            'xmlns' -> false;
            _ -> true
         end
      end
   end, Attrs)).

%% @doc Returns the list of namespace prefixes "needed" by an element in canonical form
%% @internal
-spec needed_ns(Elem :: #xmlElement{}) -> [string()].
needed_ns(E = #xmlElement{nsinfo = NsInfo, attributes = Attrs, content = Kids}) ->
   NeededNs1 = case NsInfo of
      {Nas, _} -> [Nas];
      _ -> []
   end,
   % show through namespaces that apply at the bottom level? this part of the spec is retarded
   %KidElems = [K || K <- Kids, element(1, K) =:= xmlElement],
   NeededNs2 = NeededNs1, %case KidElems of
      %[] -> [K || {K,V} <- E#xmlElement.namespace#xmlNamespace.nodes];
      %_ -> NeededNs1
   %end,
   lists:foldl(fun(Attr, Needed) ->
      case Attr#xmlAttribute.nsinfo of
         {"xmlns", _} -> Needed;
         {Ns, _Name} ->
            case lists:member(Ns, Needed) of
               true -> Needed;
               _ -> [Ns | Needed]
            end;
         _ -> Needed
      end
   end, NeededNs2, Attrs).

%% @doc Make xml ok to eat, in a non-quoted situation.
%% @internal
-spec xml_safe_string(term()) -> string().
xml_safe_string(Term) -> xml_safe_string(Term, false).

%% @doc Make xml ok to eat
%% @internal
-spec xml_safe_string(String :: term(), Quotes :: boolean()) -> string().
xml_safe_string(Atom, Quotes) when is_atom(Atom) -> xml_safe_string(atom_to_list(Atom), Quotes);
xml_safe_string(Bin, Quotes) when is_binary(Bin) -> xml_safe_string(binary_to_list(Bin), Quotes);
xml_safe_string([], _) -> [];
xml_safe_string(Str, Quotes) when is_list(Str) ->
   [Next | Rest] = Str,
   if
      (not Quotes andalso ([Next] =:= "\n")) -> [Next | xml_safe_string(Rest, Quotes)];
      (Next < 32) orelse (Next > 126) ->
         lists:flatten(["&#x" ++ integer_to_list(Next, 16) ++ ";" | xml_safe_string(Rest, Quotes)]);
      (Quotes andalso ([Next] =:= "\"")) -> lists:flatten(["&quot;" | xml_safe_string(Rest, Quotes)]);
      ([Next] =:= "&") -> lists:flatten(["&amp;" | xml_safe_string(Rest, Quotes)]);
      ([Next] =:= "<") -> lists:flatten(["&lt;" | xml_safe_string(Rest, Quotes)]);
      (not Quotes andalso ([Next] =:= ">")) -> lists:flatten(["&gt;" | xml_safe_string(Rest, Quotes)]);
      true -> [Next | xml_safe_string(Rest, Quotes)]
   end;
xml_safe_string(Term, Quotes) ->
   xml_safe_string(io_lib:format("~p", [Term]), Quotes).

%% @doc Worker function for canonicalisation (c14n). It accumulates the canonical string data
%%      for a given XML "thing" (element/attribute/whatever)
%% @internal
-type xml_thing() :: #xmlDocument{} | #xmlElement{} | #xmlAttribute{} | #xmlPI{} | #xmlText{} | #xmlComment{}.
-spec c14n(XmlThing :: xml_thing(), KnownNs :: [{string(), string()}], ActiveNS :: [string()], Comments :: boolean(), Acc :: [string() | number()]) -> [string() | number()].

c14n(#xmlText{value = Text}, _KnownNS, _ActiveNS, _Comments, Acc) ->
   [xml_safe_string(Text) | Acc];

c14n(#xmlComment{value = Text}, _KnownNS, _ActiveNS, true, Acc) ->
   ["-->", xml_safe_string(Text), "<!--" | Acc];

c14n(#xmlPI{name = Name, value = Value}, _KnownNS, _ActiveNS, _Comments, Acc) ->
   NameString = if is_atom(Name) -> atom_to_list(Name); true -> string:strip(Name) end,
   case string:strip(Value) of
      [] -> ["?>", NameString, "<?" | Acc];
      _ -> ["?>", Value, " ", NameString, "<?" | Acc]
   end;

c14n(#xmlDocument{content = Kids}, KnownNS, ActiveNS, Comments, Acc) ->
   case lists:foldl(fun(Kid, AccIn) ->
      case c14n(Kid, KnownNS, ActiveNS, Comments, AccIn) of
         AccIn -> AccIn;
         Other -> ["\n" | Other]
      end
   end, Acc, Kids) of
      ["\n" | Rest] -> Rest;
      Other -> Other
   end;

c14n(#xmlAttribute{nsinfo = NsInfo, name = Name, value = Value}, _KnownNs, ActiveNS, _Comments, Acc) ->
   case NsInfo of
      {Ns, NName} ->
         case lists:member(Ns, ActiveNS) of
            true -> ["\"",xml_safe_string(Value, true),"=\"",NName,":",Ns," " | Acc];
            _ -> error("attribute namespace is not active")
         end;
      _ ->
         ["\"",xml_safe_string(Value, true),"=\"",atom_to_list(Name)," " | Acc]
   end;

c14n(Elem = #xmlElement{}, KnownNSIn, ActiveNSIn, Comments, Acc) ->
   Namespace = Elem#xmlElement.namespace,
   Default = Namespace#xmlNamespace.default,
   {ActiveNS, ParentDefault} = case ActiveNSIn of
      [{default, P} | Rest] -> {Rest, P};
      Other -> {Other, ''}
   end,
   % add any new namespaces this element has that we haven't seen before
   KnownNS = lists:foldl(fun({Ns, Uri}, Nss) ->
      case proplists:is_defined(Ns, Nss) of
         true -> Nss;
         _ -> [{Ns, atom_to_list(Uri)} | Nss]
      end
   end, KnownNSIn, Namespace#xmlNamespace.nodes),

   % now figure out the minimum set of namespaces we need at this level
   NeededNs = needed_ns(Elem),
   % and all of the attributes that aren't xmlns
   Attrs = clean_sort_attrs(Elem#xmlElement.attributes),

   % we need to append any xmlns: that our parent didn't have (ie, aren't in ActiveNS) but
   % that we need
   NewNS = NeededNs -- ActiveNS,
   NewActiveNS = ActiveNS ++ NewNS,

   % the opening tag
   Acc1 = case Elem#xmlElement.nsinfo of
      {ENs, EName} ->
         [EName, ":", ENs, "<" | Acc];
      _ ->
         [atom_to_list(Elem#xmlElement.name), "<" | Acc]
   end,
   % xmlns definitions
   {Acc2, FinalActiveNS} = if
      not (Default =:= []) andalso not (Default =:= ParentDefault) ->
         {["\"", xml_safe_string(Default, true), " xmlns=\"" | Acc1], [{default, Default} | NewActiveNS]};
      true -> {Acc1, NewActiveNS}
   end,
   Acc3 = lists:foldl(fun(Ns, AccIn) ->
      ["\"",xml_safe_string(proplists:get_value(Ns, KnownNS, ""), true),"=\"",Ns,":"," xmlns" | AccIn]
   end, Acc2, lists:sort(NewNS)),
   % any other attributes
   Acc4 = lists:foldl(fun(Attr, AccIn) ->
      c14n(Attr, KnownNS, FinalActiveNS, Comments, AccIn)
   end, Acc3, Attrs),
   % close the opening tag
   Acc5 = [">" | Acc4],

   % now accumulate all our children
   Acc6 = lists:foldl(fun(Kid, AccIn) ->
      c14n(Kid, KnownNS, FinalActiveNS, Comments, AccIn)
   end, Acc5, Elem#xmlElement.content),

   % and finally add the close tag
   case Elem#xmlElement.nsinfo of
      {Ns, Name} ->
         [">", Name, ":", Ns, "</" | Acc6];
      _ ->
         [">",atom_to_list(Elem#xmlElement.name),"</" | Acc6]
   end;

% I do not give a shit
c14n(_, _KnownNS, _ActiveNS, _Comments, Acc) ->
   Acc.

%% @doc Puts an XML document or element into canonical form, as a string.
-spec c14n(XmlThing :: xml_thing()) -> string().
c14n(Elem) ->
   c14n(Elem, true).

%% @doc Puts an XML document or element into canonical form, as a string.
-spec c14n(XmlThing :: xml_thing(), Comments :: boolean()) -> string().
c14n(Elem, Comments) ->
   lists:flatten(lists:reverse(c14n(Elem, [], [], Comments, []))).


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

canon_name_test() ->
   "urn:foo:Blah" = canon_name("foo", "Blah", #xmlNamespace{nodes = [{"foo", 'urn:foo:'}]}),
   "urn:foo:Blah" = canon_name("foo", 'Blah', #xmlNamespace{nodes = [{"foo", 'urn:foo:'}]}),
   {'EXIT', {{ns_not_found, _, _}, _}} = (catch canon_name("foo", "Blah", #xmlNamespace{})),
   "urn:bar:Blah" = canon_name("bar", "Blah", #xmlNamespace{nodes = [{"bar", 'urn:bar:'}]}).
canon_name_attr_test() ->
   "urn:foo:Blah" = canon_name(#xmlAttribute{name = 'Blah', nsinfo = {"foo", "Blah"}, namespace = #xmlNamespace{nodes = [{"foo", 'urn:foo:'}]}}).
canon_name_elem_test() ->
   "urn:foo:Blah" = canon_name(#xmlElement{name = 'Blah', nsinfo = {"foo", "Blah"}, namespace = #xmlNamespace{nodes = [{"foo", 'urn:foo:'}]}}).

needed_ns_test() ->
   Ns = #xmlNamespace{nodes = [{"foo", 'urn:foo:'}, {"bar", 'urn:bar:'}]},

   E1 = esaml:build_nsinfo(Ns, #xmlElement{name = 'foo:Blah', attributes = [#xmlAttribute{name = 'bar:name', value="foo"}]}),
   ["bar", "foo"] = lists:sort(needed_ns(E1)),

   E2 = esaml:build_nsinfo(Ns, #xmlElement{name = 'Blah', attributes = [#xmlAttribute{name = 'bar:name', value = "foo"}]}),
   ["bar"] = needed_ns(E2),

   E3 = esaml:build_nsinfo(Ns, #xmlElement{name = 'Blah', attributes = [#xmlAttribute{name = 'name', value = "foo"}], content = [#xmlElement{name = 'foo:InnerBlah'}]}),
   [] = needed_ns(E3),

   E4 = esaml:build_nsinfo(Ns, #xmlElement{name = 'Blah'}),
   [] = needed_ns(E4).

xml_safe_string_test() ->
   "foo" = xml_safe_string('foo'),
   "foo \ngeorge" = xml_safe_string(<<"foo \ngeorge">>),
   "foo &lt;&#x5;&gt; = &amp; help" = xml_safe_string(lists:flatten(["foo <", 5, "> = & help"])),
   "&#xE;" = xml_safe_string(<<14>>),
   "\"foo\"" = xml_safe_string("\"foo\"").

c14n_3_1_test() ->
   {Doc, _} = xmerl_scan:string("<?xml version=\"1.0\"?>\n\n<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->", [{namespace_conformant, true}, {document, true}]),
   WithoutComments = "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>",
   WithoutComments = c14n(Doc, false),

   WithComments = "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 --></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->",
   WithComments = c14n(Doc, true).

c14n_3_2_test() ->
   {Doc, _} = xmerl_scan:string("<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>", [{namespace_conformant, true}, {document, true}]),

   Target = "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>",
   Target = c14n(Doc, true).

c14n_3_3_test() ->
   {Doc, _} = xmerl_scan:string("<!DOCTYPE doc [<!ATTLIST e9 attr CDATA \"default\">]>\n<doc>\n   <e1   />\n   <e2   ></e2>\n   <e3   name = \"elem3\"   id=\"elem3\"   />\n   <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"\n      xmlns:b=\"http://www.ietf.org\"\n      xmlns:a=\"http://www.w3.org\"\n      xmlns=\"http://example.org\"/>\n   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n            <e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\"/>\n         </e8>\n      </e7>\n   </e6>\n</doc>", [{namespace_conformant, true}, {document, true}]),

   Target = "<doc>\n   <e1></e1>\n   <e2></e2>\n   <e3 id=\"elem3\" name=\"elem3\"></e3>\n   <e4 id=\"elem4\" name=\"elem4\"></e4>\n   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n   <e6>\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\">\n            <e9></e9>\n         </e8>\n      </e7>\n   </e6>\n</doc>",
   Target = c14n(Doc, true).

c14n_3_4_test() ->
   {Doc, _} = xmerl_scan:string("<!DOCTYPE doc [\n<!ATTLIST normId id ID #IMPLIED>\n<!ATTLIST normNames attr NMTOKENS #IMPLIED>\n]>\n<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n   <normNames attr='   A   &#x20;&#13;&#xa;&#9;   B   '/>\n   <normId id=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n</doc>", [{namespace_conformant, true}, {document, true}]),

   Target = "<doc>\n   <text>First line\n\nSecond line</text>\n   <value>2</value>\n   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n   <normNames attr=\"A  &#xD;&#xA;&#x9; B\"></normNames>\n   <normId id=\"'  &#xD;&#xA;&#x9; '\"></normId>\n</doc>",
   Target = c14n(Doc, true).

-endif.
