## Digest Access Authentication for Joomla! Control Panel

This plugin implements digest access authentication scheme (RFC 2617 \[1\]).

Integrity protection (i.e., qop=auth-int) is not supported.
However, as far as I know, only Presto-powered Opera (e.g., version 12) supports digest authentication scheme with integrity protection.

#### Security considerations
1. This plugin can be useful if a secure connection (even shared SSL) is not available.
2. It has basic protection against replay attacks by updating the nonce and checking the counter.
3. However, it protects password only. Digest authentication scheme is vulnerable to man-in-the-middle attack.
4. Unfortunately, login prompts for basic and digest authentications are indistinguishable on modern browsers (a potential attacker can impose basic authentication scheme).
5. Needless to say, there is no eavesdropping protection (when not combined with SSL/TLS).

#### Other
* The access level for this plugin must be Public.
* For Joomla 2.5, output buffering may be required, i.e., put
<pre>php\_value output\_buffering 1</pre>
in *administrator/.htaccess* file.

#### References
1. [RFC 2617](https://datatracker.ietf.org/doc/html/rfc2617)

#### Links
* [Joomla! website](https://www.joomla.org/)
