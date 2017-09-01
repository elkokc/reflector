# reflector ![](https://github.com/elkokc/reflector/blob/master/screenshot/release-v1.0-blue.svg)


# Description
Burp Suite extension is able to find reflected XSS on page in real-time while browsing on web-site and include some features as:
* Highlighting of reflection in the response tab.
* Test which symbols is allowed in this reflection.
* Analyze  of reflection context.
* Content-Type whitelist.
 
 
 # How to use
After plugin install you just need to start work with the tested web-application. Every time when reflection is found, reflector defines severity and generates burp issue.
![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/reflector_demo1.gif)

Each burp issue includes detailed info about reflected parameter, such as:
* Symbols that allowed in this reflection.
* Highlighting of reflection value in response.
* Reflection context analyze.

# Allowed sybmols analyse
![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/symbols_analyse.png)
When the reflection is found and option "Aggressive mode" is activated, the reflector will check which of special-symbols are displayed on this page from vulnerable parameters. For this action, reflector compose additional requests for each reflected parameter. In example, while we was working with elkokc.ml website reflector are generated issue with a detailed information about reflection. There are 3 reflection for "search" parameter and each of them pass special symbols. Because of the possibility of displaying special characters issue severity is marked as high. Every time when reflection is found reflector define severity and generate burp issue.

# Context analyse
In the "Check context" mode  reflector it's not only show special characters that are reflected to the page, but also figure out a character that allows to break the syntax in the page code. In example you may see server response by reflector extension. Parameter "search" was send with a payload  - p@y<"'p@y. As a result, it was reflected a few times in a different contexts. 
* reflection with next characters - ',", <  and the double quote  allow to exit from this context and write HTML code.
* reflection with next characters - ", <  and the bracket allow to inject HTML-tags. 
* reflection with next characters -  ',", < and the single quote allow to exit from js variable context and write malicious code.

![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/aggressivemode_context.png)

In the issue information it's marked as: 
* Context char - character that allows to breake the syntax.
* Other chars - other chars that are reflected without context.
![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/aggressivemode_context1.png)

# Reflection navigation
Navigation by arrow buttons in the response tab.
![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/navigation.gif)

# Settings
* Scope only - allow reflector to work only with a scope added websites.
* Agressive mode - reflector generates additional request with a test payload .
* Check context - activate check context mode.

Moreover you can manage content-types whitelist with which  reflector plugin should work. But if you will use another types except text/html,  this can lead to slowdowns in work.
![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/settings.png)

