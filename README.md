# Dangerous Methods
A Burp Suite Professional extension for finding the use of potentially dangerous methods/functions in Javascript, jQuery, AngularJS, and others.

* Passive scanner checks create informational issues in Burp Suite
* Powered by regular expressions
* Written in Python
* Requires Jython 2.7+
* 21 checks across 3 frameworks/languages
* Pull requests welcome!

### Screenshots
[![Example Issue](screenshots/dangerous-methods-issue.png)]

### Todo
* Collect references
* Make regexes longer/more robust/more accurate
    * ~~Determine valid identifier regex to precede JS methods~~
    * Should they be broad enough to prefer false positives over false negatives?
* Rework issue details and references
* Add new dangerous methods
    * Look into templating languages
* Add extension information to registerExtenderCallbacks output
* Possibly load regexes/references from file?
* Write better/more realistic test app
    * Reformat HTML to show what tests apply to which issues
* ~~Send output properly~~
* ~~Find out if Burp Pro is needed~~
* ~~Throw exceptions where needed~~
* ~~Add screenshots~~