# Dangerous Methods
A Burp Suite extension for finding the use of potentiall dangerous methods/functions in Javascript, jQuery, PHP, and other languages.

* Powered by regular expressions
* Creates informational issues in Burp Suite
* Written in Python
* Requires Jython 2.7+ 

### Todo
* Write getRemediationDetail for each language
* Collect references
* Make regexes longer/more robust
* Send output properly
* Throw exceptions where needed
* Add new dangerous methods
* Create dict of issue details in ScanIssue, keyed with regex
* Create dict of remediation details in ScanIssue, keyed with regex