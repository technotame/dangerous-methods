### To Add
* [dangerous PHP](https://www.eukhost.com/blog/webhosting/dangerous-php-functions-must-be-disabled)
* Angular ng-bind-html-unsafe
* HTML Element.setAttribute(...) see OWASP reference
* .insertBefore()
* .insertAfter()
* .prepend()
* .prependTo()
* .wrap()
* .wrapAll()
* .before()
* .after()

### Regexes Added
* innerHtml(): `'\.innerHTML'`
* eval(): `'eval\('`
* document.write(): `'eval\('`
* document.writeln(): `'document\.writeln\('`
* outerHTML(): `'\.outerHTML'`
* insertAdjacentHTML(): `'\.insertAdjacentHTML'`
* document.URL.substring(): `'document\.URL\.substring'`
* jQUery .html(): `'\$\(.*\)\.html\('`
* jQuery .append(): `'\.append\('`
* Angular .trustAsHtml(): `'\.trustAsHtml\('`

### References
* innerHtml()
    * [Mozilla Developer Network innerHTML page](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML)
    * [Dangerous Javascript Functions](http://blog.blueclosure.com/2017/09/javascript-dangerous-functions-part-1.html)
    * [OWASP](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* eval()
    * [Mozilla Developer Network eval() page](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval)
* document.write()
    * [Dangerous Javascript Functions](http://blog.blueclosure.com/2017/09/javascript-dangerous-functions-part-1.html)
    * [OWASP](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* document.writeln()
    * [Dangerous Javascript Functions](http://blog.blueclosure.com/2017/09/javascript-dangerous-functions-part-1.html)
    * [OWASP](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* outerHTML()
    * [Dangerous Javascript Functions](http://blog.blueclosure.com/2017/09/javascript-dangerous-functions-part-1.html)
    * [OWASP](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* insertAdjacentHTML()
    * [Dangerous Javascript Functions](http://blog.blueclosure.com/2017/09/javascript-dangerous-functions-part-1.html)
    * [OWASP](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* document.URL.substring()
    * [Dangerous Javascript Functions](http://blog.blueclosure.com/2017/09/javascript-dangerous-functions-part-1.html)
* jQUery .html()
    * [jQuery API page for html()](https://api.jquery.com/html/)
    * [Unsafe jQuery Methods](https://coderwall.com/p/h5lqla/safe-vs-unsafe-jquery-methods)
* jQuery .append()
    * [Unsafe jQuery Methods](https://coderwall.com/p/h5lqla/safe-vs-unsafe-jquery-methods)
* Angular .trustAsHtml()
    * 