### To Add
* [dangerous PHP](https://www.eukhost.com/blog/webhosting/dangerous-php-functions-must-be-disabled)


### Regexes Added
* eval(): `'eval\('`
* document.write(): `'eval\('`
* document.writeln(): `'document\.writeln\('`
* innerHtml(): `'\.innerHTML'`
* outerHTML(): `'\.outerHTML'`
* insertAdjacentHTML(): `'\.insertAdjacentHTML'`
* document.URL.substring(): `'document\.URL\.substring'`
* jQUery .html(): `'\$\(.*\)\.html\('`
* jQuery .append(): `'\.append\('`
* Angular .trustAsHtml(): `'\.trustAsHtml\('`
* Angular ng-bind-html-unsafe: `ng-bind-html-unsafe`
* .setAttribute(: `\.setAttribute\(`
* jQuery .insertBefore(): `\.insertBefore\(`
* jQuery .insertAfter(): `\.insertAfter\(`
* jQuery .prepend(): `\.prepend\(`
* jQuery .prependTo(): `\.prependTo\(`
* jQuery .wrap(): `\.wrap\(`
* jQuery .wrapAll(): `\.wrapAll\(`
* jQuery .before(): `\.before\(`
* jQuery .after(): `\.after\(`
* React dangerouslySetInnerHTML: `dangerouslySetInnerHTML`

### References
* eval()
    * [Mozilla Developer Network eval() page](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval)
* document.write()
    * [Dangerous Javascript Functions](http://blog.blueclosure.com/2017/09/javascript-dangerous-functions-part-1.html)
    * [OWASP](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* document.writeln()
    * [Dangerous Javascript Functions](http://blog.blueclosure.com/2017/09/javascript-dangerous-functions-part-1.html)
    * [OWASP](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* innerHtml()
    * [Mozilla Developer Network innerHTML page](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML)
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
    * [AngularJS Security Guide](https://docs.angularjs.org/guide/security)
* Angular ng-bind-html-unsafe
    * [ng-bind-html-unsafe](http://erikaugust.com/thoughts/ng-bind-html/)
* .setAttribute(
    * [OWASP](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* jQuery .insertBefore()
    * [Unsafe jQuery Methods](https://coderwall.com/p/h5lqla/safe-vs-unsafe-jquery-methods)
* jQuery .insertAfter()
    * [Unsafe jQuery Methods](https://coderwall.com/p/h5lqla/safe-vs-unsafe-jquery-methods)
* jQuery .prepend()
    * [Unsafe jQuery Methods](https://coderwall.com/p/h5lqla/safe-vs-unsafe-jquery-methods)
* jQuery .prependTo()
    * [Unsafe jQuery Methods](https://coderwall.com/p/h5lqla/safe-vs-unsafe-jquery-methods)
* jQuery .wrap()
    * [Unsafe jQuery Methods](https://coderwall.com/p/h5lqla/safe-vs-unsafe-jquery-methods)
* jQuery .wrapAll()
      * [Unsafe jQuery Methods](https://coderwall.com/p/h5lqla/safe-vs-unsafe-jquery-methods)
* jQuery .before():
      * [Unsafe jQuery Methods](https://coderwall.com/p/h5lqla/safe-vs-unsafe-jquery-methods)
* jQuery .after()
      * [Unsafe jQuery Methods](https://coderwall.com/p/h5lqla/safe-vs-unsafe-jquery-methods)
* React dangerouslySetInnerHTML
* [React Docs](https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml)