# Copyright (c) 2018 TechnoTame

try:
    from burp import IBurpExtender, IScannerCheck, IScanIssue
    from java.lang import RuntimeException
    from array import array
    import re
except ImportError:
    print "Failed to load dependencies."

VERSION = '1.0'

# inherit IBurpExtender as base class, which defines registerExtenderCallbacks
# inherit IScannerCheck to register as custom scanner


class BurpExtender(IBurpExtender, IScannerCheck):
    # get references to callbacks, called when extension is loaded
    def registerExtenderCallbacks(self, callbacks):
        # get a local instance of callbacks object
        self._callbacks = callbacks
        self._callbacks.setExtensionName("Dangerous Methods")
        # register as scanner object so we get used for active/passive scans
        self._callbacks.registerScannerCheck(self)
        print """Successfully loaded Dangerous Methods v""" + VERSION + """\n
Repository @ https://gitlab.com/technotame/dangerous-methods
Send feedback or bug reports to technotame@0xfeed.io
Copyright (c) 2018 Technotame"""
        return

    # 'The Scanner invokes this method for each base request/response that is
    # passively scanned'
    # passing the self object as well for access to helper functions, etc.
    # java.util.List<IScanIssue> doPassiveScan(IHttpRequestResponse
    # baseRequestResponse)
    def doPassiveScan(self, baseRequestResponse):
        try:
            scanObject = DoScan(baseRequestResponse, self._callbacks)
        except:
            raise RuntimeException('Failed to create scanObject.')
        try:
            scanResult = scanObject.regexSearch()
        except:
            raise RuntimeException('Failed to call scanObject.regexSearch.')

        if(len(scanResult) > 0):
            return scanResult
        else:
            return None

    # 'The Scanner invokes this method when the custom Scanner check has
    # reported multiple issues for the same URL path'
    # 'The method should return -1 to report the existing issue only, 0 to
    # report both issues, and 1 to report the new issue only.'
    # consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

# Custom class to perform scans
# Returns list of ScanIssue object(s)


class DoScan:
    def __init__(self, requestResponse, callbacks):
        self._requestResponse = requestResponse
        self._callbacks = callbacks
        # get local instance of getHelpers for helper functions
        self._helpers = self._callbacks.getHelpers()

        # set all regexes, issue details, references etc. here
        regexes = [r'eval\(', r'document\.write\(', r'document\.writeln\(',
                   r'\.innerHTML', r'\.outerHTML',
                   r'\.insertAdjacentHTML', r'document\.URL\.substring',
                   r'\$\(.*\)\.html\(', r'\.append\(',
                   r'\.trustAsHtml\(', r'ng-bind-html-unsafe',
                   r'\.setAttribute\(', r'\.insertBefore\(',
                   r'\.insertAfter\(', r'\.prepend\(', r'\.prependTo\(',
                   r'\.wrap\(', r'\.wrapAll\(', r'\.before\(', r'\.after\(']

        ref = '<b>References:</b>'
        badJSlink = '<li>http://blog.blueclosure.com/2017/09/javascript-dangerous-functions-part-1.html</li>'
        owaspXSSLink = '<li>https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet</li>'
        badjQueryLink = '<li>https://coderwall.com/p/h5lqla/safe-vs-unsafe-jquery-methods</li>'

        references = [ref + '<ul><li>https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval</li></ul>',
                      ref + '<ul>' + badJSlink + owaspXSSLink + '</ul>',
                      ref + '<ul>' + badJSlink + owaspXSSLink + '</ul>',
                      ref + '<ul><li>https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML</li>' +
                      badJSlink + owaspXSSLink + '</ul>',
                      ref + '<ul>' + badJSlink + owaspXSSLink + '</ul>',
                      ref + '<ul>' + badJSlink + owaspXSSLink + '</ul>',
                      ref + '<ul>' + badJSlink + '</ul>',
                      ref + '<ul><li>https://api.jquery.com/html/</li>' + badjQueryLink + '</ul>',
                      ref + '<ul>' + badjQueryLink + '</ul>',
                      ref + '<ul><li></li>https://docs.angularjs.org/guide/security</ul>',
                      ref + '<ul><li>http://erikaugust.com/thoughts/ng-bind-html/</li></ul>',
                      ref + '<ul>' + owaspXSSLink + '</ul>',
                      ref + '<ul>' + badjQueryLink + '</ul>',
                      ref + '<ul>' + badjQueryLink + '</ul>',
                      ref + '<ul>' + badjQueryLink + '</ul>',
                      ref + '<ul>' + badjQueryLink + '</ul>',
                      ref + '<ul>' + badjQueryLink + '</ul>',
                      ref + '<ul>' + badjQueryLink + '</ul>',
                      ref + '<ul>' + badjQueryLink + '</ul>',
                      ref + '<ul>' + badjQueryLink + '</ul>']

        self._references = references
        referencesDict = {}
        for counter, regex in enumerate(regexes):
            referencesDict[regex] = references[counter]

        # print referencesDict
        regexLength = len(regexes)
        self._regexes = regexes
        self._regexLength = regexLength

        dangerous = 'The following potentially dangerous '
        found = ' method has been found: <br><br><b>$val$</b><br><br>'
        jsFound = dangerous + 'Javascript' + found
        jqueryFound = dangerous + 'jQuery' + found
        angularFound = dangerous + 'AngularJS' + found

        issueDetails = [jsFound, jsFound, jsFound, jsFound, jsFound, jsFound,
                        jsFound, jqueryFound, jqueryFound, angularFound,
                        angularFound, jsFound, jqueryFound, jqueryFound,
                        jqueryFound, jqueryFound, jqueryFound, jqueryFound,
                        jqueryFound, jqueryFound]

        issuesDetailsDict = {}
        for counter, regex in enumerate(regexes):
            issuesDetailsDict[regex] = issueDetails[counter]
        self._issueDetailsDict = issuesDetailsDict

        self._issueName = 'Potentially Dangerous Method Found'
        self._severity = 'Information'

        return

    def regexSearch(self):
        response = self._requestResponse.getResponse()
        offset = []
        offsetArray = array('i', [0, 0])

        issues = []

        for i in range(0, self._regexLength):
            offset = []
            try:
                compiledRegex = re.compile(self._regexes[i], re.DOTALL)
            except:
                raise RuntimeException('Failed to compile regular expression.')
            try:
                matched = compiledRegex.finditer(self._helpers.bytesToString(response))
            except:
                raise RuntimeException('Regular expression search failed.')

            # find offsets for all matches
            for match in matched:
                offset = []
                span = match.span()
                offsetArray[0] = span[0]
                offsetArray[1] = span[1]
                offset.append(offsetArray)

                # replace issue detail with regex match
                detail = self._issueDetailsDict[self._regexes[i]]
                detail = detail.replace("$val$", str(match.group()))

                # create temp ScanIssue and add to ScanIssue list
                try:
                    tempIssue = ScanIssue(self._requestResponse.getHttpService(),
                                          self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                                          [self._callbacks.applyMarkers(self._requestResponse, None, offset)],
                                          self._issueName, False, detail + self._references[i])
                except:
                    raise RuntimeException('Failed to create issue.')
                try:
                    issues.append(tempIssue)
                except:
                    raise RuntimeException('Failed to append issue.')

        return issues

# 'This interface is used to retrieve details of Scanner issues. Extensions
# can obtain details of issues by registering an IScannerListener or
# by calling IBurpExtenderCallbacks.getScanIssues(). Extensions can also add
# custom Scanner issues by registering an IScannerCheck or calling
# IBurpExtenderCallbacks.addScanIssue(), and providing their own
# implementations of this interface. Note that issue descriptions and other
# text generated by extensions are subject to an HTML whitelist that allows
# only formatting tags and simple hyperlinks.'
# Here we are implementing our own custom scan issue to set scan issue
# information parameters and create getters for each parameter


class ScanIssue(IScanIssue):
    # constructor for setting issue information
    def __init__(self, httpService, url, requestResponse, name, severity,
                 issueDetail):
        self._httpService = httpService
        self._url = url
        self._requestResponse = requestResponse
        self._name = name
        # not using severity as all issues should be informational
        # self._severity = severity
        self._issueDetail = issueDetail

    # getters for issue information
    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    # statically setting to 'Information'
    def getSeverity(self):
        return 'Information'

    # statically setting to 'Firm'
    def getConfidence(self):
        return 'Firm'

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._issueDetail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._requestResponse

    def getHttpService(self):
        return self._httpService
