from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import re

# inherit IBurpExtender as base class, which defines registerExtenderCallbacks
# inherit IScannerCheck to register as custom scanner
class BurpExtender(IBurpExtender, IScannerCheck):

    # get references to callbacks, called when extension is loaded
    def	registerExtenderCallbacks(self, callbacks):
        # get a local instance of callbacks object
        self._callbacks = callbacks
        self._callbacks.setExtensionName("Dangerous Methods")
        # register as scanner object so we get used for active/passive scans
        self._callbacks.registerScannerCheck(self)
        print '[*] Extension registered.'
        return

    # 'The Scanner invokes this method for each base request/response that is passively scanned'
    # passing the self object as well for access to helper functions, etc.
    # java.util.List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    def doPassiveScan(self, baseRequestResponse):
        print '[*] Passive scan is a go.'
        try:
            scanObject = DoScan(baseRequestResponse, self._callbacks)
        except:
            print '[*] Failed to create scanObject!'
        try:
            scanResult = scanObject.regexSearch()
        except:
            print '[*] Failed on call to regexSearch!'
        
        if(len(scanResult) > 0):
            return scanResult
        else:
            return None
    
    # 'The Scanner invokes this method when the custom Scanner check has reported multiple issues for the same URL path'
    # 'The method should return -1 to report the existing issue only, 0 to report both issues, and 1 to report the new issue only.'
    # int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
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
        # get local instance of getHelpers for helper functionss
        self._helpers = self._callbacks.getHelpers()

        # set all regexes, issue details, links etc. here
        regexes = [r'eval\(', r'document\.write\(', r'document\.writeln\(', r'\.innerHTML', r'\.outerHTML', 
                    r'.\insertAdjacentHTML', r'document\.URL\.substring', r'\$\(.*\)\.html\(']
        regexLength = len(regexes)
        self._regexes = regexes
        self._regexLength = regexLength

        issueDetails = ['The following potentially dangerous Javascript method has been found: <br><br><b>$val$</b><br><br>', 
                        'The following potentially dangerous Javascript method has been found: <br><br><b>$val$</b><br><br>',
                        'The following potentially dangerous Javascript method has been found: <br><br><b>$val$</b><br><br>',
                        'The following potentially dangerous Javascript method has been found: <br><br><b>$val$</b><br><br>',
                        'The following potentially dangerous Javascript method has been found: <br><br><b>$val$</b><br><br>',
                        'The following potentially dangerous Javascript method has been found: <br><br><b>$val$</b><br><br>',
                        'The following potentially dangerous Javascript method has been found: <br><br><b>$val$</b><br><br>',
                        'The following potentially dangerous jQuery method has been found: <br><br><b>$val$</b><br><br>']
        issuesDetailsDict = {}
        for counter, regex in enumerate(regexes):
            issuesDetailsDict[regex] = issueDetails[counter]
        self._issueDetailsDict = issuesDetailsDict

        self._issueName = 'Dangerous Method Found'
        self._severity = 'Information'

        return

    def regexSearch(self):
        response = self._requestResponse.getResponse()
        offset = []
        offsetArray = array('i', [0, 0])

        issues = []

        for i in range(0, self._regexLength):
            offset = []
            # compile regex
            try:
                compiledRegex = re.compile(self._regexes[i], re.DOTALL)
            except:
                print '[*] Failed to compile regex!'
                # need to throw exception here
            matched = compiledRegex.finditer(self._helpers.bytesToString(response))

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
                tempIssue = ScanIssue(self._requestResponse.getHttpService(), self._helpers.analyzeRequest(self._requestResponse).getUrl(), 
                    [self._callbacks.applyMarkers(self._requestResponse, None, offset)], self._issueName, False, detail)
                try:
                    issues.append(tempIssue)
                except:
                    print '[*] Appending issue failed'

        return issues

# 'This interface is used to retrieve details of Scanner issues. Extensions can obtain details of issues by registering an IScannerListener or 
# by calling IBurpExtenderCallbacks.getScanIssues(). Extensions can also add custom Scanner issues by registering an IScannerCheck or calling 
# IBurpExtenderCallbacks.addScanIssue(), and providing their own implementations of this interface. Note that issue descriptions and other text 
# generated by extensions are subject to an HTML whitelist that allows only formatting tags and simple hyperlinks.'
# Here we are implementing our own custom scan issue to set scan issue information parameters and create getters for each parameter
class ScanIssue(IScanIssue):
    # constructor for setting issue information
    def __init__(self, httpService, url, requestResponse, name, severity, issueDetail):
        self._httpService = httpService
        self._url = url
        self._requestResponse = requestResponse
        self._name = name
        # not using severity as all issues should be informational
        # self._severity = severity
        self._issueDetail = issueDetail

        # TODO
        # create dict of remediation details, keyed with regex?

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
        return 'Remediation details here. <br><br><b>References:</b><ul><li></li></ul>'

    def getHttpMessages(self):
        return self._requestResponse

    def getHttpService(self):
        return self._httpService