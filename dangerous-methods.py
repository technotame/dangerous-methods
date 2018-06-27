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
        # do passive scan stuff here (i.e. call custom scan method)
        # returns 'A list of IScanIssue objects, or null if no issues are identified', else return None
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
            print '[*] Returning results from scan!'
            return scanResult
            # return None
        else:
            print '[*] No results found in scan!'
            return None
    
    # 'The Scanner invokes this method when the custom Scanner check has reported multiple issues for the same URL path'
    # 'The method should return -1 to report the existing issue only, 0 to report both issues, and 1 to report the new issue only.'
    # we return 0 here to indicate we want to report both, as we may see multiple instances of the same issue
    # int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    # may not need this?????
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
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
        regexes = ['eval', r'document\.write']
        regexLength = len(regexes)
        self._regexes = regexes
        self._regexLength = regexLength

        issueDetails = ['eval issue', 'document.write issue']
        issuesDetailsDict = {}
        for counter, regex in enumerate(regexes):
            issuesDetailsDict[regex] = issueDetails[counter]
        self._issueDetailsDict = issuesDetailsDict

        self._issueName = 'Dangerous Method Found'
        self._severity = 'Information'

        return

    def regexSearch(self):
        response = self._requestResponse.getResponse()
        responseLength = len(response)
        offset = []
        offsetArray = array('i', [0, 0])

        issues = []

        # TODO figure out why it's only skipping to first occurence of eval
        for i in range(0, self._regexLength):
            offset = []
            # compile regex
            try:
                compiledRegex = re.compile(self._regexes[i], re.DOTALL)
            except:
                print '[*] Failed to compile regex!'
                # need to throw exception here
            matched = compiledRegex.findall(self._helpers.bytesToString(response))
            print '[*] Matched is: ' + str(matched)

            # find offsets for all matches
            for match in matched:
                offset = []
                print '[*] match is: ' + str(match)
                beginning = self._helpers.indexOf(response, match, True, 0, responseLength)
                offsetArray[0] = beginning
                offsetArray[1] = beginning + len(match)
                offset.append(offsetArray)
                print '[*] Offset is: ' + str(offset)

                # create temp ScanIssue and add to ScanIssue list
                print '[*] Trying to create issue!'
                tempIssue = ScanIssue(self._requestResponse.getHttpService(), self._helpers.analyzeRequest(self._requestResponse).getUrl(), 
                    [self._callbacks.applyMarkers(self._requestResponse, None, offset)],
                    self._issueName, False, self._issueDetailsDict[self._regexes[i]])
                try:
                    issues.append(tempIssue)
                except:
                    print '[*] Appending issue failed'

        # clear each variable used, like ScanIssue object, regex, offset etc
        return issues


# 'This interface is used to retrieve details of Scanner issues. Extensions can obtain details of issues by registering an IScannerListener or 
# by calling IBurpExtenderCallbacks.getScanIssues(). Extensions can also add custom Scanner issues by registering an IScannerCheck or calling 
# IBurpExtenderCallbacks.addScanIssue(), and providing their own implementations of this interface. Note that issue descriptions and other text 
# generated by extensions are subject to an HTML whitelist that allows only formatting tags and simple hyperlinks.'
# Here we are implementing our own custom scan issue to set scan issue information parameters and create getters for each parameter
class ScanIssue(IScanIssue):
    print '[*] ScanIssue created.'
    # constructor for setting issue information
    def __init__(self, httpService, url, requestResponse, name, severity, issueDetail):
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

    # statically setting to 'Certain'
    def getConfidence(self):
        return 'Certain'

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