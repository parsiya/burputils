# Burp extension to test burputils Header module.
# creates a listener and prints information about incoming requests.

# support for burp-exceptions - see https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
    import sys
except ImportError:
    pass

# support for burputils - https://github.com/parsiya/burputils
# comment if not using burputils
from burputils import BurpUtils

# this is always used
from burp import IBurpExtender
# this is needed to register a listener
from burp import IHttpListener
# add any other classes. e.g., if you want to also create a new tab
# from burp import ITab

class BurpExtender(IBurpExtender, IHttpListener):
    # implement IBurpExtender

    # set everything up
    def registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        # self.helpers = callbacks.getHelpers()
        self.utils = BurpUtils(callbacks)

        # support for burp-exceptions
        try:
            sys.stdout = callbacks.getStdout()
        except:
            pass
        
        # set our extension name
        callbacks.setExtensionName("Test Helpers")
        
        # register an HTTP listener
        callbacks.registerHttpListener(self)

    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        
        # do nothing for requests because we will not see the changes in history
        if messageIsRequest:         
            return

        # if we got here, we have a response
        print "Got response"

        # get response info
        responseInfo = self.utils.getInfo(messageIsRequest, messageInfo)
        
        # get headers
        responseHeaders = responseInfo.getHeaders()
        print "Response headers before modification"
        print responseHeaders

        # get headers using utils
        utilHeaders = self.utils.getHeaders(responseInfo)

        # print util headers to see if it works correctly
        # order will be off but it does not matter
        print "response headers recreated"
        respHeaderFromUtils = utilHeaders.exportRaw()
        print respHeaderFromUtils

        # add a header multiple times
        utilHeaders.add("customheader", "customvalue1")
        utilHeaders.add("customheader", "customvalue2")
        utilHeaders.add("customheader", "customvalue3")

        # remove `Vary: Accept-Encoding`
        utilHeaders.remove("Vary")

        # overwrite `Content-Type` with our own value
        utilHeaders.overwrite("Content-Type", "Custom content type")

        # print modified headers
        print "response headers recreated after modification"
        respHeaderFromUtils = utilHeaders.exportRaw()
        print respHeaderFromUtils

        # put everything back together
        bodyBytes = self.utils.getBody(messageIsRequest, messageInfo)
        # build message
        modifiedmsg = self.utils.helpers.buildHttpMessage(respHeaderFromUtils, bodyBytes)

        # set modified message response
        modifiedmsg = self.utils.setRequestResponse(messageIsRequest, modifiedmsg, messageInfo)

        # this should be reflected in response tab

        # done
        print "--------"
        return

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass
