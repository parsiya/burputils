# Burp extension to test burputils modules.
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
        self.utils = BurpUtils(callbacks.getHelpers())

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

        print "*****"
        print "type(messageInfo)", type(messageInfo)
        
        # get response info
        responseInfo = self.utils.getInfo(messageIsRequest, messageInfo)
        
        # get headers using utils
        utilHeaders = self.utils.getHeaders(responseInfo)

        # overwrite `Content-Type` with our own value
        utilHeaders.overwrite("Content-Type", "Custom content type")

        # put everything back together
        bodyBytes = self.utils.getBody(messageIsRequest, messageInfo)
        # build message
        modifiedmsg = self.utils.burpHelper.buildHttpMessage(utilHeaders.exportRaw(), bodyBytes)

        # set modified message response
        modifiedmsg = self.utils.setRequestResponse(messageIsRequest, modifiedmsg, messageInfo)

        print "type(HttpMessage)", type(modifiedmsg)

        # this should be reflected in response tab

        # done
        print "*****"
        return

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass