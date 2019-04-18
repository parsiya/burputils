# Burp extension to test my helper modules.
# it creates a listener and prints information about incoming requests.

# support for burp-exceptions - see https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
    import sys
except ImportError:
    pass

from burp import IBurpExtender
from burp import IHttpListener
from burputils import BurpUtils

class BurpExtender(IBurpExtender, IHttpListener):

    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        # self.utilss = callbacks.getHelpers()
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
        
        # log for requests
        if messageIsRequest:         
            # print "Got request"
            # # print "Request info from raw bytes"
            # # # process request
            # # # reqInfo = self.utils.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
            # # # reqInfo = self.utils.analyzeRequest(messageInfo)
            # # reqInfoFromBytes = self.utils.getInfoFromBytes(messageIsRequest, messageInfo.getRequest())

            # # # get method
            # # print "Method:", reqInfoFromBytes.getMethod()

            # # # get URL
            # # # this will return an error, use helper.getInfo instead which uses IRequestResponse
            # # # print "URL:", reqInfoFromBytes.getUrl()

            # # # get headers
            # # print "Headers:", reqInfoFromBytes.getHeaders()

            # print "Request info from RequestResponse"
            # # test getInfo
            # reqInfoFromRequestResponse = self.utils.getInfo(messageIsRequest, messageInfo)

            # # get method
            # print "Method:", reqInfoFromRequestResponse.getMethod()

            # # get URL
            # print "URL:", reqInfoFromRequestResponse.getUrl()

            # # get headers
            # print "Headers:", reqInfoFromRequestResponse.getHeaders()

            # hdr = self.utils.getHeaders(reqInfoFromRequestResponse)

            # # print "Host:", hdr.get("Host")[0]
            # # print "Cache-Control:", hdr.get("Cache-Control")[0]

            # print "headers recreated"
            # exported = hdr.exportRaw()
            # print exported
            
            return

        # if we got here, we have a response

        print "Got response"

        # get response info
        responseInfo = self.utils.getInfo(messageIsRequest, messageInfo)
        
        # get headers
        responseHeaders = responseInfo.getHeaders()
        print "Response headers"
        print responseHeaders

        # get headers using utils
        utilHeaders = self.utils.getHeaders(responseInfo)

        # print util headers
        print "response headers recreated"
        respHeaderFromUtils = utilHeaders.exportRaw()
        print respHeaderFromUtils

        # add something
        utilHeaders.add("customheader", "customvalue1")
        utilHeaders.add("customheader", "customvalue2")
        utilHeaders.add("customheader", "customvalue3")

        # remove `Vary: Accept-Encoding`
        utilHeaders.remove("Vary")

        # remove `Content-Type` and add our own
        utilHeaders.overwrite("Content-Type", "Custom content type")

        # print util headers
        print "response headers recreated after modification"
        respHeaderFromUtils = utilHeaders.exportRaw()
        print respHeaderFromUtils

        # put everything back together
        bodyBytes = self.utils.getBody(messageIsRequest, messageInfo)
        # build message
        modifiedmsg = self.utils.burpHelper.buildHttpMessage(respHeaderFromUtils, bodyBytes)

        # set modified message response
        self.utils.setRequestResponse(messageIsRequest, modifiedmsg, messageInfo)

        # this should be reflected in response tab

        # done
        print "--------"
        return

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass