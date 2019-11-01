# Burp extension to highlight specific request with specific response headers.
# First it adds a random header to every response and then highlights it with a specific color.

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

def random_color():
    """Returns a random color from the list."""
    # valid highlight colors for Burp
    import random
    colors = ["red","orange","yellow","green","cyan","blue","pink","magenta","gray"]
    return random.choice(colors)

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
        callbacks.setExtensionName("Request Highlighter Example")
        
        # register an HTTP listener
        callbacks.registerHttpListener(self)

    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        
        # do nothing for requests because we will not see the changes in history
        if messageIsRequest:         
            return

        # get response info
        responseInfo = self.utils.getInfo(messageIsRequest, messageInfo)

        # get headers using utils
        utilHeaders = self.utils.getHeaders(responseInfo)

        # overwrite `Content-Type` with our own value
        utilHeaders.add("color", random_color())

        # put everything back together
        bodyBytes = self.utils.getBody(messageIsRequest, messageInfo)
        # build message
        modifiedmsg = self.utils.burpHelper.buildHttpMessage(utilHeaders.exportRaw(), bodyBytes)

        # set modified message response
        modifiedmsg = self.utils.setRequestResponse(messageIsRequest, modifiedmsg, messageInfo)

        # now we can highlight based on color
        # read the value of "color" header if any.
        respInfo = self.utils.getInfo(messageIsRequest, messageInfo)
        hdrs = self.utils.getHeaders(respInfo)

        # headers.get returns a list, we want the first item.
        header_color = hdrs.get("color")
        if header_color is not None:
            header_color = header_color[0]
        # debugging
        # print "***** header_color", header_color, "type: ", type(header_color)
        messageInfo = messageInfo.setHighlight(header_color)

        return

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass
