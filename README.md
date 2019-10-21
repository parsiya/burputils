# Burp Utils <!-- omit in toc -->
A work-in-progress collection of utilities for creating Burp extensions in
Python. **The API is very much subject to change.**

Currently, it has helper methods to manipulate requests/responses and headers.

- [Adding to Extension](#adding-to-extension)
    - [Which Option Should I Use?](#which-option-should-i-use)
    - [Why Do You Use IExtensionHelpers During Construction?](#why-do-you-use-iextensionhelpers-during-construction)
    - [Burp-Exceptions](#burp-exceptions)
- [Usage](#usage)
- [I Found a Bug!](#i-found-a-bug)
- [License](#license)

## Adding to Extension
1. Add it as a Python Burp module and use `from burputils import *`.
    * For more info see:
    https://parsiya.net/blog/2018-12-19-python-utility-modules-for-burp-extensions/
2. Copy the file to the same path as your extension and use `from burputils import *`.
    * `burputils.py` does not have to be loaded in Burp, just leave it in the same path.
3. Copy/paste used code into your extension.

### Which Option Should I Use?
I suggest option 1 for development and 2 for release.

If you are only using a few functions, you can copy/paste them at the end of
your extension file and avoid having two files.

### Why Do You Use IExtensionHelpers During Construction?
Burp only allows you to get an instance of that class through callbacks.

Inside your extension, you can either use it directly by setting it manually 
or use helpers via `burpUtilsObject.burpHelper`:
* `utils.burpHelper.buildHttpMessage`

### Burp-Exceptions
BurpUtils does not need it but you should use it for extension development:

* https://github.com/securityMB/burp-exceptions

## Usage
Create an object inside `registerExtenderCallbacks` and assign it to the tab.

``` python
def registerExtenderCallbacks(self, callbacks):
    # obtain an extension helpers object
    # self.helpers = callbacks.getHelpers()
    self.utils = BurpUtils(callbacks.getHelpers())
```

Inside the extension methods (e.g. `processHttpMessage`) use `self.utils`.

``` python
def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
    
    if messageIsRequest:         
        return

    # get response info
    # we could use the same method to get request headers
    responseInfo = self.utils.getInfo(messageIsRequest, messageInfo)
    
    # get headers using utils
    utilHeaders = self.utils.getHeaders(responseInfo)

    # add a header multiple times
    utilHeaders.add("customheader", "customvalue1")
    utilHeaders.add("customheader", "customvalue2")
    utilHeaders.add("customheader", "customvalue3")

    # remove `Vary: Accept-Encoding`
    utilHeaders.remove("Vary")

    # overwrite `Content-Type` with our own value
    utilHeaders.overwrite("Content-Type", "Custom content type")

    # put everything back together
    # same method can be used to get request body bytes
    bodyBytes = self.utils.getBody(messageIsRequest, messageInfo)
    # build message
    # we can call Burp helpers with "self.utils.burpHelper"
    modifiedmsg = self.utils.burpHelper.buildHttpMessage(respHeaderFromUtils, bodyBytes)

    # set modified message response
    self.utils.setRequestResponse(messageIsRequest, modifiedmsg, messageInfo)

    # this should be reflected in response tab
    print "--------"
    return
```

See [test-extension](test-extension.py) for a complete extension. It adds some
headers to responses before they hit HTTP History.

## I Found a Bug!
Bugs in my code? Never!!1! Please make an issue.

## License
Now that is a can of worms. GPLv3, see [LICENSE](LICENSE) for details.