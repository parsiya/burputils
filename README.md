# Burp Utils <!-- omit in toc -->
A work-in-progress collection of utilities for creating Burp extensions in
Python. **The API is very much subject to change and README might be outdated.**

Currently, it has helper methods to manipulate requests/responses and headers.

- [Adding BurpUtils to your Extension](#adding-burputils-to-your-extension)
    - [Which Option Should I Use?](#which-option-should-i-use)
    - [Why Does It Use IExtensionHelpers During Construction?](#why-does-it-use-iextensionhelpers-during-construction)
    - [Burp-Exceptions](#burp-exceptions)
- [Usage](#usage)
- [Examples](#examples)
- [I Found a Bug or I Would Like a Feature](#i-found-a-bug-or-i-would-like-a-feature)
- [License](#license)

## Adding BurpUtils to your Extension
There are several ways to use BurpUtils

1. Burp Module:
    1. Clone this repository in the [Burp Python modules directory][python-burp-module].
        * For more info see: https://parsiya.net/blog/2018-12-19-python-utility-modules-for-burp-extensions/
    2. The directory should look like `burp-module-directory\burputils`.
    3. Import it with `from burputils import BurpUtils`.
2. Local Module:
    1. Copy the files in the top path (e.g., `burputils.py`, `headers.py` etc.) to your extensions directory.
    2. Import it with `from burputils import BurpUtils`.
3. Copy/paste used code into your extension.
    1. Import it however.

### Which Option Should I Use?

* Option 1: If you want your extension to only contain your own code.
    * The test extensions use this approach.
* Option 2: If you want your extension to be self-sufficient.
* Option 3: Uf you are only using a few utility functions.

### Why Does It Use IExtensionHelpers During Construction?
Burp only allows you to get an instance of that class through callbacks.

By using it during constructions, both BurpUtils and your extension can use
them like `utils.burpHelper.buildHttpMessage`.

### Burp-Exceptions
BurpUtils does not need it but you should use it for extension development:

* https://github.com/securityMB/burp-exceptions

## Usage
Create an object inside `registerExtenderCallbacks` and assign it to the
extension.

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

## Examples
See the extensions in [test-extensions](test-extensions):

* [test-extensions/headers-test.py](test-extensions/headers-test.py) for a
  extension that adds some headers to responses before their hit Burp's HTTP
  history.
* [test-extensions/request-highlighter-example.py](test-extensions/request-highlighter-example.py)
  adds a random response header to each request and then highlights them in HTTP
  History accordingly.

## I Found a Bug or I Would Like a Feature
Bugs in my code? Never!!1! Please make an issue in both cases.

## License
MIT, see [LICENSE](LICENSE) for details.

The project was initially licensed under GPLv3. As the sole contributor to the
project, I switched to MIT. Complying with all GPL requirements was too hard.

<!-- Links -->
[python-burp-module]: https://portswigger.net/burp/documentation/desktop/tools/extender#python-environment