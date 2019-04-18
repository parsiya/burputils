# Burp Utils
A work-in-progress collection of utilities for creating Burp extensions in
 Python. **The API is very much subject to change.**

## Usage
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
The helper library does not need it yet but you should use it for extension
 development:

* https://github.com/securityMB/burp-exceptions

## Docs
To be created.

See [test-extension.py](test-extension.py) for an example. It adds some headers
 to responses before they hit HTTP History.

## I Found a Bug!
Bugs in my code? Never!!1! Please make an issue.

## License
Now that is a can of worms. GPLv3, see [LICENSE](LICENSE) for details.