class Headers:
    """Represents HTTP headers.

    Burp returns headers as an ArrayList<string>, this class converts it into
    a dict(list).
    
    Note: This class treats headers as case-sensitive and does not check for
    duplicate values. Duplicate headers will be repeated in the list.
    """

    def __init__(self):
        """Create the header collection."""
        from collections import defaultdict
        self._hdr = defaultdict(list)
        # the first header line coming from Burp is special.
        # it's the first line of the request ("GET /whatever HTTP/1.1")
        # which has a different structure than other headers.
        self._first = ""

    def get(self, header):
        """Returns a list containing the header and its value(s) or None if header does not exist in _hdr.

        Args:

        * header (string): Header name.
        """
        # this is functionally equivalent to "self._hdr[header]" but we can
        # change the default return value from None later if needed (e.g. to "").
        return self._hdr.get(header, None)
    
    def add(self, header, value):
        """Adds header:value to _hdr.

        If header exists, value is added to the list under that header.

        Args:

        * header (string): Header name.
        * value (string): Header value.
        """
        self._hdr[header].append(value)
        
    def remove(self, header):
        """Removes header from _hdr.
        
        Args:

        * header (string): Header name.
        """
        # pop removes header from the dictionary and returns its value.
        # providing the default value None, prevents exceptions if header does not
        # exist in the dictionary.
        temp = self._hdr.pop(header, None)
    
    def overwrite(self, header, value):
        """Overwrites the value of a header.

        * If the header does not exist, it will be added.
        * If you want duplicate headers, use add instead.

        Args:

        * header (string): Header name.
        * value (string): Header value.
        """
        # if it exists, remove it
        if header in self._hdr:
            self.remove(header)
        
        # add header
        self.add(header, value)

    def importRaw(self, rawHeader):
        """Deserializes the Burp header list into a Headers object.
        Returns a Headers object.
        
        Args:

        * rawHeader: java.util.ArrayList(string) containing the headers.
            Output of IRequestInfo.getHeaders() or IResponseInfo.getHeaders().
        """
        # set the first line, e.g. "GET /whatever HTTP/1.1".
        self._first = rawHeader[0]
        # set the rest
        for h in rawHeader[1:]:
            # separate header and value
            spl = h.split(":", 1)
            if len(spl) == 2:
                self.add(spl[0], spl[1].strip())
            else:
                # if the line does not contain ":", add all of it
                self.add(spl[0], None)

    def exportRaw(self):
        """Serializes the Headers object back to the Burp format.
        Returns a java.util.ArrayList(string).

        The returned string list has one header on each line including
        duplicate headers.

        This can be used in Burp's IExtensionHelpers.buildHttpMessage.
        """
        import java.util.ArrayList as ArrayList
        lst = ArrayList()
        # add the first line
        lst.add(self._first)
        # iterate through headers
        for header in self._hdr:
            values = self._hdr[header]
            if values is None:
                # if header does not have a value, just add the header
                lst.add(header)
                continue
            
            # iterate through header values and add one line for each value
            for val in values:
                lst.add("{}: {}".format(header, val))
        return lst
