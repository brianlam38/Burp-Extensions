from burp import IBurpExtender
from burp import ISessionHandlingAction

SESSION_ID_KEY = "X-Custom-Session-Id:"
SESSION_ID_KEY_BYTES = bytearray(SESSION_ID_KEY)
NEWLINE_BYTES = bytearray("\r\n")

class BurpExtender(IBurpExtender, ISessionHandlingAction):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # save the helpers for later
        self.helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Session token example")
        callbacks.registerSessionHandlingAction(self)

    #
    # Implement ISessionHandlingAction
    #

    def getActionName(self):
        return "Use session token from macro"

    def performAction(self, current_request, macro_items):
        if len(macro_items) == 0:
            return

        # extract the response headers
        final_response = macro_items[len(macro_items) - 1].getResponse()
        if final_response is None:
            return

        headers = self.helpers.analyzeResponse(final_response).getHeaders()

        session_token = None
        for header in headers:
            # skip any header that isn't an "X-Custom-Session-Id"
            if not header.startswith(SESSION_ID_KEY):
                continue

            # grab the session token
            keylen = len(SESSION_ID_KEY)
            session_token = header[keylen:].strip()

        # if we failed to find a session token, stop doing work
        if session_token is None:
            return

        req = current_request.getRequest()

        session_token_key_start = self.helpers.indexOf(req, SESSION_ID_KEY_BYTES, False, 0, len(req))
        session_token_key_end = self.helpers.indexOf(req, NEWLINE_BYTES, False, session_token_key_start, len(req))

        # glue together first line + session token header + rest of request
        current_request.setRequest(
                    req[0:session_token_key_start] +
                    self.helpers.stringToBytes("%s %s" % (SESSION_ID_KEY, session_token)) +
                    req[session_token_key_end:])
