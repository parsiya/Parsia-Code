# 0-decoder/library.py

# getInfo processes the request/response and returns info
def getInfo(content, isRequest, helpers):
    if isRequest:
        return helpers.analyzeRequest(content)
    else:
        return helpers.analyzeResponse(content)

# getBody returns the body of a request/response
def getBody(content, isRequest, helpers):
    info = getInfo(content, isRequest, helpers)
    return content[info.getBodyOffset():]

# setBody replaces the body of request/response with newBody and returns the result
# should I check for sizes or does Python automatically increase the array size?
def setBody(newBody, content, isRequest, helpers):
    info = getInfo(content, isRequest, helpers)
    content[info.getBodyOffset():] = newBody
    return content

# decode64 decodes a base64 encoded byte array and returns another byte array
def decode64(encoded, helpers):
    return helpers.base64Decode(encoded)

# encode64 encodes a byte array and returns a base64 encoded byte array
def encode64(plaintext, helpers):
    return helpers.base64Encode(plaintext)
