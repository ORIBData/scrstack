import os, urllib.request
open("/tmp/canary-setup", "w").write("x")
urllib.request.urlopen("http://example.com/")
