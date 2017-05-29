import urllib2

def request_url(url):
	request = urllib2.Request(url)
	try:
		request_handle = urllib2.urlopen(request)
	except urllib2.HTTPError, error:
		print "HTTP error on" + " " + url + " " + "code" + " " + str(error.code)
		exit(4)
	except urllib2.URLError, error:
		print "URL error on" + " " + url + " " + "reason" + " " + str(error.reason)
		exit(5)
	return request_handle.read()
