import urllib2
import time

def request_url(url):
	req = urllib2.Request(url)
	#import pdb; pdb.set_trace()
	while True:
		try:
			resp = urllib2.urlopen(req)
		except urllib2.HTTPError as e:
			if e.code == 404:
				exit(4)
			print "HTTP error on" + " " + url + " " + "code" + " " + str(e.code)
			time.sleep(360)
		except urllib2.URLError as e:
			print "URL error on" + " " + url + " " + "reason" + " " + str(e.reason)
			time.sleep(360)
		else:
			print "OK"
			return resp.read()
		
