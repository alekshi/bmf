#!/usr/bin/python

"""
The script use BMF controller's API to create policy structure diagrams. The script uses filter-interface names and/or
filter-interface-groups names as argument and creats images with BMF policy structure. 
"""

import json
import requests
import sys
import ipaddress
import argparse
import pygraphviz
import networkx as nx
from networkx.drawing.nx_agraph import write_dot, graphviz_layout, to_agraph
import matplotlib.pyplot as plt
from collections import defaultdict
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ClassScriptConfig():
    """
    This class contains all script settings what were parsed from CLI arguments and check whether they valid
    """

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-c", "--controller", required=True, help="Provide IP address or FQDN of controller")
        parser.add_argument("-u", "--username", required=True, help="Provide username to log in to controller")
        parser.add_argument("-p", "--password", required=True, help="Provide password to log in to controller")
        parser.add_argument("-f", "--filter_interface_list", nargs='+', default=[], help="Provide list of filter interfaces")
        parser.add_argument("-g", "--group", nargs='+', default=[], help="Provide filter-interface-group name")
        parser.add_argument("-o", "--output", help="Provide file name for output png")
        args = parser.parse_args()
        self.controller_ip = args.controller
        self.username = args.username
        self.password = args.password
        self.output_name = args.output
        self.session_cookie = self.api_login()
        if not self.session_cookie:
        	sys.exit('Unable to connect to login to BMF controller. Bye.')
        self.filterInterfaceList = list()
        if len(args.filter_interface_list) > 0:
        	self.filterInterfaceList+=args.filter_interface_list
        if len(args.group) > 0:
        	for group in args.group:
        		rawList = self.api_request("/api/v1/data/controller/applications/bigtap/filter-interface-group[name=\'{}\']".format(group))[0]['filter-group']
        		for filterInterface in rawList:
        			self.filterInterfaceList.append(filterInterface['name'])

    def api_login(self):
        """
        Just internal function to get REST API token 
        """
        login_path = '/api/v1/auth/login'
        url = 'https://{}:8443{}'.format(self.controller_ip, login_path)
        login_dictionary = {'user': self.username, 'password': self.password}
        data = json.dumps(login_dictionary)
        headers = {'content-type': 'application/json'}
        try:
            response = requests.request('POST', url, data = data, headers=headers, verify=False)
            return json.loads(response.content)['session_cookie']
        except:
            return False
    
    def api_request(self, path, method = 'GET', data = ''):
        """
        Just internal function to make REST API call
        """
        url = 'https://{}:8443{}'.format(self.controller_ip, path)
        headers = {"content-type": "application/json"}
        headers['Cookie'] = 'session_cookie={}'.format(self.session_cookie)
        response = requests.request(method, url, data=data, headers=headers, verify=False).json()
        return (response)
    
    
    def api_logout(self):
        """
        Just internal function to log out from contoller and wipe session token
        """
        logout_path = '/api/v1/data/controller/core/aaa/session[auth-token="{}"]'.format(self.session_cookie)
        url = 'https://{}:8443{}'.format(self.controller_ip, logout_path)
        headers = {'content-type': 'application/json', 'Cookie': 'session_cookie={}'.format(self.session_cookie)}
        try:
            response = requests.request('DELETE', url, headers=headers, verify=False)
            return True
        except:
            return False

class bigtapFabric():
	def __init__(self, **kwargs):
		for attribute, value in kwargs.items():
			setattr(self, attribute, value)
		self.bigtapFilterIfaceList = list()
		self.bigtapDeliveryIfaceList = list()
		self.bigtapPolicyList = list()
		self.bigtapFilterGroupList = list()
		self.bigtapDeliveryGroupList = list()

	def getSwitchName(self, dpid):
		request_url = "/api/v1/data/controller/core/switch[dpid=\'{}\']?select=name".format(dpid)
		return self.scriptConfig.api_request(request_url)[0]['name']

	def getBigtapInterfaceList(self, bigtapIfaceType = 'filter'):
		returnList = list()
		if bigtapIfaceType == 'filter':
			request_url = '/api/v1/data/controller/applications/bigtap/topology/filter-interface?select=bigtapinterface'
		else:
			request_url = '/api/v1/data/controller/applications/bigtap/topology/delivery-interface?select=bigtapinterface'
		rawList = self.scriptConfig.api_request(request_url)
		for interface in rawList:
			returnList.append({'name': interface['bigtapinterface'],
							  'physInface': interface['switch'],
							  'switch': self.getSwitchName(interface['switch'])
							  })
		return returnList

	def getBigtapIfaceGroupList(self, bigtapIfaceGroupType = 'filter'):
		returnList = list()
		if bigtapIfaceType == filter:
			request_url = '/api/v1/data/controller/applications/bigtap/filter-interface-group'
			groupType = 'filter'
		else:
			request_url = '/api/v1/data/controller/applications/bigtap/delivery-interface-group'
			groupType = 'delivery'
		rawList = self.scriptConfig.api_request(request_url)		
		for group in rawList:
			ifaceList = list()
			for groupName in group['{}-group'.format(groupType)]:
				ifaceList.append(groupName['name'])
			returnList.append({'name': group['name'],
							   'ifaceList': ifaceList
							  })
		return returnList

	def getBigtapPolicyList(self):
		request_url = '/api/v1/data/controller/applications/bigtap/policy?select=name&select=priority'
		return self.scriptConfig.api_request(request_url)

	def getIfaceByName(self, name):
		for iface in self.bigtapIfaceSet:
			if iface.name == name:
				return iface



class bigtapInterface():
	def __init__(self, name, **kwargs):
		self.name = name
		for attribute, value in kwargs.items():
			setattr(self, attribute, value)
		self.isfilter = False
		self.isdelivery = False
		self.asFilterList = list()
		self.asDeliveryList = list()

	def printPolicyUsage(self, bigtapIfaceType = 'filter'):
		result_list = list()
		if bigtapIfaceType == 'filter':
			for policy in self.asFilterList:
				result_list.append(policy.name)
		else:
			for policy in self.asDeliveryList:
				result_list.append(policy.name)
		return result_list

class bigtapFilterGroup():
	def __init__(self, name, **kwargs):
		self.name = name
		for attribute, value in kwargs.items():
			setattr(self, attribute, value)

class bigtapPolicy():
	def __init__(self, **kwargs):
		self.policyDeliveryIfaceList = list()
		self.policyFilterIfaceList = list()
		self.priority = '-1'
		for attribute, value in kwargs.items():
			setattr(self, attribute, value)

class bigtapGraph():
	def __init__(self, **kwargs):
		self.bigtapGraph = nx.DiGraph()
		for attribute, value in kwargs.items():
			setattr(self, attribute, value)

	def bigtapIfaceBranch(self, bigtapIface):
		nextIfaceList = list()
		if not self.bigtapGraph.has_node(bigtapIface.name):
			self.bigtapGraph.add_node(bigtapIface.name, shape = 'box')
		for policy in bigtapIface.asFilterList:
			if not self.bigtapGraph.has_node('{} | {}'.format(policy.name, policy.priority)):
				self.bigtapGraph.add_node('{} | {}'.format(policy.name, policy.priority), shape = 'box', style='rounded,filled')
			self.bigtapGraph.add_edge(bigtapIface.name, '{} | {}'.format(policy.name, policy.priority))
			for iface in policy.policyDeliveryIfaceList:
				if not self.bigtapGraph.has_node(iface.name):
					self.bigtapGraph.add_node(iface.name, shape = 'box')
				self.bigtapGraph.add_edge('{} | {}'.format(policy.name, policy.priority), iface.name)
				nextIfaceList.append(iface)
		return nextIfaceList
	
	def bigtapIfaceGraph(self, bigtapIface):
		for iface in self.bigtapIfaceBranch(bigtapIface):
			self.bigtapIfaceGraph(iface)
		return True

	def bigtapIfaceGraphDraw(self):
		self.bigtapGraph.graph['graph'] = {'splines': 'ortho', 'ranksep': '2', 'nodesep': '2'}
		bigtapAGraph = to_agraph(self.bigtapGraph)
		bigtapAGraph.layout('dot')
		bigtapAGraph.draw('{}.png'.format(self.scriptConfig.output_name))
		return True

def main():
	scriptConfig = ClassScriptConfig()
	bmfController = bigtapFabric(**{'scriptConfig': scriptConfig})

	for iface in bmfController.getBigtapInterfaceList('filter'):
		newFilterIface = bigtapInterface(**{**iface, **{'scriptConfig': scriptConfig}})
		newFilterIface.isfilter = True
		bmfController.bigtapFilterIfaceList.append(newFilterIface)

	for iface in bmfController.getBigtapInterfaceList('delivery'):
		for bigtapIface in bmfController.bigtapFilterIfaceList:
			if bigtapIface.name == iface:
				bmfController.bigtapDeliveryIfaceList.append(bigtapIface)
				bmfController.bigtapDeliveryIfaceList[-1].isdelivery = True
		else:
			newDeliveryIface = bigtapInterface(**{**iface, **{'scriptConfig': scriptConfig}})
			newDeliveryIface.isdelivery = True
			bmfController.bigtapDeliveryIfaceList.append(newDeliveryIface)

	bmfController.bigtapIfaceSet = set(bmfController.bigtapFilterIfaceList).union(set(bmfController.bigtapDeliveryIfaceList))

	for policy in bmfController.getBigtapPolicyList():
		newPolicy = bigtapPolicy(**{**policy, **{'scriptConfig': scriptConfig}})
		request_url = "/api/v1/data/controller/applications/bigtap/policy[name=\'{}\']/filter-interface?select=bigtapinterface".format(newPolicy.name)
		rawList = scriptConfig.api_request(request_url)
		for ifaceList in rawList:
			temp_list = ifaceList['bigtapinterface'].split(', ')
			for iface in temp_list:
				if bmfController.getIfaceByName(iface) not in newPolicy.policyFilterIfaceList:
					newPolicy.policyFilterIfaceList.append(bmfController.getIfaceByName(iface))
					newPolicy.policyFilterIfaceList[-1].asFilterList.append(newPolicy)
		request_url = "/api/v1/data/controller/applications/bigtap/policy[name=\'{}\']/delivery-interface?select=bigtapinterface".format(newPolicy.name)
		rawList = scriptConfig.api_request(request_url)
		for ifaceList in rawList:
			temp_list = ifaceList['bigtapinterface'].split(', ')
			for iface in temp_list:
				if bmfController.getIfaceByName(iface) not in newPolicy.policyDeliveryIfaceList:
					newPolicy.policyDeliveryIfaceList.append(bmfController.getIfaceByName(iface))
					newPolicy.policyDeliveryIfaceList[-1].asDeliveryList.append(newPolicy)

		bmfController.bigtapPolicyList.append(newPolicy)

	graph = bigtapGraph(**{'scriptConfig': scriptConfig})
	for ifaceName in scriptConfig.filterInterfaceList:	
		bigtapFilterIface = bmfController.getIfaceByName(ifaceName)
		graph.bigtapIfaceGraph(bigtapFilterIface)

	print(graph.bigtapIfaceGraphDraw())


if __name__ == '__main__':
    main()


