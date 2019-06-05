#!/usr/bin/python

"""
This script is intended to:
   - What policies are used specific IPv4 prefix as src, dst or both?
   - Where is this prefix match (switches) and how much traffic (bps) this prefix generate.
To start the script please provide the following info:
   -c - IP address of controller
   -t - Token to access to controller's API
   -d - Is this prefix source 'src', destination 'dst' or both
   -p - The IPv4 prefix what we would like to find out among policies
"""


import json
import requests
import sys
import ipaddress
import argparse
from multiprocessing import Pool
from collections import defaultdict
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def argument_parsing():
	"""
	Just simple argument parsing function. 
	Check arguments and return a dictionary with arguments if they are correct
	"""
	isvalid = True
	parser = argparse.ArgumentParser()
	parser.add_argument("-c", "--controller", required=True, help="Provide IP address or FQDN of controller")
	parser.add_argument("-t", "--token", required=True, help="Provide token to connect to controller")
	parser.add_argument("-d", "--direction", required=True, help="Provide prefix's direction. Use 'src', 'dst' or 'both' ")
	parser.add_argument("-p", "--prefix", required=True, help="Provide IPv4 prefix to search. Use d.d.d.d/dd")
	args = vars(parser.parse_args())
	controller = args['controller']
	token = args['token']
	direction = args['direction']
	prefix = args['prefix']
	try:
		args['prefix'] = ipaddress.ip_network(prefix)
	except:
		print('Unable to parse prefix. Try d.d.d.d/dd again')
		isvalid = False
	if direction not in ['src', 'dst', 'both']:
		print('Wrong direction. Try \'src\', \'dst\' or \'both\'')
		isvalid = False
	if not is_controller_alive(token, controller):
		isvalid = False
	if isvalid:
		return args
	else:
		sys.exit('Something wrong. Please check some arguments')
		return None

def is_controller_alive(session_cookie, controller_ip):
	"""
	Chech whether are controller IP and token correct
	"""
	url = 'https://{}:8443{}'.format(controller_ip, '/api/v1/data/controller/core/version')
	headers = {"content-type": "application/json"}
	headers['Cookie'] = 'session_cookie={}'.format(session_cookie)
	isalive = False
	try:
		code = requests.request('GET', url, headers=headers, verify=False).status_code
		if code == 200:
			isalive = True
		elif code == 401:
			print('Authentication error. Please check the token')
		else:
			print('Something wrong with connection to controller. Sorry')
	except requests.ConnectionError:
		print ('Unable to reach controller. Please check IP or FQDN')
	except:
		print('Something wrong with connection to controller. Sorry')
	return isalive


def api_request(session_cookie, controller_ip, path, method = 'GET', data = ''):
	"""
	Just simple API request function. Return list with JSON response
	"""
	url = 'https://{}:8443{}'.format(controller_ip, path)
	headers = {"content-type": "application/json"}
	headers['Cookie'] = 'session_cookie={}'.format(session_cookie)
	response = requests.request(method, url, data=data, headers=headers, verify=False).json()
	return (response)

def configured_policy_prefix_check(policy_list, prefix, direction = 'both'):
	"""
	This function check if the prefix match inside policies match rules among all BMF policies.
	Return dictionary where keys are policy name and value is list of matched rules. 
	"""
	matched_policies = defaultdict(list)
	for policy in policy_list:
		if 'rule' in policy:
			for rule in policy['rule']:
				if 'ether-type' in rule:
					if rule['ether-type'] == 2048:
						try:
							if direction in ('src', 'both') and prefix.overlaps(ipaddress.ip_network('{}/{}'.format(rule['src-ip'], rule['src-ip-mask']))):
								matched_policies[policy['name']].append(rule)
							if direction in ('dst', 'both') and prefix.overlaps(ipaddress.ip_network('{}/{}'.format(rule['dst-ip'], rule['dst-ip-mask']))):
						   		matched_policies[policy['name']].append(rule)
						except:
							pass
	return matched_policies

def is_flow_bytes_match(flow_prefix_string, flow_mask_string, prefix_string):
	"""
	Check if a IPv4 address match a flow string.
	We use binary matching, because flow could contain non-contiguous mask 
	"""
	flow_ip_byte = ipaddress.ip_address(flow_prefix_string).packed
	flow_mask_byte = ipaddress.ip_address(flow_mask_string).packed
	prefix_ip_byte = ipaddress.ip_address(prefix_string).packed
	byte_match_list = [False, False, False, False]
	for ipv4_octet in range(0,4):
		if bytes([flow_ip_byte[ipv4_octet] & flow_mask_byte[ipv4_octet]]) == bytes([prefix_ip_byte[ipv4_octet] & flow_mask_byte[ipv4_octet]]):
			byte_match_list[ipv4_octet] = True
	if not False in byte_match_list:
		return True
	else:
		return False

def is_any_addr_match_flow(flow_prefix_string, flow_mask_string, prefix):
	"""
	Just check whether any IPv4 address from prefix match with flow.
	"""
	for ipv4addr in prefix:
		if is_flow_bytes_match(flow_prefix_string, flow_mask_string, str(ipv4addr)):
			return True
	else:
		return False


def is_prefix_match_flow(flow_prefix_string, flow_mask_string, prefix):
	"""
	If requered prefix is /32 we just check whether is it match with some flows.
	If lenght of prefix less then 32, we are needed check each IPv4 address to find out whether
	any IPv4 address match with flow. As it could be short prefix, we are needed to do it in parallel way.
	We split original prefix on two (odd) and four (even) parts and check their in parallel.
	If some prefix match with flow, this function returns True
	"""
	if prefix.prefixlen == 32:
		return is_flow_bytes_match(flow_prefix_string, flow_mask_string, str(prefix.network_address))
	else:
		pool_args = []
		if prefix.prefixlen % 2 == 0:
			subnets = list(prefix.subnets(prefixlen_diff=2))
		else:
			subnets = list(prefix.subnets(prefixlen_diff=1))
		for subnet in subnets:
			pool_args.append((flow_prefix_string, flow_mask_string, subnet))
		with Pool(processes=len(subnets)) as pool:
			result = pool.starmap(is_any_addr_match_flow, pool_args)
		return any(result)

def matched_flow(prefix, flow, field):
	"""
	This function builds list of the flow that prefix was matched. 
	List contains flow fields, current and peak rate.
	"""
	ismatch = False
	matched_fields = []
	if 'ipv4-address-mask' not in field:
		if prefix.overlaps(ipaddress.ip_network('{}/{}'.format(field['ipv4-address'], '32'))):
			ismatch = True
	else:
		try:
			if prefix.overlaps(ipaddress.ip_network('{}/{}'.format(field['ipv4-address'], field['ipv4-address-mask']))):
				ismatch = True
		except:
			ismatch = is_prefix_match_flow(field['ipv4-address'], field['ipv4-address-mask'], prefix)
	if ismatch:
		for flow_field in flow['flow-mod']['match-field']:
			if flow_field['type'] not in ['bsn-in-ports-512', 'in-port']:
				matched_fields.append(flow_field)
		return ({'flow':    matched_fields, 
				 'bitrate': flow['bit-rate'], 
				 'peak': 	flow['peak-bit-rate']
				})
	else:
		return None



def runtime_flow_statistics_check(controller_ip, session_cookie, prefix, policy_name, direction = 'both'):
	"""
	This function checks runtime flow statistics for requred prefix.
	Return dictionary where keys are switches and values are lists with flow fields, current and peak rate
	"""
	matched_flow_dict = defaultdict(list)
	flow_list = api_request(session_cookie, controller_ip, '/api/v1/data/controller/applications/bigtap/policy[name=\'{}\']?select=flow-info/flow'.format(policy_name))
	if len(flow_list) > 0:
		for switch in flow_list[0]['flow-info']:
			switch_name = api_request(session_cookie, controller_ip, '/api/v1/data/controller/core/switch[dpid=\'{}\']?select=name'.format(switch['switch']))[0]['name']
			for flow in switch['flow']:
				for field in flow['flow-mod']['match-field']:
					if (direction in ['src', 'both'] and field['type'] == 'ipv4-src') or (direction in ['dst', 'both'] and field['type'] == 'ipv4-dst'):
						current_flow = matched_flow(prefix, flow, field)
						if current_flow != None:
							matched_flow_dict[switch_name].append(current_flow)
	else:
		print('Inactive flow. Bye.')
		sys.exit(1)
	return matched_flow_dict



def formated_output(input_dict, prefix, controller_ip, session_cookie, type, policy_name = 'NULL'):
	"""
	Just pretty formatted output
	"""
	if type == 'prefix':
		print ('The prefix {} is conteined in the following policies:\n'.format(str(prefix)))
		for policy, rules in input_dict.items():
			policy_priority = api_request(session_cookie, controller_ip, '/api/v1/data/controller/applications/bigtap/policy[name=\'{}\']?select=priority'.format(policy))[0]['priority']
			print ('{}Policy {} (priority {}):\n'.format('\t', policy, policy_priority))
			for rule in rules:
				print ('{}rule #{}'.format('\t'*2,rule['sequence']))
				for key, value in rule.items():
					if key != 'sequence':
						print ('{}{}: {}'.format('\t'*3, key, value))
			print ('-'*50)
	if type == 'flow':
		print ('Statistics for prefix {} in policy {}:'.format(str(prefix), policy_name))
		for switch, flows in input_dict.items():
			print ('{}Switch {}'.format('\t', switch))
			for flow in flows:
				print ('{}Current bit rate {:.6f}Gbps\n{}Peak bit rate {:.6f}Gbps'.format('\t'*2, int(flow['bitrate'])/1000000000, '\t'*2, int(flow['peak'])/1000000000))
				for element in flow['flow']:
					for field, value in element.items():
						print('{}{}:{}'.format('\t'*3, field, value))
			print ('-'*50)



def main():
	#Argument parsing
	script_args = argument_parsing()
	controller_ip = script_args['controller']
	session_cookie = script_args['token']
	direction = script_args['direction']
	prefix = script_args['prefix']
	#Collect all policies from controller
	policy_list = api_request(session_cookie, controller_ip, '/api/v1/data/controller/applications/bigtap/policy')
	#Check what policies the prefix match
	matched_policies = configured_policy_prefix_check(policy_list, prefix, direction)
	if len(matched_policies) > 0:
		#If the matched policies exist, show their
		formated_output(matched_policies, prefix, controller_ip, session_cookie, 'prefix')
		#If we would like to see statistics per switch and flow for requred prefix, choose policy
		print ('If you would like to see statistics by the prefix, please choice a policy:')
		for index, policy in enumerate(list(matched_policies.keys())):
			print ('[{}] - {}'.format(index+1, policy))
		policy_index = input('Please choice the policy for monitoring: ')
		try:
			policy = list(matched_policies.keys())[int(policy_index)-1]
		except:
			print ('Wrong choice! Bye')
			sys.exit(1)
		#Collect runtime statistics for the prefix	
		matched_flow = runtime_flow_statistics_check(controller_ip, session_cookie, prefix, policy, direction)
		formated_output(matched_flow, prefix, controller_ip, session_cookie, 'flow', policy)
	else:
		sys.exit('There aren\'t any matching for prefix {}'.format(str(prefix)))

if __name__ == '__main__':
	main()