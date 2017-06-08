#!/usr/bin/env python
# Brian Adams, DevOps Contractor 2016.
# Tested with Python 2.7

import cloudpassage
import re
from os import environ,path,getcwd
import json
import simplejson
import yaml
import argparse
from collections import Counter,defaultdict
# from collections import defaultdict


class PolicyGen:
    # Using **kwargs for pep8 compliance
    def __init__(self, *kwargs):
        # Groups and prod lists to be replace by yaml template
        self.cwd = path.realpath(path.join(getcwd(), path.dirname(__file__)))
        self.api_key = environ['CLOUDP_KEY']
        self.api_secret = environ['CLOUDP_SECRET']
        self.session = cloudpassage.HaloSession(self.api_key, self.api_secret)
        self.server = cloudpassage.Server(self.session)
        self.policies = cloudpassage.FirewallPolicy(self.session)
        self.policy_init = cloudpassage.policy.Policy(self.session)
        self.poldetails = cloudpassage.FirewallRule(self.session)
        self.firewall_services = cloudpassage.FirewallService(self.session)
        self.http_helper = cloudpassage.HttpHelper(self.session)
        self.args = args
        self.firewall_ports = {}
        self.filtered_ports = {}
        self.rules = []
        self.myrules = {}
        self.users = {}
        self.user_id = {}
        self.filtered_rules = {}
        self.rule_ids = []
        self.filtered_rule_ids = {}
        self.log_positions = {}
        self.pol_positions = {}
        self.list_of_servers = self.server.list_all()
        self.list_of_policies = self.policies.list_all()
        self.list_of_services = self.firewall_services.list_all()
        self.policy_names = []
        self.filtered_groups = []
        self.policy_ids = []
        self.filtered_policy_ids = []
        self.unfiltered_policy_ids = []
        self.filtered_policies = {}
        self.activerules = {}
        self.myactiverules = {}
        self.activecomments = {}
        self.activeurls = {}
        self.activepolicies = {}
        self.user = {}
        self.json = {}
        self.group = kwargs[0]
        self.chain = kwargs[1]
        self.active = kwargs[2]
        self.source = kwargs[3]
        self.destination = kwargs[4]
        self.states = kwargs[5]
        self.action = kwargs[6]
        self.username = kwargs[11]
        self.all = kwargs[12]
        # Split without spaces being added
        self.service = kwargs[7]
        self.filtered_service = {}
        self.unfiltered_service = {}
        self.log = kwargs[8]
        self.log_prefix = kwargs[9]
        self.comment = kwargs[10]
        self.wildcard = kwargs[13]
        self.setactive = kwargs[14]
        self.setinactive = kwargs[15]
        self.dryrun = kwargs[16]
        self.subtractfromlastrule = kwargs[17]
        self.deleteinactive = kwargs[18]
        self.fullbackup = kwargs[19]
        self.fullrestore = kwargs[20]
        self.filename = kwargs[21]

    def getusers(self):

        # Not included in api due to being subject to change

        endpoint = "/v2/users"
        request = self.http_helper
        key = "users"
        max_pages = 50
        response = request.get_paginated(endpoint, key, max_pages)
        user_details = response

        return user_details

    # Get policy names and ids and filter based on group names

    def getpolicies(self):

        if self.fullbackup is not True and self.fullrestore is not True:
            self.users = self.getusers()

            for user in self.users:
                if user['username'] == self.username:
                    self.user[user['username']] = user['id']
                    self.user_id = user['id']

            if self.user_id == {}:
                raise KeyError("User not found!")

        elif self.fullbackup is True or self.fullrestore is True:
            pass

        # Get all policies if args set to all, otherwise filter policies
        for service in self.list_of_services:
            if self.all is False and service["name"] == self.service:

                self.filtered_service["name"] = service['id']
                self.filtered_service[service['id']] = service['name']

        for policy in self.list_of_policies:

            self.policy_names.append(policy["name"])
            self.policy_ids.append(policy["id"])

        self.filtered_policies = dict(zip(self.policy_names, self.policy_ids))

        for policy, polid in self.filtered_policies.iteritems():
            if self.all is False and (self.fullbackup is False and self.fullrestore is False):
                if self.wildcard is True:
                    if self.group in policy:

                        self.filtered_groups.append(policy)
                        self.filtered_policy_ids.append(polid)

                elif self.wildcard is False:
                    if self.group == policy:

                        self.filtered_groups.append(policy)
                        self.filtered_policy_ids.append(polid)

            elif self.all is True or (self.fullbackup is True or self.fullrestore is True):
                self.filtered_groups.append(policy)
                self.filtered_policy_ids.append(polid)

        self.filtered_policies = dict(zip(self.filtered_groups, self.filtered_policy_ids))

        # Get each rule in each filtered policy. Will need refactoring.
        for polkey, polvalue in self.filtered_policies.iteritems():

            self.rules.append(self.poldetails.list_all(polvalue))

        self.rules = json.dumps(self.rules)
        self.rules = json.loads(self.rules)

        # Grab each rule and its corresponding url by chain and user
        for rules in self.rules:
            for rule in rules:
                if self.chain == rule['chain'] and (self.fullbackup is False and self.fullrestore is False):

                    self.myrules[rule['id']] = rule['url']

                elif (self.fullbackup is True or self.fullrestore is True):

                    self.myrules[rule['id']] = rule['url']

        # Take each rule and identify its matching policy
        for rule, url in self.myrules.iteritems():
            for policy, polid in self.filtered_policies.iteritems():
                if polid in url:
                    if (self.fullbackup is False and self.fullrestore is False):

                        self.filtered_rule_ids[rule] = policy

                    elif (self.fullbackup is True or self.fullrestore is True):

                        self.filtered_rule_ids[rule] = polid

        # Determine log position by counting rule frequency
        log_count = Counter(self.filtered_rule_ids.values())

        for rule in log_count:

            # Add before the last 3 rules, typically being loopback
            # May need to remove this since it seems to apply before last rule anyway
            # Takes absolute value of number of negative 
            if log_count.values()[0] != 1:

                self.log_positions[rule] = log_count[rule] - self.subtractfromlastrule

                if self.log_positions[rule] < 1: 

                    if abs(self.log_positions[rule]) != 0:
                        self.log_positions[rule] = abs(self.log_positions[rule])
                    else: self.log_positions[rule] = abs(self.log_positions[rule]) + 1

            elif log_count.values()[0] == 1:

                self.log_positions[rule] = log_count[rule]

            elif log_count.values()[0] == 0:
       
                self.log_positions[rule] == self.log_positions[rule] + 1   

        for polname, pos in self.log_positions.iteritems():
            for policy, polid in self.filtered_policies.iteritems():
                if policy in polname:

                    self.pol_positions[polid] = pos

        if self.fullbackup is False and self.fullrestore is False:
            for polname, pos in self.log_positions.iteritems():
                print "%s, %s, %s, %s" % (polname, pos, self.service, self.username)

        elif self.fullbackup is True or self.fullrestore is True:
                pass


    def backupall(self):
        print "\nWriting rules to %s... " % (self.filename)
        with open(path.join(self.cwd, self.filename), 'w') as file:
            for rule,policy_id in self.filtered_rule_ids.iteritems():
                # print str(self.poldetails.describe(policy_id, rule))
                # file.write(str(self.poldetails.describe(policy_id, rule)) + "\n")

                for policy,pol_id in self.filtered_policies.iteritems():
                    if policy_id in pol_id:
                        file.write("%s\n%s\n" % (str(self.poldetails.describe(policy_id, rule)), policy))

            file.close()

    def restoreall(self):

        d = defaultdict(list)

        with open(path.join(self.cwd, self.filename), 'r') as file:
            for line in file:
                if line.startswith('{'):
                    print line
                    # rule looks like this:
                    """
                    {u'comment': u'bar IN 1', u'log_prefix': u'',
                     u'firewall_service': {u'protocol': u'TCP', u'name': u'ssh',
                                           u'url': u'https://api.cloudpassage.com/v1/firewall_services/ea3fe1309956012ee2db4040ebe4a8e4',
                                           u'system': True, u'group_name': None, u'port': u'22', u'shared': True,
                                           u'group_id': None, u'id': u'ea3fe1309956012ee2db4040ebe4a8e4'},
                     u'log': False, u'chain': u'INPUT',
                     u'url': u'https://api.cloudpassage.com/v1/firewall_policies/cce9aa407eac11e68e517b69c9287cc2/firewall_rules/ccf0032c7eac11e68e517b69c9287cc2',
                     u'active': False, u'connection_states': u'NEW, ESTABLISHED', u'action': u'ACCEPT',
                     u'position': 1, u'id': u'ccf0032c7eac11e68e517b69c9287cc2'}
                    """
                    rule_ids = re.search('(?<=position\': \d, u\'id\': u\')(.*)', line)
                    rule_urls = re.search('chain\': (.*) u\'url\':(.+?(?=(active|firewall_target)))', line)
                    rule_urls = ''.join(rule_urls.groups()[1]).split('u\'')[1].split('\'')[0]

                    for rule_id in rule_ids.groups():
                        comment = ''
                        log_prefix = ''
                        log = ''
                        chain = ''
                        protocol = ''
                        source_service_id = ''
                        position = ''
                        firewall_source_id = ''
                        firewall_target_id = ''
                        active = ''
                        connection_states = ''
                        action = ''
                        fw_type = ''
                        pol_id = ''

                        rule_id = rule_id.strip('\'}')

                        if rule_id in self.myrules:
                            pass

                        else:
                                if rule_id in rule_urls:

                                    # This could probably be refactored
                                    for index, item in enumerate(line.split('u\'')):
                                        myline = line.split('u\'')
                                        if 'comment' in item:
                                            comment = myline[index + 1].split('\',')[0]

                                        if 'log_prefix' in item:
                                            log_prefix = myline[index + 1].split('\',')[0]

                                        if 'firewall_service\': {' in item:
                                            protocol = myline[index + 2].split('\',')[0]
                                            # End of firewall_service section, so cut out curly bracket
                                            source_service_id = myline[index + 14].split('\',')[0].split('\'}')[0]

                                        if 'log' in item and not 'log_prefix' in item:
                                            log = myline[index].split('\',')[0].split(':')[1].split(',')[0].strip(' ')

                                        if 'chain' in item:
                                            chain = myline[index + 1].split('\',')[0]
                                            pol_id = myline[index + 3].split('\',')[0].split('/')[5]

                                        if 'position' in item:
                                            position = int(myline[index].split('\',')[0].split(':')[1].split(',')[0].strip(' '))

                                        if 'firewall_source\': {' in item:
                                            # firewall_source_id = myline[index + 2].split('\',')[0
                                            firewall_source_id = myline[index + 6].split('\',')[0].split('},')[0].strip('\' ')

                                        if 'firewall_target\': {' in item:
                                            firewall_target_id = myline[index + 4].split('\',')[0]

                                        if 'active' in item:
                                            active = myline[index].split('\',')[0].split(':')[1].split(',')[0].strip(' ')

                                        if 'connection_states' in item:
                                            connection_states = myline[index].split(':')[1].rsplit(',', 1)[0].strip(' ')
                                            if connection_states == 'None':
                                                connection_states = None

                                        if 'action' in item:
                                            action = myline[index + 1].split('\',')[0]

                                        if 'type' in item:
                                            fw_type = myline[index + 1].split('\',')[0]

                                    policy_json = {
                                    'firewall_rule': {'chain': chain,
                                                      'firewall_source': {'id': source_service_id, 'type': fw_type},
                                                      'active': active, 'firewall_service': source_service_id,
                                                      'connection_states': connection_states, 'action': action,
                                                      'log': log,
                                                      'log_prefix': log_prefix, 'comment': comment,
                                                      'position': position }
                                    }


                                    if self.dryrun is True:
                                        print json.dumps(policy_json)

                                    elif self.dryrun is False:
                                        policy_json = {
                                         'firewall_rule': {'comment': comment, 'action': action,
                                                           'log_prefix': log_prefix,
                                                           'firewall_service': u'%s' % (source_service_id),
                                                           'log': log, 'chain': 'INPUT', 'position': position,
                                                           'active': active, 'connection_states': connection_states,
                                                           'firewall_source': {'type': 'User',
                                                                               'id': u'%s' % (firewall_source_id)}}}
                                        self.poldetails.create(pol_id, policy_json)
            file.close()

    def getactiverule(self):

        self.users = self.getusers()

        for user in self.users:
            if user['username'] == self.username:

                self.user[user['username']] = user['id']
                self.user_id = user['id']

        # Searches all rules for account number
        for service in self.list_of_services:
            if service["name"] == self.service:

                self.filtered_service["name"] = service['id']
                self.filtered_service[service['id']] = service['name']

        for policy in self.list_of_policies:

            self.policy_names.append(policy["name"])
            self.policy_ids.append(policy["id"])

        self.filtered_policies = dict(zip(self.policy_names, self.policy_ids))

        for policy, polid in self.filtered_policies.iteritems():
            if self.all is False:
                if self.wildcard is True:
                    if self.group in policy:

                        self.filtered_groups.append(policy)
                        self.filtered_policy_ids.append(polid)

                elif self.wildcard is False:
                    if self.group == policy:

                        self.filtered_groups.append(policy)
                        self.filtered_policy_ids.append(polid)

            elif self.all is True or self.fullbackup is True:

                self.filtered_groups.append(policy)
                self.filtered_policy_ids.append(polid)

        self.filtered_policies = dict(zip(self.filtered_groups, self.filtered_policy_ids))

        # Get each rule in each filtered policy. Will need refactoring.
        for polkey, polvalue in self.filtered_policies.iteritems():
            self.rules.append(self.poldetails.list_all(polvalue))

        self.rules = json.dumps(self.rules)
        self.rules = json.loads(self.rules)
        # Grab each rule and its corresponding url by chain
        for rules in self.rules:
            for rule in rules:
                if self.all is False:
                    if self.comment == rule['comment']:
                        if self.setactive is True or self.deleteinactive is True:
                            for polkey, polvalue in self.filtered_policies.iteritems():
                                if polvalue in rule['url'] and rule['active'] is False:
                                    # BREAKPOINT
                                    print "%s, %s, %s" % (polkey, rule['comment'], rule['firewall_source']['username'])
                                    self.myactiverules[rule['id']] = polvalue
                                    self.activerules[rule['id']] = {}
                                    self.activerules[rule['id']] = rule['url']
                                    self.activecomments[rule['id']] = rule['comment']
                                    self.activepolicies[rule['id']] = polkey
                                    self.activeurls[polkey] = rule['url']

                        elif self.setinactive is True:
                            for polkey, polvalue in self.filtered_policies.iteritems():
                                if polvalue in rule['url'] and rule['active'] is True:
                                    print "%s, %s, %s" % (polkey, rule['comment'], rule['firewall_source']['username'])
                                    self.myactiverules[rule["id"]] = polvalue
                                    self.activerules[rule['id']] = {}
                                    self.activerules[rule['id']] = rule['url']
                                    self.activecomments[rule['comment']] = polkey
                                    self.activeurls[polkey] = rule['url']

                # Add rules by user id instead of by comment
                elif (self.all is True and self.setactive is True) or \
                     (self.all is True and self.deleteinactive is True):
                    if "firewall_source" in rule:
                        if "id" in rule["firewall_source"]:
                            if self.user_id == rule["firewall_source"]["id"] and rule["active"] is False:
                                for polkey, polvalue in self.filtered_policies.iteritems():
                                    if polvalue in rule["url"]:
                                        print "%s, %s, %s" % (polkey, rule['comment'], rule['firewall_source']['username'])
                                        self.myactiverules[rule["id"]] = polvalue
                                        self.activerules[rule["id"]] = {}
                                        self.activerules[rule["id"]] = rule["url"]
                                        self.activecomments[rule["comment"]] = polkey
                                        self.activeurls[polkey] = rule['url']

                elif (self.all is True and self.setinactive is True) or \
                     (self.all is True and self.deleteinactive is False):
                    if "firewall_source" in rule:
                        if "id" in rule["firewall_source"]:
                            if self.user_id == rule["firewall_source"]["id"] and rule["active"] is True:
                                for polkey, polvalue in self.filtered_policies.iteritems():
                                    if polvalue in rule["url"]:
                                        print "%s, %s, %s" % (polkey, rule['comment'], rule['firewall_source']['username'])
                                        self.myactiverules[rule["id"]] = polvalue
                                        self.activerules[rule["id"]] = {}
                                        self.activerules[rule["id"]] = rule["url"]
                                        self.activecomments[rule['comment']] = polkey
                                        self.activeurls[polkey] = rule['url']

                elif (self.fullbackup is True or self.fullrestore is True):
                        if "firewall_source" in rule:
                            if "id" in rule["firewall_source"]:
                                for polkey, polvalue in self.filtered_policies.iteritems():
                                    if polvalue in rule["url"]:
                                        print "%s, %s, %s" % (polkey, rule['comment'], rule['firewall_source']['username'])
                                        self.myactiverules[rule["id"]] = polvalue
                                        self.activerules[rule["id"]] = {}
                                        self.activerules[rule["id"]] = rule["url"]
                                        self.activecomments[rule['comment']] = polkey
                                        self.activeurls[polkey] = rule['url']

    def setactiverule(self):
        for rule, polid in self.myactiverules.iteritems():
            if rule != {}:
                rule_json = {'firewall_rule': {'active': True}}
                self.poldetails.update(polid, rule, rule_json)

    def setinactiverule(self):
        for rule, polid in self.myactiverules.iteritems():
            if rule != {}:
                rule_json = {'firewall_rule': {'active': False}}
                self.poldetails.update(polid, rule, rule_json)

    def deleteinactiverule(self):
        for rule, polid in self.myactiverules.iteritems():
            if rule != {}:
                self.poldetails.delete(polid, rule)

    def updatepolicies(self):
        # Add new firewall rule for each port for a specified rule
        # Expected: name: ssh, value: 12345678...
        # filitered_service = self.filtered_service.values()
        # filtered_service = self.filtered_service
        for pol, pos in self.pol_positions.iteritems():
            for service in self.list_of_services:
                if service["name"] == self.service:
                    policy_json = {
                        'firewall_rule': {'chain': self.chain, 'firewall_source': {'id': self.user_id, 'type': 'User'},
                                          'active': self.active, 'firewall_service': service["id"],
                                          'connection_states': self.states, 'action': self.action, 'log': self.log,
                                          'log_prefix': self.log_prefix, 'comment': self.comment, 'position': pos}}

                    print policy_json
                    self.poldetails.create(pol, policy_json)


class Execute:
    def __init__(self, *kwargs):
        self.all = kwargs[0].all
        self.dryrun = kwargs[0].dry
        self.setactive = kwargs[0].setactive
        self.setinactive = kwargs[0].setinactive
        self.deleteinactive = kwargs[0].deleteinactive
        self.filename = kwargs[0].filename
        self.fullbackup = kwargs[0].fullbackup
        self.fullrestore = kwargs[0].fullrestore

    def backupall(self):

        policies = PolicyGen(False, False, False,
                             False, False, False,
                             False, False, False,
                             False, False, False, self.all,
                             False, self.setactive, self.setinactive,
                             self.dryrun, False, self.deleteinactive, self.fullbackup, self.fullrestore, self.filename)

        policies.getpolicies()
        policies.backupall()

    def restoreall(self):

        policies = PolicyGen(False, False, False,
                             False, False, False,
                             False, False, False,
                             False, False, False, self.all,
                             False, self.setactive, self.setinactive,
                             self.dryrun, False, self.deleteinactive, self.fullbackup, self.fullrestore, self.filename)

        policies.getpolicies()
        policies.restoreall()

    def applypolicy(self):
        # Have to split service names and remove additional whitespace

        with open(self.filename, 'r') as stream:
            group_names = yaml.load(stream)

        active_groups = [name.strip() for name in group_names["groups"]["enabled"].split(',')]
        usernames = [username.strip() for username in group_names["groups"]["usernames"].split(',')]

        for group in active_groups:
            group_names[group]['service'] = {}
            group_names[group]['service'] = [service.strip() for service in group_names[group]['services'].split(',')]

        if self.dryrun is True:
            print "\nApplying policy rules (dry run)...\n"
            print "POLICY POSITION SERVICE USER\n"

        elif self.dryrun is False:
            print "\nApplying policy rules...\n"
            print "POLICY POSITION SERVICE USER\n"

        # Set default fields
        for group in active_groups:
            if group_names["groups"]["comment"] is None:
                comment = group_names[group]["comment"]
            else:
                comment = group_names["groups"]["comment"]

            if group_names["groups"]["subtractfromlastrule"] is None:
                subtractfromlastrule = group_names[group]["subtractfromlastrule"]
            else:
                subtractfromlastrule = group_names["groups"]["subtractfromlastrule"]

            if group_names["groups"]["usernames"] is None:
                username = group_names[group]["username"]

                for service in group_names[group]['service']:
                    policies = PolicyGen(group_names[group]['name'], group_names[group]['chain'],
                                         group_names[group]['active'],
                                         service, group_names[group]['destination'], group_names[group]['states'],
                                         group_names[group]['action'], service, group_names[group]['log'],
                                         group_names[group]['log_prefix'], comment, username, self.all,
                                         group_names[group]['wildcard'], self.setactive, self.setinactive, self.dryrun,
                                         subtractfromlastrule, self.deleteinactive, self.fullbackup, self.fullrestore,
                                         self.filename)

                    if self.dryrun is True:
                        policies.getpolicies()

                    elif self.dryrun is False:
                        policies.getpolicies()
                        policies.updatepolicies()

            # Run through multiple users
            else:
                for user in usernames:
                    # Only apply to active groups
                    # Apply for multiple users
                    for service in group_names[group]['service']:
                        policies = PolicyGen(group_names[group]['name'], group_names[group]['chain'],
                                             group_names[group]['active'],
                                             service, group_names[group]['destination'], group_names[group]['states'],
                                             group_names[group]['action'], service, group_names[group]['log'],
                                             group_names[group]['log_prefix'], comment, user, self.all,
                                             group_names[group]['wildcard'], self.setactive, self.setinactive,
                                             self.dryrun, subtractfromlastrule, self.deleteinactive, self.fullbackup, self.fullrestore,
                                             self.filename)

                        if self.dryrun is True:
                            policies.getpolicies()

                        elif self.dryrun is False:
                            policies.getpolicies()
                            policies.updatepolicies()

        if policies.getpolicies.__self__.user is not False:
            print "\nUser %s has id %s" % (policies.getpolicies.__self__.user.keys()[0],
                                           policies.getpolicies.__self__.user.values()[0])

    def applyactivity(self):

        activerules = {}
        activecomments = {}

        with open(self.filename, 'r') as stream:
            group_names = yaml.load(stream)

        active_groups = [name.strip() for name in group_names["groups"]["enabled"].split(',')]
        usernames = [username.strip() for username in group_names["groups"]["usernames"].split(',')]

        for group in active_groups:
            group_names[group]['service'] = {}
            group_names[group]['service'] = [service.strip() for service in group_names[group]['services'].split(',')]

        if self.dryrun is True:
            print "\ndry run\n"

        # Set default fields
        if self.all is False:
            for group in active_groups:
                if group_names["groups"]["comment"] is None:
                    comment = group_names[group]["comment"]
                else:
                    comment = group_names["groups"]["comment"]

                if group_names["groups"]["subtractfromlastrule"] is None:
                    subtractfromlastrule = group_names[group]["subtractfromlastrule"]

                else:
                    subtractfromlastrule = group_names["groups"]["subtractfromlastrule"]

                if group_names["groups"]["usernames"] is None:
                    username = group_names[group]["username"]
                    for service in group_names[group]['service']:
                        policies = PolicyGen(group_names[group]['name'], group_names[group]['chain'],
                                             group_names[group]['active'],
                                             service, group_names[group]['destination'], group_names[group]['states'],
                                             group_names[group]['action'], service, group_names[group]['log'],
                                             group_names[group]['log_prefix'], comment, username, self.all,
                                             group_names[group]['wildcard'], self.setactive, self.setinactive,
                                             self.dryrun, subtractfromlastrule, self.deleteinactive, self.fullbackup,
                                             self.fullrestore, self.filename)
                else:
                    # Apply to all users
                    # Only apply to active groups
                    for user in usernames:
                        for service in group_names[group]['service']:
                            policies = PolicyGen(group_names[group]['name'], group_names[group]['chain'],
                                                 group_names[group]['active'],
                                                 service, group_names[group]['destination'],
                                                 group_names[group]['states'],
                                                 group_names[group]['action'], service, group_names[group]['log'],
                                                 group_names[group]['log_prefix'], comment, user, self.all,
                                                 group_names[group]['wildcard'], self.setactive, self.setinactive,
                                                 self.dryrun, subtractfromlastrule, self.deleteinactive, self.fullbackup,
                                                 self.fullrestore, self.filename)

                        policies.getactiverule()

                if self.dryrun is True and (self.setactive or self.deleteinactive) is True:
                   pass

                elif self.dryrun is False and self.setactive is True:

                    for comment, policy in policies.getactiverule.__self__.activecomments.iteritems():
                        for rule, url in policies.getactiverule.__self__.activerules.iteritems():
                            activerules[url] = rule
                            activecomments[policy] = comment

                    policies.setactiverule()

                elif self.dryrun is False and self.setinactive is True:
                    for comment, policy in policies.getactiverule.__self__.activecomments.iteritems():
                        for rule, url in policies.getactiverule.__self__.activerules.iteritems():
                            activerules[url] = rule
                            activecomments[policy] = comment

                    policies.setinactiverule()

                elif self.dryrun is False and self.deleteinactive is True:
                    for comment, policy in policies.getactiverule.__self__.activecomments.iteritems():
                        for rule, url in policies.getactiverule.__self__.activerules.iteritems():
                            activerules[url] = rule
                            activecomments[policy] = comment

                    policies.deleteinactiverule()

                elif self.dryrun is True and self.setinactive is True:
                    for comment, policy in policies.getactiverule.__self__.activecomments.iteritems():
                        for rule, url in policies.getactiverule.__self__.activerules.iteritems():
                            activerules[url] = rule
                            activecomments[policy] = comment

        elif self.all is True:

            for user in usernames:
                policies = PolicyGen(False, False, False,
                                     False, False, False,
                                     False, False, False,
                                     False, False, user, self.all,
                                     False, self.setactive, self.setinactive,
                                     self.dryrun, False, self.deleteinactive, self.fullrestore,
                                     self.fullbackup, self.filename)

            policies.getactiverule()

            if self.dryrun is True:
                for comment, policy in policies.getactiverule.__self__.activecomments.iteritems():
                    for rule, url in policies.getactiverule.__self__.activerules.iteritems():
                        print "%s, %s, %s" % (policy, comment, url)
                        activerules[url] = rule
                        activecomments[policy] = comment

            elif self.dryrun is False and self.setactive is True:
                for comment, policy in policies.getactiverule.__self__.activecomments.iteritems():
                    for rule, url in policies.getactiverule.__self__.activerules.iteritems():
                        print "%s, %s, %s" % (policy, comment, url)
                        activerules[url] = rule
                        activecomments[policy] = comment

                policies.setactiverule()

            elif self.dryrun is False and self.deleteinactive is True:
                for comment, policy in policies.getactiverule.__self__.activecomments.iteritems():
                    for rule, url in policies.getactiverule.__self__.activerules.iteritems():
                        print "%s, %s, %s" % (policy, comment, url)
                        activerules[url] = rule
                        activecomments[policy] = comment

                policies.deleteinactiverule()

            elif self.dryrun is False and self.setinactive is True:

                print "\nSetting rule inactive..."
                policies.setinactiverule()

        if policies.getpolicies.__self__.user is not False:
            print "\nUser %s has id %s" % (policies.getpolicies.__self__.user.keys()[0], policies.getpolicies.__self__.user.values()[0])

# End of classes. Parse arguments

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers()

parser = argparse.ArgumentParser()
parser.add_argument("--dry", help="view changes script will make without them being made", action="store_true")
parser.add_argument("--all", help="apply to all policies with user", action="store_true")
parser.add_argument("--setactive", help="sets inactive rules with matching comment to active", action="store_true")
parser.add_argument("--setinactive", help="sets active rules with matching comment to inactive", action="store_true")
parser.add_argument("--deleteinactive", help="deletes inactive rule based on comment or all", action="store_true")
parser.add_argument("--fullbackup", help="creates a full backup of all policies", action="store_true")
parser.add_argument("--fullrestore", help="creates a full restore of all policies", action="store_true")
parser.add_argument('filename')
args = parser.parse_args()

if __name__ == "__main__":
    try:
        execute = Execute(args)

        if args.setactive is False and args.setinactive is False and args.deleteinactive is False and args.fullbackup is False and args.fullrestore is False:

            print "\nApplying to policy..."
            execute.applypolicy()

        elif args.setactive is True or args.setinactive is True or args.deleteinactive is True:

            print "\nApplying activity to rule(s)...\n"

            execute.applyactivity()

        elif args.fullbackup is True and args.fullrestore is False:

            print "\nGenerating full backup"

            execute.backupall()

        elif args.fullrestore is True and args.fullbackup is False:

            print "\nRunning full restore"

            execute.restoreall()

    except Exception as e:
        print "Error: {0}".format(e)
