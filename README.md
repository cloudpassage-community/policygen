#### LICENSE 

Copyright (c) 2016, CloudPassage, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of CloudPassage, Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CLOUDPASSAGE, INC. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#### GENERAL

This is a script meant to showcase what you can do with the CloudPassage API, and more generally, the SDK. It will either add after the first rule when "subtractfrom: 1" is stated, and if the value end up being greater than the number of rules in the policy, it will take the absolute value and use that. If there are 10 rules in a policy, for example, and subtractfrom: 15 is used, it will attempt to add at +15 and will become the last rule in the policy. I am open to other ideas as far as this is concerned. 

If more than one service/port is specified in a comma-seperated list, the script will add a rule for each service depending on the group. 

#### LIMITATIONS

Currently there are no verification checks apart from ensuring a user exists, so use at your own risk. It is fairly simple and quick to delete any rules that match a comment. In an ideal world bastions created for specific groups of users based on their role would be the strategy to use for granting access via Halo (i.e. "dev" bastion can access dev policies, and specific users in dev group are allowed access to dev bastion)

#### BASIC USAGE


./policy_gen.py groups.yml --dry

Applying to policy...

Applying policy rules (dry run)...

POLICY POSITION SERVICE USER

foobar, 3, ssh, foobar
bar, 3, ssh, foobar
foobar, 3, cp-ssh, foobar

User foobar has id b123456789abcdefghijklmnop

$ ./policy_gen.py groups.yml

Applying to policy...

Applying policy rules...

POLICY POSITION SERVICE USER

foobar, 3, ssh, foobar
bar, 3, ssh, foobar
{'firewall_rule': {'comment': 'autogen1', 'action': 'ACCEPT', 'log_prefix': None, 'firewall_service': u'ea3fe1309956012ee2db4040ebe4a8e4', 'log': False, 'chain': 'INPUT', 'position': 3, 'active': False, 'connection_states': 'NEW, ESTABLISHED', 'firewall_source': {'type': 'User', 'id': u'b96845ce4ba411e7b90f354f2b504992'}}}
{'firewall_rule': {'comment': 'autogen1', 'action': 'ACCEPT', 'log_prefix': None, 'firewall_service': u'ea3fe1309956012ee2db4040ebe4a8e4', 'log': False, 'chain': 'INPUT', 'position': 3, 'active': False, 'connection_states': 'NEW, ESTABLISHED', 'firewall_source': {'type': 'User', 'id': u'b96845ce4ba411e7b90f354f2b504992'}}}
foobar, 4, cp-ssh, foobar

User foobar has id b123456789abcdefghijklmnop
