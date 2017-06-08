NOTES: adding "--all" as an arg runs script based on user and applies to all
rules with user in firewall source rather than based on comment and user. All 
values in this examples have been substituded and will not reflect correct values
in cloudpassage account. 

DRY RUN
=======

```
./policy_gen.py groups.yml --dry

Applying to policy...

Applying policy rules (dry run)...

POLICY POSITION SERVICE USER

foobar, 3, ssh, foobar
bar, 3, ssh, foobar
foobar, 3, cp-ssh, foobar

User foobar has id b123456789abcdefghijklmnop
```

APPLIED RUN
===========
```
$ ./policy_gen.py --deleteinactive groups.yml

Applying activity to rule(s)...

foobar, autogen1, foobar
bar, autogen1, foobar

User foobar has id a123456789abcdefg
```

SET RULES ACTIVE BASED ON COMMENT AND USER
==========================================

```
$ ./policy_gen.py --setactive groups.yml

Applying activity to rule(s)...

foobar, autogen1, foobar
bar, autogen1, foobar

User foobar has id a123456789abcdefg
```

SET RULES INACTIVE
==================

```
$ ./policy_gen.py groups.yml --dry --setactive

Applying activity to rule(s)...


dry run

foobar, autogen1, foobar
bar, autogen1, foobar
foobar, autogen1, foobar

User foobar has id a123456789abcdefg
```

DELETE RULES WITH COMMENT AND USER
==================================
```
./policy_gen.py --deleteinactive groups.yml

Applying activity to rule(s)...

foobar, autogen1, foobar
bar, autogen1, foobar

User foobar has id a123456789abcdefg
```
