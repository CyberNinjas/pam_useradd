pam module that creates new users
=================================

intro
-----

pam_useradd dynamically creates new user accounts if they do not yet exist on the system.

usage
-----

> auth     optional       pam_useradd.so

security
--------

Default system policies should be set up in a way that new
users don't gain privileges that can be used to damage the system.

do not use the module with 'su'. It's not safe to be used in setuid
context.
