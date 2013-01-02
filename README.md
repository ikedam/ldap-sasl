LDAP SASL plugin
================

Japanese version of this document is README_ja.md

Jenkins plugin to use LDAP with SASL for authentication.

What's this?
------------

LDAP SASL is a [Jenkins](http://jenkins-ci.org/) plugin.
This plugin provides the "LDAP-SASL" security realm:

* This plugin performs authentication with LDAP server using the Simple Authentication and Security Layer (SASL) framework.
* You specify following parameters.
	* LDAP URI
		* URI to access to the LDAP server.
		* Multiple servers can be specified.
	* SASL Mechanisms
		* SASL mechanism to used in the authentication.
		* Multiple mechanisms can be specified. In that case, the most suitable mechanism negotiated with the LDAP server is used.
	* Group search base
		* the root DN where the group entries located.
		* You must specify if you want to use group-belonging information of users in the LDAP directories.
	* Prefix of Group Name
		* the prefix added to the group name. For example, "group1" group in LDAP directory will be treated as "ROLE_group1" in Jenkins.

Limitations
-----------

* To retrieve group information from the LDAP server, the following must be satisfied.
	* LDAP server supports LDAP "who am i?" extended operation.
	* LDAP "who am i?" request returns the distinguished name (cn=MyName,ou=People,dc=example,dc=com).
		* If returns username(MyName@example.com), the group information cannot be retrieved.
	* Group search base is specified.

How does this work?
-------------------

* This plugin uses JNDI to access to LDAP servers.
* The retrieval of groups an authenticated user belongs is performed in following steps:
	1. Resolve the DN of the authenticated user by using LDAP "who am i?" extended operation.
	2. Search for groups: the base DN is the value specified in Group search base, and the condition is that the group has the member attribute whose value is the DN of the user.
	3. The cn attribute of the group entry is used as the group name. If Prefix of Group Name is specified, it will be added.

TODO
----

* Write tests.
* [Releasing a Plugin and Hosting a Plugin on jenkins-ci.org] (https://wiki.jenkins-ci.org/display/JENKINS/Hosting+Plugins)

