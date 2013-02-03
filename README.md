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
	* How to identify user DN.
		* Needed when you want to retrieve group information from LDAP.
		* Followings are supported
			* Use LDAP "who am i?" extended operation
			* Query LDAP specifying the base DN and the query string.
	* Whether retrieve group information from LDAP.
		* The user DN have to be indentified.
		* You must specify base DN, and prefix added to the group name.
		* For example, "group1" group in LDAP directory will be treated as "ROLE_group1" in Jenkins by specifying "ROLE_" as the prefix.

Limitations
-----------

* LDAPS is not tested.

