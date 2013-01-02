LDAP SASL plugin
================

LDAPサーバとSASL認証を行うJenkinsプラグイン

これはなに？
------------

LDAP SASL は、「LDAP-SASL」ユーザー情報を追加する [Jenkins](http://jenkins-ci.org/) プラグインです: 

* Simple Authentication and Security Layer (SASL) 機構を使用して、LDAPサーバと認証を行います。
* 以下のパラメータを設定できます。
	* LDAP URI
		* LDAPサーバに接続するためのURI。
		* 複数のURIを指定できます。
	* SASL Mechanisms
		* 認証で使用するSASL機構。
		* 複数の機構を指定できます。実際にどの機構が使用されるかはLDAPサーバとのネゴシエーションで決定されます。
	* Group search base
		* LDAPディレクトリ内でグループ情報が配置されている場所のルートDN。
		* JenkinsでLDAPサーバのグループ情報を使用する場合は、 この値の指定が必要です。
	* グループ名のプリフィクス
		* Jenkinsで使用するグループ名の先頭に付加する文字列を指定します。例えばLDAPディレクトリ内での「group1」というグループ名は、Jenkins内では「ROLE_group1」などとして使用されます。

制限事項
--------

* LDAPサーバからグループ情報を取得するためには、以下の条件を満たす必要があります。
	* LDAPサーバが LDAP "who am i?" 拡張機能をサポートしている
	* LDAPサーバが "who am i?" リクエストに対して DN (cn=MyName,ou=People,dc=example,dc=com のような値) を返すこと。
		* ユーザ名 (MyName@example.com) を返す場合、グループ情報は取得できません。
	* Group search base を設定していること。

このプラグインの動作原理
------------------------

* このプラグインはLDAPサーバとの接続にJNDIを使用しています。
* 認証したユーザのグループ情報の取得は以下のように行なっています:
	1. LDAP "who am i?" 拡張機能を使用し、認証したユーザのDNを取得する。
	2. LDAP ディレクトリ内でグループを検索します。 member属性に認証したユーザのDNが設定されているエントリが対象になります。
	3. 取得したエントリのCN属性の値をグループ名として使用します。グループ名のプリフィクスが指定されている場合、ここで付加します。

TODO
----

* テストを書く
* [jenkins-ci.orgでプラグインを公開する] (https://wiki.jenkins-ci.org/display/JENKINS/Hosting+Plugins)

