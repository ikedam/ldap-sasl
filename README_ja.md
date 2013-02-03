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
	* ユーザのDNの取得方法
		* LDAPからユーザが所属するグループの情報を取得する場合は必須です。
		* 以下の方法から選択できます。
			* LDAP "who am i?" 拡張操作を使用する
			* ベースDNとクエリを指定してLDAPに問い合わせる
	* グループの情報を取得するか否か
		* ユーザのDN取得の設定がされている必要があります。
		* ベースDN、グループ名に付加するプリフィクスを指定します。
		* 例えばプリフィクスとして「ROLE_」を指定すると、LDAPディレクトリ内での「group1」というグループ名は、Jenkins内では「ROLE_group1」などとして使用されます。

制限事項
--------

* LDAPSの使用はテストされていません。
