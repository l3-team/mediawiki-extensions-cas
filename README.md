# MediaWiki CAS extension

The **CAS** extension extends the [PluggableAuth](https://www.mediawiki.org/wiki/Extension:PluggableAuth) extension to provide authentication using [Apereo CAS phpCAS](https://github.com/apereo/phpCAS).

Recommended MediaWiki version: **1.35+**

## Required

- Mediawiki 1.3.5 or possibly earlier
- PluggableAuth 7.0.0 or possibly earlier

## Installation

> This extension requires the [PluggableAuth](https://www.mediawiki.org/wiki/Extension:PluggableAuth) extension to be installed first.

* Download and place the file(s) in a directory called Cas in your extensions/ folder.
* Launch this command in the directory to install composer packages (dependencies of Cas package like apereo/phpcas) from composer.json and composer.lock :
```
composer install
```
* Add the following code at the bottom of your LocalSettings.php and configures settings:

```php
$wgGroupPermissions['*']['createaccount'] = true;
$wgPluggableAuth_EnableAutoLogin = false;
$wgPluggableAuth_EnableLocalLogin = true;
$wgPluggableAuth_EnableLocalProperties = false;

# settings to set
$wgCas_Server="cas.host.com";
$wgCas_Port=443;
$wgCas_Path="/cas";
$wgCas_ServiceUrl="https://mediawikis.host.com";
$wgCas_CACert=false;
$wgCas_CA=null;
$wgCas_LogoutRequest=true;
$wgCas_DisplayName="displayName";
$wgCas_Email="mail";
$wgCas_GroupMap=null;
//$wgCas_GroupMap=array('attr_name' => 'memberOf','sysop' => 'cn=code_groupe_sysop,ou=groups,dc=univ,dc=fr','interface-admin' => 'cn=code_groupe_interface_admin,ou=groups,dc=univ,dc=fr','bureaucrat' => 'cn=code_groupe_bureaucrat,ou=groups,dc=univ,dc=fr');

$wgPluggableAuth_ButtonLabel = 'Se connecter avec CAS';
$wgPluggableAuth_Config['Se connecter avec CAS'] = [
  'plugin' => 'Cas',
  'data' => []
];

# mediawiki 1.3.5
wfLoadExtension( 'PluggableAuth' ); # version 7.0.0
wfLoadExtension( 'Cas' ); # plugin Cas
```

* Configure as required
* Done! Navigate to Special:Version on your wiki to verify that the extension is successfully installed.

## Configure

Values must be provided for the following mandatory configuration variables:

Flag | Default | Description
---- | ------- | -----------
$wgCas_Server | cas.host.com | The host of the Cas server.
$wgCas_Port | 443 | The port of the Cas server.
$wgCas_Path | "" | The path of the Cas server.
$wgCas_ServiceUrl | http://127.0.0.1 | The service url.
$wgCas_CACert | false | The bool if cert
$wgCas_CA | null | The cert
$wgCas_Username | no default value | The main attribute returned by Cas server.
$wgCas_Email | no default value | The name of the attribute to be used for the user's email address.
$wgCas_DisplayName | no default value | The name of the attribute(s) to be used for the user's real name.

In addition, the following optional configuration variable is provided:

Flag | Default | Description
---- | ------- | -----------
$wgCas_GroupMap | null | Mapping  attributes to MediaWiki groups of the form: `$wgCas_GroupMap = array('attr_name' => 'memberOf','sysop' => 'cn=code_group,ou=groups,dc=univ,dc=fr','interface-admin'=>'cn=code_groupe,ou=groups,dc=univ,dc=fr','bureaucrat' => 'cn=code_groupe,ou=groups,dc=univ,dc=fr', '...');` No group mapping is performed if $wgCas_GroupMap is null.

- group sysop is the group of wiki admins
- group interface-admin is the of wiki interface admins
- group bureaucrat is the group of wiki privileged users

### Group mapping

Use case: your CAS reads groups from LDAP or Database and stores this information inside an attribute of the response. You want to use this to map MediaWiki groups to users belonging to some known groups given by your CAS.

Example:

* Your CAS sends an attribute named "memberOf" with a list of groups like ["cn=admins,ou=groups,dc=univ,dc=fr", "..."] in the response after authentication.
* All users that have the value "cn=admins,ou=groups,dc=univ,dc=fr" in the "memberOf" attribute shall be mapped to the MediaWiki "sysop" group to give them admin rights within your MediaWiki instance.
* Create a group map in your LocalSettings.php as follows: $wgCas_GroupMap = array('attr_name' => 'groups','sysop' => 'administrator',);

You can come up with rather complex mappings that fit your needs. If you have more than one attribute from SAML, just add it to the array with the array of values you like to map.

**HINT**: If a user belongs to a MediaWiki group that is no longer mapped to that user (for example, by losing the group membership in user data source), the user will be removed from that MediaWiki group at next log in. In that way you can mass remove groups and their memberships, too - just scramble the mapping values so they don't match the response, but don't mess up the MediaWiki group name.

### Single Logout (SLO)

coming soon


### Troubleshooting 

## Enable debug PHP

If you want enable debug PHP, add the following code at the top of your LocalSettings.php :
```php
error_reporting( -1 );
ini_set( 'display_errors', 1 );
```

## Disable the cache of mediawiki

If you want disable the cache of your mediawiki, add the following code at the bottom of your LocalSettings.php :
```php
$wgMainCacheType = CACHE_NONE;
$wgCacheDirectory = false;
```

## Enable debug of mediawiki

If you want enable debug of your mediawiki, add the following code at the bottom of your LocalSettings.php :
```php
$wgDebugLogFile = "/tmp/debug-{$wgDBname}.log";
```

## Disable the sessions from memcache (if enabled)

If you want disable the sessions from memcache (if enabled), add the following code at the bottom of your LocalSetting
s.php :
```php
$wgSessionsInMemcached = false;
```

