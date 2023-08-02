<?php

namespace MediaWiki\Extension\Cas;

use Exception;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\PluggableAuth\PluggableAuth;
use MediaWiki\MediaWikiServices;
use MWException;
use MediaWiki\User\UserIdentity;
use PluggableAuthLogin;
use User;

class Cas extends PluggableAuth {

	/**
         * AuthManager instance to manage authentication session data
         *
         * @var AuthManager
         */
        private $authManager;

        /** @var MediaWikiServices */
        protected $services = null;

        public function __construct() {
                $this->services = MediaWikiServices::getInstance();
        }

    /**
     * Authenticates against CAS
     * @param int &$id not used
     * @param string &$username set to username
     * @param string &$realname set to real name
     * @param string &$email set to email
     * @param string &$errorMessage any errors
     * @return boolean false on failure
     * @SuppressWarnings( UnusedFormalParameter )
     * @SuppressWarnings( ShortVariable )
     */
    public function authenticate(?int &$id, ?string &$username, ?string &$realname, ?string &$email, ?string &$errorMessage): bool {
	// required for \phpCAS::client call
	\phpCAS::setLogger();
	\phpCAS::setVerbose(false);

	// server
        if (empty($GLOBALS['wgCas_Server'])) {
            throw new Exception(wfMessage('cas-wg-empty-server')->plain());
	}

	// port
	if (empty($GLOBALS['wgCas_Port'])) {
            throw new Exception(wfMessage('cas-wg-empty-port')->plain());
        }

	// path
	if (!isset($GLOBALS['wgCas_Path'])) {
            throw new Exception(wfMessage('cas-wg-empty-path')->plain());
        }

	// service url
	if (empty($GLOBALS['wgCas_ServiceUrl'])) {
            throw new Exception(wfMessage('cas-wg-empty-service-url')->plain());
        }

	// cacert
        if (empty($GLOBALS['wgCas_CACert'])) {
            throw new Exception(wfMessage('cas-wg-empty-ca-cert')->plain());
	}

	// ca
        if (empty($GLOBALS['wgCas_CA'])) {
            throw new Exception(wfMessage('cas-wg-empty-ca')->plain());
        }

	// logoutrequest
	if (empty($GLOBALS['wgCas_LogoutRequest'])) {
            throw new Exception(wfMessage('cas-wg-empty-logout-request')->plain());
        }

	// call
        \phpCAS::client(CAS_VERSION_2_0, $GLOBALS['wgCas_Server'], $GLOBALS['wgCas_Port'], is_null($GLOBALS['wgCas_Path']) ? '' : $GLOBALS['wgCas_Path'], $GLOBALS['wgCas_ServiceUrl'], false);

        if(is_bool($GLOBALS['wgCas_CACert']) && $GLOBALS['wgCas_CACert'] == false) {
            \phpCAS::setNoCasServerValidation();
        } else {
            \phpCAS::setCasServerCACert($GLOBALS['wgCas_CA']);
        }

        if($GLOBALS['wgCas_LogoutRequest']) {
            //\phpCAS::handleLogoutRequests(true);
        } else {
            //\phpCAS::handleLogoutRequests(false);
        }	

	\phpCAS::forceAuthentication();

        //$id = null;
	$attributes = \phpCAS::getAttributes();
	//echo "attributes<br />\n";
	//var_dump($attributes);
	
	//username
	$username = \phpCAS::getUser();
	//echo "username<br />\n";
	//var_dump($username);

	// displayname
	if (empty($GLOBALS['wgCas_DisplayName'])) {
            throw new Exception(wfMessage('cas-wg-empty-displayname')->plain());
        } else {
            $realname = $attributes[$GLOBALS['wgCas_DisplayName']];
        }	

	//email
        if (empty($GLOBALS['wgCas_Email'])) {
            throw new Exception(wfMessage('cas-wg-empty-email')->plain());
        } else {
            $email = $attributes[$GLOBALS['wgCas_Email']];
        }
	//echo "mail<br />\n";
	//var_dump($mail);

	$username = (!is_numeric($username) ? strtolower($username) : $username);
	//echo "username<br />\n";
	//var_dump($username);
        
	//echo "user<br />\n";
	//var_dump($user);

	//echo "id<br />\n";
	//var_dump($id);
	
	if (empty($GLOBALS['wgCas_GroupMap'])) {
            throw new Exception(wfMessage('cas-wg-empty-groupmap')->plain());
        }
	
        if ( (isset($GLOBALS['wgCas_GroupMap'])) && ($GLOBALS['wgCas_GroupMap'] != null) ) {
	    $user = $this->services->getUserFactory()->newFromName( $username );
	    $this->populateGroups($user, $attributes);
        }


        return true;
    }


    /**
     * Logout
     *
     * @param User $user
     * @return boolean
     */
    public function deauthenticate( UserIdentity &$user ): void {
        // Nothing to do, really
        $user = null;
        
    }

    public function saveExtraAttributes(int $id): void {

    }

    /**
     *
     * @param User $user
     */
    public static function populateGroups(User $user, $attributes) {
        if ( method_exists( MediaWikiServices::class, 'getAuthManager' ) ) {
            // MediaWiki 1.35+
            $authManager = MediaWikiServices::getInstance()->getAuthManager();
        } else {
            $authManager = AuthManager::singleton();
        }
	$attr_name = $GLOBALS['wgCas_GroupMap']['attr_name'];

        if (empty($attr_name)) {
            throw new Exception(wfMessage('cas-wg-empty-groupmap-attr')->plain());
        }

        $groups = $attributes[$attr_name];

        if (empty($groups)) {
            throw new Exception(wfMessage('cas-attr-empty-groupmap-attr')->plain());
        }

        if (!empty($groups)) {

            // Check 'sysop' in LocalSettings.php
            $sysop = $GLOBALS['wgCas_GroupMap']['sysop'];

            if (in_array($sysop, $groups)) {
                if (method_exists(MediaWikiServices::class, 'getUserGroupManager')) {
                    // MW 1.35+
                    MediaWikiServices::getInstance()->getUserGroupManager()->addUserToGroup($user, 'sysop');
                } else {
                    $user->addGroup('sysop');
                }
            } else {
                if (method_exists(MediaWikiServices::class, 'getUserGroupManager')) {
                    // MW 1.35+
                    MediaWikiServices::getInstance()->getUserGroupManager()->removeUserFromGroup($user, 'sysop');
                } else {
                    $user->removeGroup('sysop');
                }
            }

	    // Check 'interface-admin' in LocalSettings.php
            $interfaceadmin = $GLOBALS['wgCas_GroupMap']['interface-admin'];

            if (in_array($interfaceadmin, $groups)) {
                if (method_exists(MediaWikiServices::class, 'getUserGroupManager')) {
                    // MW 1.35+
                    MediaWikiServices::getInstance()->getUserGroupManager()->addUserToGroup($user, 'interface-admin');
                } else {
                    $user->addGroup('interface-admin');
                }
            } else {
                if (method_exists(MediaWikiServices::class, 'getUserGroupManager')) {
                    // MW 1.35+
                    MediaWikiServices::getInstance()->getUserGroupManager()->removeUserFromGroup($user, 'interface-admin');
                } else {
                    $user->removeGroup('interface-admin');
                }
            }

            // Check 'bureaucrat' in LocalSettings.php
            $bureaucrat = $GLOBALS['wgCas_GroupMap']['bureaucrat'];

            if (in_array($bureaucrat, $groups)) {
                if (method_exists(MediaWikiServices::class, 'getUserGroupManager')) {
                    // MW 1.35+
                    MediaWikiServices::getInstance()->getUserGroupManager()->addUserToGroup($user, 'bureaucrat');
                } else {
                    $user->addGroup('bureaucrat');
                }
            } else {
                if (method_exists(MediaWikiServices::class, 'getUserGroupManager')) {
                    // MW 1.35+
                    MediaWikiServices::getInstance()->getUserGroupManager()->removeUserFromGroup($user, 'bureaucrat');
                } else {
                    $user->removeGroup('bureaucrat');
                }
            }
        }
    }



        /**
         * Provide a getter for the AuthManager to abstract out version checking.
         *
         * @return AuthManager
         */
        protected function getAuthManager() {
                $authManager = $this->services->getAuthManager();
                return $authManager;
        }

}
