<?php

namespace MediaWiki\Extension\Cas;

use GlobalVarConfig;

class Config extends GlobalVarConfig {
	const VERSION = "1.0.2";

	public function __construct() {
		parent::__construct( 'Cas' );
	}

	/**
	 * Factory method for MediaWikiServices
	 * @return Config
	 */
	public static function newInstance() {
		return new self();
	}

	/**
	 * Convenience function to show the tests we can actually load.
	 *
	 * @return string
	 */
	public static function getVersion() {
		return self::VERSION;
	}
}
