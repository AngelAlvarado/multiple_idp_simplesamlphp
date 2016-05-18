<?php
/**
 * Object to handle SAML features from within the Drupal context, this object does not pretend
 * to replace the simplesaml library, it just defines and centralizes the behavior of SAML
 * on this module.
 * The use of this object allows us to use multiple IDPs because the instance can be loaded
 * for every IDP needed on memory when executing the SSO authentication process, the object will
 * know what to do based on the ID of the IDP provided.
 * @package simplesamlphp_auth
 * @category Entity
 * @version 1.0
 */
class SimpleSAML_Drupal {
	/**
	 * Contains the reference to the SimpleSAML object
	 * @var object SimpleSAML_Auth_Simple
	 */
	private $_simplesaml_auth_simple = NULL;
	/**
	 * A collection of data with the attributes of the IDP, the difference
	 * between this and auth_source is that the attributes loaded here come
	 * directly from the assertion.
	 * @var stdClass
	 */
	private $_simplesaml_auth_attributes = NULL;
	/**
	 * Reference to the object that controls the SimpleSAML configurations
	 * @var object SimpleSAML_Configuration
	 */
    private $_simplesaml_auth_config = NULL;
	/**
	 * The version of the current SimpleSAML object been used
	 * @var int
	 */
	private $_simplesaml_auth_version = '';
	/**
	 * The IDP currently been used with the attributes declared on the Drupal
	 * Admin interface, we use this attributes to map them to the loaded attributes
	 * coming from the assertion.
	 * @var object stdClass
	 */
	private $_simplesaml_auth_source = NULL;

	/**
	 * Initializes the instance
	 */
	public function __construct() {
		$this->_autoload();
	}
	/**
	 * Pre-loads the object with the necessary data that will be used
	 * to execute all SAML related tasks
	 */
	private function _autoload() {
		 if ($this->_isEnabled() !== TRUE) {
			 throw new Exception("We're sorry but the simplesaml module is not yet enabled.");
  		 } // end if

		 /**
		  * Load the simplesaml Library from the specified path, if none is provided by default
		  * the system will use '/var/simplesamlphp'
		  */
  		 $basedir = variable_get('simplesamlphp_auth_installdir', '/var/simplesamlphp');
		 if (!file_exists($basedir . '/lib/_autoload.php')) {
			   throw new Exception("Unable to continue the SAML authentication process the provided path {$basedir} is wrong.");
  		 } // end if

		 require_once $basedir . '/lib/_autoload.php';
  		 $this->_simplesaml_auth_config = SimpleSAML_Configuration::getInstance();
  		 $this->_simplesaml_auth_version = $this->_simplesaml_auth_config->getVersion();
	}

	/**
	 * Determines if the simplesaml module / service is active on Drupal
	 * @param bool $watchdog - Flag that is used to decide if the fail message should go to the watchdog,
	 * default to TRUE
	 * @return bool TRUE if enabled otherwise FALSE
	 */
	private function _isEnabled($watchdog = TRUE) {
		$failure = NULL;
  		$isActivated = variable_get('simplesamlphp_auth_activate');
  		$basedir = variable_get('simplesamlphp_auth_installdir', '/var/simplesamlphp');
  		if ($isActivated) {
    		// Make sure we know where SimpleSAMLphp is.
    		if (!file_exists($basedir)) {
				if ($watchdog === TRUE) {
					watchdog('simplesamlphp_auth', 'SimpleSAMLphp could not be found at %basedir . The simplesamlphp_auth module
						cannot function until the path to the local SimpleSAMLphp instance is configured.',
						array('%basedir' => $basedir), WATCHDOG_WARNING);
				} // end if
				return FALSE;
    		} // end if
			return TRUE;
  		}
		else {
			if ($watchdog === TRUE) {
				watchdog('simplesamlphp_auth', 'SimpleSAMLphp is not active. The simplesamlphp_auth module
						cannot function until is activated, enabling the module is not enough.', NULL, WATCHDOG_WARNING);
			} // end if
			return FALSE;
		} // end if - else
		return FALSE;
	}

	/**
	 * Loads simpleSAMLphp IDP configuration and metadata, we retrieve the data from the
	 * parameter of the URL (e.g saml_login/%id) the hook menu gets the data and queries
	 * the DB to get the IDP information that's later turn into an object that we can
	 * easy manipulate. If no IDP value is given the method will load the default SP
	 * @see simplesamlphp_auth.module - ssaml_auth_load
	 * @param stdClass $idp - A standard class object with the data of the IDP to load
	 * @return object
	 * @throws Exception When there's not a valid source to use
	 */
	public function load($idp = NULL) {
		 if (NULL !== $idp && !empty($idp)) {
			 if (is_object($idp)) {
				$this->_simplesaml_auth_source = $idp;
			 }
			 else {
				 $data = db_query("SELECT * FROM {saml_idp_settings} WHERE id = :id", array(':id' => $idp))->fetchObject();
				 $this->_simplesaml_auth_source = $data;
			 } // end if - else
			 if (!empty($this->_simplesaml_auth_source)) {
				 /**
			  	  * Since the object will be lost once the user goes to the IDP, we need a way to remember it without
			  	  * overwriting the values because of multiple users, best case create a COOKIE to get this done, why?
			  	  * because is local and per user, besides it's temporary once the user is logged it'll die
			  	  */
			 	  setcookie('MyIDP', (string) $this->_simplesaml_auth_source->id, time() + (60 * 60));
			 	  $attributes = unserialize($this->_simplesaml_auth_source->attributes);
			 	  foreach ($attributes as $key => $data) {
					   if ($key == 'cs_fields') {
						   foreach ($data as $additional_data) {
							   $additional_data = explode(':', $additional_data);
							   $this->_simplesaml_auth_source->{$additional_data[0]} = $additional_data[1];
						   } // end foreach
      			 	   } // end if
				 	   $this->_simplesaml_auth_source->{$key} = $data;
    		 	  } // end foreach
			 	  $sp_name = $this->_simplesaml_auth_source->source_name;
			 }
			 else {
				 throw new Exception("Unable to continue with SSO process, there's no source available to proceed!");
			 } // end if - else
  		  }
		  elseif (isset($_COOKIE['MyIDP']) && (int) $_COOKIE['MyIDP'] > 0) {
				// Recursive call
				return $this->load($_COOKIE['MyIDP']);
  		  }
		  else {
			$sp_name = 'default-sp';
		  } // end if - elseif - else

  		  $this->_simplesaml_auth_simple = new SimpleSAML_Auth_Simple($sp_name);
  		  $this->_simplesaml_auth_attributes = $this->_simplesaml_auth_simple->getAttributes();
	}

	/**
	 * Retrieves the specified attribute from the current SAML Assertion
	 * most of the time this will be used to retrieve the mandatory attributes that
	 * allow us to create or log the users into the system, if no attribute name is provided
	 * the method will return all the attributes
	 * @param string $attr_name - The requested attribute name
	 * @return mixed - A string with the requested value OR all the attributes from the Assertion OR
	 * an empty string when there's no attributes for the current user.
	 * @throws Exception When the specified attribute doesn't exists for the user
	 */
	public function getAttrsFromAssertion($attr_name = '') {
		if (empty($this->_simplesaml_auth_attributes)) {
			return '';
		} // end if
		$attribute_assertion = '';
		// Check if valid local session exists ..
		if ($this->_simplesaml_auth_simple->isAuthenticated()) {
			if (empty($attr_name)) {
				return $this->_simplesaml_auth_attributes;
			} // end if
			if (isset($this->_simplesaml_auth_attributes[$attr_name])) {
				$attribute_assertion = $this->_simplesaml_auth_attributes[$attr_name][0];
			}
			else {
				throw new Exception("Error in simplesamlphp_auth.module: The requested attribute {$attr_name} doesn't exists in the assertion");
			} // end if - else
		} // end if
		return $attribute_assertion;
	}

	/**
	 * Retrieves the attributes declared on the Drupal site for the corresponding IDP
	 * @return stdClass With the properties loaded if the object exists ELSE void
	 */
	public function getAuthSourceAttributes() {
		if (NULL !== $this->_simplesaml_auth_source) {
			return $this->_simplesaml_auth_source;
		} // end if
		return;
	}

	/**
	 * Retrieves the SimpleSAML_Auth_Simple instance from the current object
	 * this way we can use the object from outside without wrapping the simple SAML methods
	 * from inside this object.
	 * @return SimpleSAML_Auth_Simple object if exists ELSE void
	 */
	public function getSimpleSAMLAuthSimple() {
		if (NULL !== $this->_simplesaml_auth_simple) {
			return $this->_simplesaml_auth_simple;
		} // end if
		return;
	}

	/**
	 * Retrieves the version of the library currently used
	 * @return string Indicating the version used at the moment, IF empty void is returned
	 */
	public function getSimpleSAMLVersion() {
		if (!empty($this->_simplesaml_auth_version)) {
			return $this->_simplesaml_auth_version;
		} // end if
		return;
	}

	/**
	 * Validates that everything that needs to be loaded is, before making any SAML requests
	 * @param bool $watchdog - Keep track of function validation on watchdog, defaults to TRUE
	 * @return bool TRUE if everything is loaded correctly, FALSE otherwise
	 */
	public function doSanitizeChecking($watchdog = TRUE) {
		$config_store_type = $this->_simplesaml_auth_config->getValue('store.type');
		// Make sure phpsession is NOT being used.
  		if ($config_store_type == 'phpsession') {
			  if ($watchdog === TRUE) {
				  watchdog('simplesamlphp_auth', 'A user attempted to login using simplesamlphp but the store.type is phpsession,
					use memcache or sql for simplesamlphp session storage. See: simplesamlphp/config/config.php.', NULL, WATCHDOG_WARNING);
			  } // end if
			  return FALSE;
  		} // end if

  		// Make sure there is an instance of SimpleSAML_Auth_Simple.
  		if (NULL === $this->_simplesaml_auth_simple) {
			  if ($watchdog === TRUE) {
				  watchdog('simplesamlphp_auth', 'A user attempted to login using this module but there was a problem.',
					  NULL, WATCHDOG_WARNING);
			  } // end if
			  return FALSE;
  		} // end if
		return TRUE;
	}

	/**
	 * Implements a variation of the factory method pattern that allow us to create
	 * single instances of an object without having the disadvantages of the Singleton
	 * pattern, it also help us to make sure we keep the values of the current IDP during the
	 * script execution, this is an alternative to using global variables on the
	 * simplesamlphp module.
	 * @link https://en.wikipedia.org/wiki/Factory_method_pattern
	 * @link http://ttmm.io/tech/singleton-alternative/
	 * @return SimpleSAML_Drupal object
	 */
	public static function factory() {
		static $instance = NULL;
		if (NULL === $instance) {
			$instance = new self;
		} // end if
		return $instance;
	}
}
