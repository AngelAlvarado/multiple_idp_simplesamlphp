<?php
/**
 * @file
 * Contains non-hook implementations.
 * This module belongs to Andreas Åkre Solberg, Snorre Løvås and Steve Moitozo (Maintenance)
 * the adjustments we're doing is to allow multiple IDPs and SPs on the same website with custom
 * logic from TA
 * @version 7.x.3.5
 * @author Pablo Tapia <pablo.orozco@ingenia.com>
 * @author Angel Alvarado <angel.angelio.ingenia@gmail.com>
 */

/**
 * We load the custom Simple SAML Auth object to store all the IDP information
 */
module_load_include('inc', 'simplesamlphp_auth', 'includes/simplesamlphp_auth.drupal');

/**
 * Performs login and/or register actions for SAML authenticated users.
 */
function _simplesaml_auth_login_register() {
  global $user;
  try {
    $simplesamlphp_drupal = SimpleSAML_Drupal::factory();
    $simplesamlphp_auth_as = $simplesamlphp_drupal->getSimpleSAMLAuthSimple();
  } catch(Exception $e) {
    watchdog_exception('simplesamlphp_auth', $e);
  } // end try - catch

  /**
   * Check if user is logged in SimpleSAMLphp (but not Drupal), if it is
   * then start loading the SAML attributes
   */
  if ($simplesamlphp_auth_as->isAuthenticated()) {
    $unique_attr = !empty($simplesamlphp_drupal->getAuthSourceAttributes()) ? $simplesamlphp_drupal->getAuthSourceAttributes()->unique_id : 'mail';
    $authname = $simplesamlphp_drupal->getAttrsFromAssertion($unique_attr);
    _simplesaml_auth_debug(t('Authname is [%authname] userid is [%uid]', array('%authname' => $authname,'%uid' => $user->uid,)));

    if (!empty($authname)) {
      /**
       * User is logged in with SAML authentication and we got the unique
       * identifier, so try to log into Drupal.
       */
      _simplesaml_auth_debug(t('Loading Drupal user [%authname]', array('%authname' => $authname)));
      // Retrieve user mapping and attempt to log the user in.
      $ext_user = user_external_load($authname);

      // If we did not find a Drupal user, register a new one.
      if (!$ext_user) {
        $ext_user = _simplesaml_auth_user_register($authname);
      } // end if
      _simplesaml_auth_user_login($ext_user);
    } // end if
  } // end if
}
/**
 * Creates a new Drupal account for a SAML authenticated user.
 *
 * @param string $authname
 *   Gets the authname attribute from the SAML assertion as provided by
 *   SimpleSAML_Drupal getAttrsFromAssertion()
 *
 * @return object
 *   The newly create Drupal user object.
 */
function _simplesaml_auth_user_register($authname) {
  global $user;
  try {
    $simplesamlphp_drupal = SimpleSAML_Drupal::factory();
    $simplesamlphp_auth_as = $simplesamlphp_drupal->getSimpleSAMLAuthSimple();
    $simplesamlphp_authsource = $simplesamlphp_drupal->getAuthSourceAttributes();
  } catch(Exception $e) {
    watchdog_exception('simplesamlphp_auth', $e);
  } // end try - catch

  // First we check the admin settings for simpleSAMLphp and find out if we are allowed to register users.
  if (variable_get('simplesamlphp_auth_registerusers', TRUE)) {
    // We are allowed to register new users.
    _simplesaml_auth_debug(t('Register [%authname]', array('%authname' => $authname)));
    /**
     * It's possible that a user with this name already exists, but is not
     * permitted to login to Drupal via SAML. If so, log out of SAML and
     * redirect to the front page.
     */
    $account = user_load_by_name($authname);
    if ($account) {
      _simplesaml_auth_debug(t('User [%authname] could not be registered because that username already exists and is not SAML enabled.',
        array('%authname' => $authname)));
      drupal_set_message(t('We are sorry, your user account is not SAML enabled.'));
      $simplesamlphp_auth_as->logout(base_path());
      return FALSE;
    } // end if

    /**
     * We look for the customer ID attribute inside the SAML implementation .. if there's none then we can't
     * create the user
     */
    if(NULL !== $simplesamlphp_authsource && isset($simplesamlphp_authsource->user_customer_id)) {
      // Register the new user.
      user_external_login_register($authname, 'simplesamlphp_auth');
      _simplesaml_auth_debug(t('Registered [%authname] with uid @uid', array('%authname' => $authname, '@uid' => $user->uid)));

      if (!empty($user->uid)) {
        /**
         * Populate roles and additional fields based on configuration settings.
         * We don't need to retrieve data from SAML configurations the only role for these users on this part
         * of the process is subscribers
         */
        $userinfo = array(
          'name' => $simplesamlphp_drupal->getAttrsFromAssertion($simplesamlphp_authsource->username),
          'mail' => $simplesamlphp_drupal->getAttrsFromAssertion($simplesamlphp_authsource->mailattr),
          'timezone' => 'America/New_York'
        );
        
        /**
         * If you want, you can place more custom fields and populate them here
         * @example
         * if (isset($simplesamlphp_authsource->firstname)) {
         *   $userinfo['field_first_name'] = array(
         *     'und' => array(array('value' => $simplesamlphp_drupal->getAttrsFromAssertion($simplesamlphp_authsource->firstname)))
         *   );
         * } // end if
         */
       
        $user = user_save($user, $userinfo);
        return $user;
      } else {
        /**
         * We were unable to register this new user on the site.
         * We let the user know about this, log an error, and redirect to the home page.
         */
        drupal_set_message(t( "We are sorry. While you have successfully authenticated, we were unable to create an account for you on this site. Please ask the site administrator to provision access for you."));
        watchdog('simplesamlphp_auth', 'Unable to register %authname using simplesamlphp_auth', array('%authname' => $authname), WATCHDOG_ERROR);
        $simplesamlphp_auth_as->logout(base_path());
      } // end if- else
    } // end if
     /**
      * If we don't have a customer ID attribute then we don't know the products the user can see so we can't
      * create the account
      */
     drupal_set_message(t("We are sorry. There's not enough data in the system to create an account and grant access to the system. Please ask the site administrator to check the attributes assigned to the access."));
     watchdog('simplesamlphp_auth', 'Unable to register %authname using simplesamlphp_auth no customer id attribute was provided', array('%authname' => $authname), WATCHDOG_ERROR);
     $simplesamlphp_auth_as->logout(base_path());
  } else {
    /**
     * We are not allowed to register new users on the site through simpleSAML.
     * We let the user know about this and redirect to the user/login page.
     */
    drupal_set_message(t("We are sorry. While you have successfully authenticated, you are not yet entitled to access this site. Please ask the site administrator to provision access for you."));
    $simplesamlphp_auth_as->logout(base_path());
  } // end if - else
}
/**
 * Updates a SAML authenticated user's account with current username and email.
 *
 * @param object $account
 *   The user account object to update.
 */
function _simplesaml_auth_user_update($account) {
  _simplesaml_auth_debug(t('Updating username [%acctname]', array( '%acctname' => $account->name)));
  try {
    $simplesamlphp_drupal = SimpleSAML_Drupal::factory();
    $simplesamlphp_authsource = $simplesamlphp_drupal->getAuthSourceAttributes();
  } catch(Exception $e) {
    watchdog_exception('simplesamlphp_auth', $e);
  } // end try - catch

  db_update('users')
    ->fields(array('name' => $account->name))
    ->condition('uid', $account->uid)
    ->execute();

  // Get mail from default attribute.
  try {
    $mail_address = $simplesamlphp_drupal->getAttrsFromAssertion($simplesamlphp_authsource->mailattr);
  } catch (Exception $e) {
    drupal_set_message(t('Your e-mail address was not provided by your identity provider (IDP).'), "error" );
    watchdog_exception('simplesamlphp_auth', $e);
  } // end try - catch

  _simplesaml_auth_debug(t('Updating mail [%mailaddr]', array('%mailaddr' => $mail_address)));

  if (!empty($mail_address)) {
    db_update('users')
      ->fields(array('mail' => $mail_address))
      ->condition('uid', $account->uid)
      ->execute();
  } // end if
}
/**
 * Logs a SAML-authenticated user into Drupal.
 *
 * @param object $ext_user
 *   The Drupal user object to be logged in.
 * @return IF success void ELSE boolean FALSE
 */
function _simplesaml_auth_user_login($ext_user) {
  // Making sure we use the loaded user as the current user
  global $user;
  $user = $ext_user;
  try {
    $simplesamlphp_auth_as = SimpleSAML_Drupal::factory()->getSimpleSAMLAuthSimple();
  } catch(Exception $e) {
    watchdog_exception('simplesamlphp_auth', $e);
  } // end try - catch

  /**
   * Since the whole purpose of the COOKIE is to log the user once it's done
   * we don't need it anymore
   */
  setcookie('MyIDP', '');
  
  /**
   * You can execute additional logic to validate users HERE.
   */
   
  // Finalizing the login, calls hook_user op login.
  $edit = array();
  user_login_finalize($edit);
  return;
}
/**
 * Denies non-SAML-authenticated access to the site for configured Drupal roles.
 */
function simplesaml_auth_moderate_local_login() {
  global $user;
  $simplesamlphp_auth_as = SimpleSAML_Drupal::factory()->getSimpleSAMLAuthSimple();

  // If we forbid users from logging in using local accounts.
  if (!variable_get('simplesamlphp_auth_allowdefaultlogin', TRUE)) {
    // If the user has NOT been authenticated via simpleSAML...
    if (!$simplesamlphp_auth_as->isAuthenticated()) {
      // :FYI: Until Drupal issue #754560 is corrected this message will never be seen by the user.
      drupal_set_message( t( "We are sorry, users are not permitted to log in using local accounts." ) );
      // Destroy the user's session (log them out).
      _simplesamlphp_auth_destroy_drupal_session();
    } // end if
  } else {
    // If we are allowing users to log in with local accounts.
    // If the user has NOT been authenticated via simpleSAML.
    if (!$simplesamlphp_auth_as->isAuthenticated()) {
      // See if we limit this privilege to specified users
      $strAllwDefLogUsers = variable_get('simplesamlphp_auth_allowdefaultloginusers', '');
      $arrAllwDefLogUsers = array();
      // See if we limit this privilege to specified roles.
      $arrAllwDefLogRoles = variable_get('simplesamlphp_auth_allowdefaultloginroles', FALSE);
      // If user IDs or roles are specified, we let them in, but everyone else gets logged out.
      if (drupal_strlen( $strAllwDefLogUsers ) || $arrAllwDefLogRoles) {
        // Convert the string into an array.
        // @todo Perform a test to make sure that only numbers, spaces, or commas are in the string.
        $arrAllwDefLogUsers = explode(',', $strAllwDefLogUsers);
        // If we still have something to work with.
        if (0 < count($arrAllwDefLogUsers ) || 0 < count($arrAllwDefLogRoles)) {
          /**
           * Log the user out of Drupal if:
           * 1) the current user's uid is NOT in the list of allowed uids...
           * 2) or their role does not match and allowed mixed mode role.
           */
          $matchRoles = array_intersect(array_keys($user->roles), $arrAllwDefLogRoles);
          if (!in_array($user->uid, $arrAllwDefLogUsers) && count($matchRoles) == 0) {
            // User is logged into Drupal, but may not be logged into simpleSAML.
            // If this is the case we're supposed to log the user out of Drupal.
            // :FYI: Until Drupal issue #754560 is corrected this message will never be seen by the user.
            drupal_set_message(t("We are sorry, you are not permitted to log in using a local account."));
            // The least we can do is write something to the watchdog so someone will know what's happening.
            watchdog('simplesamlphp_auth', 'User %name not authorized to log in using local account.', array('%name' => $user->name));
            _simplesamlphp_auth_destroy_drupal_session();
          } // end if
        } // end if
      } // end if
    } // end if
  } // end if - else
}
