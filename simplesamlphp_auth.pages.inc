<?php
/**
 * @file
 * Non administrative page callbacks for SimpleSamlPHP Auth module.
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
 * Represents the Drupal page (saml_login), which triggers user authentication against
 * the SimpleSAMLphp service provider.
 * @see ssaml_auth_load
 */
function simplesamlphp_auth_loginpage($sp = NULL) {
  try {
    $simplesamlphp_drupal = SimpleSAML_Drupal::factory();
    $simplesamlphp_drupal->load($sp);
  } catch(Exception $e) {
    watchdog_exception('simplesamlphp_auth', $e);
  } // end try - catch

  $idp_st = !empty($simplesamlphp_drupal->getAuthSourceAttributes()) ? $simplesamlphp_drupal->getAuthSourceAttributes()->id : $sp;

  global $user;
  global $base_url;

  module_load_include('inc', 'simplesamlphp_auth');
  // The user is not logged into Drupal.
  if ($user->uid == 0) {
    _simplesaml_auth_login_register();
  } else {
  // The user is already logged into Drupal.
    simplesaml_auth_moderate_local_login();
  } // end if - else

  $output = NULL;

  // There was a problem, we can't go on, but we don't want to tell the user any specifics either.
  if ($simplesamlphp_drupal->doSanitizeChecking() === FALSE) {
    drupal_set_message(t("We're sorry. There was a problem attempting login. The issue has been logged for the administrator."), 'error');
    drupal_goto('user/login');
  } // end if

  $return_to = NULL;

  /**
   * Support for deep linking.
   */

  // See if a URL has been explicitly provided in ReturnTo. If so, use it (as long as it points to this site).
  if (( isset($_REQUEST['ReturnTo'] ) && $_REQUEST['ReturnTo']) &&
    (valid_url( $_REQUEST['ReturnTo'] ) && stristr($_REQUEST['ReturnTo'], $base_url))) {
    $return_to = $_REQUEST['ReturnTo'];
    // If not, see if a REFERER URL is available. If so, use it (as long as it points to this site).
  } elseif ((isset($_SERVER['HTTP_REFERER']) && $_SERVER['HTTP_REFERER']) &&
    (valid_url($_SERVER['HTTP_REFERER'] ) && stristr($_SERVER['HTTP_REFERER'], $base_url))
  ) {
    $return_to = $_SERVER['HTTP_REFERER'];
  } // end if - elseif

  // If the user is anonymous, set the cookie (if we can) and require authentication.
  if ($user->uid == 0) {
    if ($return_to) {
      // Set the cookie so we can deliver the user to the place they started
      setrawcookie('simplesamlphp_auth_returnto', $return_to, time() + 60 * 60);
    } // end if

    // Require the user to be authenticated.
    setcookie('tytaa', (string) $idp_st , time() + (60 * 60 * 24 * 30), '/');
    $simplesamlphp_drupal->getSimpleSAMLAuthSimple()->requireAuth();
  } else {
    // If the user is authenticated, send them along.
    $go_to_url = NULL;
    setcookie('_lta', (string) $idp_st ,time() + (60 * 60 * 24 * 30), '/');
    // Check to see if we've set a cookie. If there is one, give it priority.
    if (isset( $_COOKIE['simplesamlphp_auth_returnto'] ) && $_COOKIE['simplesamlphp_auth_returnto']) {
      // use the cookie for the ReturnTo
      $go_to_url = $_COOKIE['simplesamlphp_auth_returnto'];
      // unset the cookie
      setrawcookie('simplesamlphp_auth_returnto', '');
    } elseif ($return_to) {
      $go_to_url = $return_to;
    } // end if - elseif

    // If a ReturnTo has been set.
    if($go_to_url) {
      $parsed_gotourl = drupal_parse_url($go_to_url);
      drupal_goto($parsed_gotourl['path'], $parsed_gotourl);
    } else {
      drupal_goto('user/' . $user->uid);
    } // end if - else
  } // end if - else

  return $output;
}
