<?php

/**
 * @file
 * Hooks for simpleSAMLphp Authentication module.
 */

/**
 * Allows the use of custom logic to alter the roles assigned to a user.
 *
 * Whenever a user's roles are evaluated this hook will be called, allowing
 * custom logic to be used to alter or even completely replace the roles
 * evaluated.
 *
 * @param array &$roles
 *   The roles that have been selected for the current user
 *   by the role evaluation process, in the format array($rid => $rid)
 */
function hook_simplesamlphp_auth_user_roles_alter(&$roles) {
    watchdog('simplesamlphp_auth', "Altering user roles");

    // Get an instance of SimpleSAML_Drupal
    try {

        $simplesamlphp_drupal = SimpleSAML_Drupal::factory();
        $simplesamlphp_auth_as = $simplesamlphp_drupal->getSimpleSAMLAuthSimple();

        // Get SAML attributes
        $attrs = $simplesamlphp_auth_as->getAttributes();
        $simplesamlphp_authsource = $simplesamlphp_drupal->getAuthSourceAttributes();

        $syncroles = $simplesamlphp_authsource->syncroles;


        if ($syncroles) {
            // The roles provided by the IdP.
            $roleMapping = $simplesamlphp_authsource->roleattr;

            if (!empty($roleMapping) && isset($attrs[$roleMapping]) && !empty($attrs[$roleMapping])) {
                $adminsRole = explode(',', $simplesamlphp_authsource->rolemappattr);
                $administrator = user_role_load_by_name('administrator');
                $adminWeight = $administrator->rid;
                // Match role names in the saml attributes to local role names.
                $roleWeight = 0;
                foreach ($attrs[$roleMapping] as $samlRole) {
                    $samlRole = trim($samlRole);
                    if (empty($samlRole)) {
                        break;
                    } else if (in_array($samlRole, $adminsRole)) {
                        if ($roleWeight < $adminWeight) {
                            $roleWeight = $adminWeight;
                        }
                        break;
                    } else {
                        if ($loadedRole = user_role_load_by_name($samlRole)) {
                            $roles[$loadedRole->rid] = $loadedRole->name;
                        }
                    }
                }
                switch ($roleWeight) {
                    // case 5:
                    //   $roles = array(5 => 'customrole');
                    //   break;
                    case $adminWeight:
                        $roles[$adminWeight] = 'administrator';
                        break;
                    case DRUPAL_AUTHENTICATED_RID: // default value => 2
                    default:
                        $roles[DRUPAL_AUTHENTICATED_RID] = 'authenticated user';
                        break;
                }
            }
        } else {
            $roles[DRUPAL_AUTHENTICATED_RID] = 'authenticated user';
        }
    } catch (Exception $e) {
        watchdog_exception('simplesamlphp_auth', $e);
    } // end try - catch  
    /*
     * global $_simplesamlphp_auth_saml_attributes; 
      if (isset($_simplesamlphp_auth_saml_attributes['roles'])) {
      // The roles provided by the IdP.
      $sso_roles = $_simplesamlphp_auth_saml_attributes['roles'];

      // Match role names in the saml attributes to local role names.
      $user_roles = array_intersect(user_roles(), $sso_roles);

      foreach (array_keys($user_roles) as $rid) {
      $roles[$rid] = $rid;
      }
      } */
}
