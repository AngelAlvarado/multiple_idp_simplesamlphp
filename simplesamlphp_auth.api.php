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
    global $_simplesamlphp_auth_saml_attributes;
    if (isset($_simplesamlphp_auth_saml_attributes['roles'])) {
        // The roles provided by the IdP.
        $sso_roles = $_simplesamlphp_auth_saml_attributes['roles'];

        // Match role names in the saml attributes to local role names.
        $user_roles = array_intersect(user_roles(), $sso_roles);

        foreach (array_keys($user_roles) as $rid) {
            $roles[$rid] = $rid;
        }
    }
}
