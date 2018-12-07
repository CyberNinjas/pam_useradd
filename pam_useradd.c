/*
 * Copyright (c) CyberNinjas <info@cyberninjas.com>
 */

#define PLEASE_ENTER_PASSWORD "Password required for %s."
#define GUEST_LOGIN_PROMPT "Guest login ok, " \
"send your complete e-mail address as password."

/* the following is a password that can't be correct */
#define BLOCK_PASSWORD "\177BAD PASSWD\177"

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

/* argument parsing */

#define PAM_DEBUG_ARG       01

static int
_pam_parse(pam_handle_t *pamh, int argc, const char **argv, const char **users)
{
    int ctrl=0;

    /* step through arguments */
    for (ctrl=0; argc-- > 0; ++argv) {

	/* generic options */

	if (!strcmp(*argv,"debug"))
	    ctrl |= PAM_DEBUG_ARG;
	else if (!strncmp(*argv,"users=",6)) {
	    *users = 6 + *argv;
	} else {
	    pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
	}
    }

    return ctrl;
}

/*
 * check if name is in list or default list. place users name in *_user
 * return 1 if listed 0 if not.
 */

static int lookup(const char *name, const char *list, char **_user)
{
    int anon = 0;

    if (list && *list) {
	const char *l;
	char *list_copy, *x;
	char *sptr = NULL;

	list_copy = strdup(list);
	x = list_copy;
	while (list_copy && (l = strtok_r(x, ",", &sptr))) {
	    x = NULL;
	    if (!strcmp(name, l)) {
		*_user = list_copy;
		anon = 1;
		break;
	    }
	}
	if (*_user != list_copy) {
	    free(list_copy);
	}
    } else {
#define MAX_L 2
	static const char *l[MAX_L] = { "useradd", "anonymous" };
	int i;

	for (i=0; i<MAX_L; ++i) {
	    if (!strcmp(l[i], name)) {
		*_user = strdup(l[0]);
		anon = 1;
		break;
	    }
	}
    }

    return anon;
}

/* --- authentication management functions (only) --- */

int
pam_sm_authenticate (pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
    int retval, ctrl;
    const char *user;
    const char *users = NULL;

    /*
     * this module checks if the user name is useradd. If
     * this is the case, it can set the PAM_RUSER to the entered email
     * address and SUCCEEDS, otherwise it FAILS.
     */

    ctrl = _pam_parse(pamh, argc, argv, &users);

    retval = pam_get_user(pamh, &user, NULL);
    if (retval != PAM_SUCCESS || user == NULL) {
	pam_syslog(pamh, LOG_ERR, "no user specified");
	return PAM_USER_UNKNOWN;
    }

    /*
     * OK. we require an email address for user or the user's password.
     * - build conversation and get their input.
     */

    {
	char *resp = NULL;
	const char *token;

	retval = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &resp,
			     PLEASE_ENTER_PASSWORD, user);

	if (retval != PAM_SUCCESS) {
	    _pam_overwrite (resp);
	    _pam_drop (resp);
	    return ((retval == PAM_CONV_AGAIN)
		    ? PAM_INCOMPLETE:PAM_AUTHINFO_UNAVAIL);
	}

        /*
         * we have a password so set AUTHTOK
         */

        pam_set_item(pamh, PAM_AUTHTOK, resp);

        /*
         * this module failed, but the next one might succeed with
         * this password.
         */

        retval = PAM_AUTH_ERR;

	/* clean up */
	_pam_overwrite(resp);
	_pam_drop(resp);

	/* success or failure */

	return retval;
    }
}

int
pam_sm_setcred (pam_handle_t *pamh UNUSED, int flags UNUSED,
		int argc UNUSED, const char **argv UNUSED)
{
     return PAM_IGNORE;
}
