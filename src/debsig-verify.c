/*
 * debsig-verify - Debian package signature verification tool
 *
 * Copyright © 2000 Ben Collins <bcollins@debian.org>
 * Copyright © 2014-2023 Guillem Jover <guillem@debian.org>
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * main routines
 */

#include <config.h>

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sha256.h>
#include <sha512.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <dpkg/dpkg.h>
#include <dpkg/error.h>
#include <dpkg/fdio.h>
#include <dpkg/string.h>
#include <dpkg/path.h>

#include "debsig.h"

const char *rootdir = "";

const char *policies_dir = DEBSIG_POLICIES_DIR;
const char *keyrings_dir = DEBSIG_KEYRINGS_DIR;

#define CTAR(x) "control.tar" # x
#define DTAR(x) "data.tar" # x
static const char ver_magic_member[] = "debian-binary";
static const char *ver_ctrl_members[] = {
	CTAR(), CTAR(.gz), CTAR(.xz), CTAR(.zst), NULL
};
static const char *ver_data_members[] = {
	DTAR(), DTAR(.gz), DTAR(.xz), DTAR(.zst), DTAR(.bz2), DTAR(.lzma), NULL
};

/* The ar format specifies a maximum size of 9,999,999,999 per
   member. so 10 digits per member. We will be be checking 3 of those
   members, so our absolute maximum is 3 times that which may take 11
   digits.
*/
#define AR_MAX_SIZE 11
struct checksums {
    struct {
        SHA256_CTX ctx;
        unsigned char result[SHA256_DIGEST_LENGTH];
        /* Space for 11 chars of data size, ":", then the hex
         * representation of the checksum */
        char text[11 + 2 + 2*SHA256_DIGEST_LENGTH];
    } sha256;
    struct {
        SHA512_CTX ctx;
        unsigned char result[SHA512_DIGEST_LENGTH];
        /* Space for 10 chars of data size, ":", then the hex
         * representation of the checksum */
        char text[11 + 2 + 2* SHA512_DIGEST_LENGTH];
    } sha512;
};

static int
checkSelRules(struct dpkg_ar *deb, const char *originID, struct group *grp, bool sigs[NUM_SIGNATURE_TYPES])
{
    int opt_count = 0;
    struct match *mtc;
    int len;
    enum signature_type sig_type;
    memset(sigs, 0, (NUM_SIGNATURE_TYPES * sizeof(bool)));

    for (mtc = grp->matches; mtc; mtc = mtc->next) {
        char *keyring;

        ds_printf(DS_LEV_VER, "      Processing '%s' key...", mtc->name);

        /* Get the keyring we might need to use multiple times. */
        keyring = getDbPathname(rootdir, keyrings_dir, originID, mtc->file);
        if (keyring == NULL) {
            ds_printf(DS_LEV_DEBUG, "checkSelRules: cannot find %s keyring", mtc->file);
            return 0;
        }

        if (mtc->id) {
            /* If we have an ID for this match, check to make sure it exists,
             * and matches the signature we are about to check.  */
            char *m_id = getKeyID(keyring, mtc->id);
            char *d_id = getSigKeyID(deb, mtc->name);
            bool is_same_id = eqKeyID(m_id, d_id);

            free(m_id);
            free(d_id);
            free(keyring);

            if (!is_same_id)
                return 0;
        } else {
            /* If the match does not specify an ID, we should check whether
             * the ID of the signature exists in the keyring specified. */
            char *m_id = getKeyID(keyring, originID);
            bool found = m_id != NULL;

            free(m_id);
            free(keyring);

            if (!found)
              return 0;
        }

        len = checkSigExist(deb, mtc->name, &sig_type);

        /* If the member exists and we reject it, fail now. Also, if it
         * doesn't exist, and we require it, fail as well. */
        if ((!len && mtc->type == MATCH_REQUIRED) ||
            (len && mtc->type == MATCH_REJECT)) {
            return 0;
        }
        /* This would mean this is Optional, so we ignore it for now */
        if (!len)
            continue;

        sigs[sig_type] = true;
        ds_printf(DS_LEV_VER, "      Found a %s sig file.", sig_types[sig_type].signame);

        /* Kick up the count once for checking later */
        if (mtc->type == MATCH_OPTIONAL)
            opt_count++;
    }

    if (opt_count < grp->min_opt) {
        ds_printf(DS_LEV_DEBUG, "checkSelRules: opt passed - %d, opt required %d",
                  opt_count, grp->min_opt);
        return 0;
    }

    return 1;
}

static off_t
copyData(int in_fd, int tmp_data_fd, off_t len, bool signature_types[], struct checksums *csums)
{
    unsigned char *buf;
    int bufsize = 32 * 1024;
    off_t bytesread = 0, byteswritten = 0;
    off_t totalread = 0, totalwritten = 0;

    if ((len != -1) && (len < bufsize))
        bufsize = len;
    if (bufsize == 0)
        buf = NULL;
    else
        buf = m_malloc(bufsize);

    while (bufsize > 0) {
        bytesread = fd_read(in_fd, buf, bufsize);
        if (bytesread < 0)
            break;
        if (bytesread == 0)
            break;

        totalread += bytesread;

        if (len != -1) {
            len -= bytesread;
            if (len < bufsize)
                bufsize = len;
        }

        /* Update checksum(s) if we're using them. */
        if (csums && signature_types[SUM_SHA256])
            SHA256_Update(&csums->sha256.ctx, buf, bytesread);
        if (csums && signature_types[SUM_SHA512])
            SHA512_Update(&csums->sha512.ctx, buf, bytesread);

        /* Update our temporary file if we're using direct
         * signing. */
        if (tmp_data_fd != -1) {
            byteswritten = fd_write(tmp_data_fd, buf, bytesread);
            if (byteswritten < 0)
                break;
            if (byteswritten == 0)
                break;
        }
        else
            byteswritten = bytesread;

        totalwritten += byteswritten;
    }

    free(buf);

    if (bytesread < 0 || byteswritten < 0)
        return -1;
    if (totalread != totalwritten)
        return -1;

    return totalread;
}

static void
hex_dump_to_buffer(char *output_buffer, unsigned char *buf, size_t buf_size)
{
    unsigned int i;
    char *p = output_buffer;

    memset(output_buffer, 0, 1 + (2*buf_size));
    for (i = 0; i < buf_size ; i++)
        p += sprintf(p, "%2.2x", buf[i]);
}

static int
verifyGroupRules(struct dpkg_ar *deb, const char *originID, struct group *grp, bool signature_types[])
{
    char *tmp_sig = NULL;
    int tmp_sig_fd = -1;
    char *tmp_data = NULL;
    int tmp_data_fd = -1;
    char *keyring = NULL;
    enum signature_type sig_type;
    int opt_count = 0, t, i;
    struct match *mtc;
    off_t len;
    off_t total_len = 0;
    struct checksums csums;

    /* Set umask for a more controlled environment. */
    umask(022);

    /* If we don't have any matches, we fail. We don't want blank,
     * take-all rules. This actually gets checked while we parse the
     * policy file, but we check again for good measure.  */
    if (grp->matches == NULL)
        return 0;

    /*
     * If we're doing direct PGP verification of data, cat all our
     * data into a single temp file. This is what we pass to the
     * OpenPGP implementation.
     */
    if (signature_types[PGP_DIRECT]) {
        tmp_data = path_make_temp_template("debsig-data");
        if ((tmp_data_fd = mkstemp(tmp_data)) == -1) {
            ds_printf(DS_LEV_ERR, "error creating temp file %s: %s\n",
                  tmp_data, strerror(errno));
            free(tmp_data);
            return 0;
        }
    }

    /* Start checksum operations too, if we're doing checksum-based
     * signing. */
    if (signature_types[SUM_SHA256])
        SHA256_Init(&csums.sha256.ctx);
    if (signature_types[SUM_SHA512])
        SHA512_Init(&csums.sha512.ctx);

    /* Now, let's find all the members we need to check. */
    if (!(len = findMember(deb, ver_magic_member)))
        goto fail_and_close;

    len = copyData(deb->fd, tmp_data_fd, len, signature_types, &csums);
    if (len < 0)
        ohshit("verifyGroupRules: cannot copy data: %s", strerror(errno));
    total_len += len;

    for (i = 0; ver_ctrl_members[i]; i++) {
        len = findMember(deb, ver_ctrl_members[i]);
        if (!len)
            continue;
        len = copyData(deb->fd, tmp_data_fd, len, signature_types, &csums);
        if (len < 0)
            ohshit("verifyGroupRules: cannot copy data: %s", strerror(errno));
        total_len += len;
        break;
    }
    if (!ver_ctrl_members[i])
        goto fail_and_close;

    for (i = 0; ver_data_members[i]; i++) {
        len = findMember(deb, ver_data_members[i]);
        if (!len)
            continue;
        len = copyData(deb->fd, tmp_data_fd, len, signature_types, &csums);
        if (len < 0)
            ohshit("verifyGroupRules: cannot copy data: %s", strerror(errno));
        total_len += len;
        break;
    }
    if (!ver_data_members[i])
        goto fail_and_close;

    if (tmp_data_fd != -1 && close(tmp_data_fd))
        ohshite("error closing temp file %s", tmp_data);
    tmp_data_fd = -1;

    /* Sanity check (11 digits: 99 999 999 999) - should never trigger
     * here due to the limitations of the ar format. */
    if (total_len > 99999999999) {
        ds_printf(DS_LEV_DEBUG, "verifyGroupRules: data size %jd too big!", total_len);
        goto fail_and_close;
    }

    /* Finish checksum operations too, if we're doing checksum-based
     * signing. */
    if (signature_types[SUM_SHA256]) {
        char *textptr = csums.sha256.text;
        textptr += sprintf(textptr, "%jd:", total_len);
        SHA256_Final(csums.sha256.result, &csums.sha256.ctx);
        hex_dump_to_buffer(textptr, csums.sha256.result, SHA256_DIGEST_LENGTH);
    }
    if (signature_types[SUM_SHA512]) {
        char *textptr = csums.sha512.text;
        textptr += sprintf(textptr, "%jd:", total_len);
        SHA512_Final(csums.sha512.result, &csums.sha512.ctx);
        hex_dump_to_buffer(textptr, csums.sha512.result, SHA512_DIGEST_LENGTH);
    }

    for (mtc = grp->matches; mtc; mtc = mtc->next) {
        ds_printf(DS_LEV_VER, "      Processing '%s' key...", mtc->name);

        /* Get the keyring we might need to use multiple times. */
        keyring = getDbPathname(rootdir, keyrings_dir, originID, mtc->file);
        if (keyring == NULL) {
            ds_printf(DS_LEV_DEBUG, "verifyGroupRules: cannot find %s keyring", mtc->file);
            goto fail_and_close;
        }

        /* If we have an ID for this match, check to make sure it exists, and
         * matches the signature we are about to check.  */
        if (mtc->id) {
            char *m_id = getKeyID(keyring, mtc->id);
            char *d_id = getSigKeyID(deb, mtc->name);
            bool is_same_id = eqKeyID(m_id, d_id);

            free(m_id);
            free(d_id);

            if (!is_same_id)
                goto fail_and_close;
        }

        /* This will also position deb->fd to the start of the member. */
        len = checkSigExist(deb, mtc->name, &sig_type);

        /* If the member exists and we reject it, die now. Also, if it
         * doesn't exist, and we require it, die as well. */
        if ((!len && mtc->type == MATCH_REQUIRED) ||
            (len && mtc->type == MATCH_REJECT)) {
            goto fail_and_close;
        }

        /* This would mean this is Optional, so we ignore it for now */
        if (!len)
            continue;

        /* Write the signature data out to a temporary file, ready to
         * pass to the openpgp implementation. */
        tmp_sig = path_make_temp_template("debsig-sig");
        if ((tmp_sig_fd = mkstemp(tmp_sig)) == -1) {
            ds_printf(DS_LEV_ERR, "error creating temp file %s: %s\n",
                      tmp_sig, strerror(errno));
            goto fail_and_close;
        }

        /* Pass NULL for the checksum contexts here so we do *not*
         * attempt to update checksums here - they're just for the
         * data, not the signature itself. */
        len = copyData(deb->fd, tmp_sig_fd, len, signature_types, NULL);
        if (len < 0)
            ohshit("verifyGroupRules: cannot copy to temp file: %s", strerror(errno));

        if (close(tmp_sig_fd) < 0)
            ohshit("error closing temp file %s", tmp_sig);

        /* Now, let's check the signature with our OpenPGP
         * implementation. */
        switch (sig_type) {
            case PGP_DIRECT:
                t = sigVerify(keyring, tmp_data, tmp_sig);
                break;
            case SUM_SHA256:
                t = sigVerifyInline(keyring, tmp_sig, csums.sha256.text);
                break;
            case SUM_SHA512:
                t = sigVerifyInline(keyring, tmp_sig, csums.sha512.text);
                break;
            default:
                ohshit("verifyGroupRules: unexpected signature type %d", sig_type);
        }
        free(keyring);
        keyring = NULL;

        tmp_sig_fd = -1;
        unlink(tmp_sig);
        free(tmp_sig);

        /* We fail no matter what now. Even if this is an optional match
         * rule, by now, we know that the sig exists, so we must fail */
        if (!t) {
            ds_printf(DS_LEV_DEBUG, "verifyGroupRules: failed for %s", mtc->name);
            goto fail_and_close;
        }

        /* Kick up the count once for checking later */
        if (mtc->type == MATCH_OPTIONAL)
            opt_count++;
    }

    if (opt_count < grp->min_opt) {
        ds_printf(DS_LEV_DEBUG, "verifyGroupRules: opt passed - %d, opt required %d",
                  opt_count, grp->min_opt);
        goto fail_and_close;
    }

    unlink(tmp_data);
    free(tmp_data);
    return 1;

fail_and_close:
    unlink(tmp_data);
    free(tmp_data);
    free(keyring);
    if (tmp_sig_fd != -1)
        close(tmp_sig_fd);
    if (tmp_data_fd != -1)
        close(tmp_data_fd);
    return 0;
}

static int
checkIsDeb(struct dpkg_ar *deb)
{
    int i;
    const char *member;
    int num_members;

    if (!findMember(deb, ver_magic_member)) {
       ds_printf(DS_LEV_VER, "Missing archive magic member %s", ver_magic_member);
       return 0;
    }

    num_members = 0;
    for (i = 0; (member = ver_ctrl_members[i]); i++)
        if (findMember(deb, member))
            num_members++;

    if (!num_members) {
        ds_printf(DS_LEV_VER, "Missing archive control member, checked:");
        for (i = 0; (member = ver_ctrl_members[i]); i++)
            ds_printf(DS_LEV_VER, "    %s", member);
        return 0;
    }

    if (num_members > 1) {
        ds_printf(DS_LEV_VER, "Found multiple control members (%d)", num_members);
        return 0;
    }

    num_members = 0;
    for (i = 0; (member = ver_data_members[i]); i++)
        if (findMember(deb, member))
            num_members++;

    if (!num_members) {
        ds_printf(DS_LEV_VER, "Missing archive data member, checked:");
        for (i = 0; (member = ver_data_members[i]); i++)
            ds_printf(DS_LEV_VER, "    %s", member);
        return 0;
    }

    if (num_members > 1) {
        ds_printf(DS_LEV_VER, "Found multiple data members (%d)", num_members);
        return 0;
    }

    return 1;
}

static void
outputVersion(void)
{
    printf(
"Debsig Program Version - "VERSION"\n"
"  Signature Version - "SIG_VERSION"\n"
"  Signature Namespace - "DEBSIG_NAMESPACE"\n"
"  Policies Directory - "DEBSIG_POLICIES_DIR"\n"
"  Keyrings Directory - "DEBSIG_KEYRINGS_DIR"\n");
}

static void
outputBadUsage(void)
{
    ohshit("Use --help for program usage information.");
}

static void
outputUsage(void)
{
    printf("Usage: %s [<option>...] <deb>\n\n", dpkg_get_progname());

    printf(
"Options:\n"
"  -q, --quiet              Quiet, only output fatal errors.\n"
"  -v, --verbose            Verbose output (mainly debug).\n"
"  -d, --debug              Debug output as well.\n"
"      --list-policies      Only list policies that can be used to validate\n"
"                             this sig. Only runs through 'Selection' block.\n"
"      --use-policy <name>  Specify the short policy name to use.\n"
"      --policies-dir <dir> Use an alternative policies directory.\n"
"      --keyrings-dir <dir> Use an alternative keyrings directory.\n"
"      --root <dir>         Use an alternative root directory for policy lookup.\n"
"      --help               Output usage info, and exit.\n"
"      --version            Output version info, and exit.\n"
);
}

static void
ds_catch_fatal_error(void)
{
    pop_error_context(ehflag_bombout);
    exit(DS_FAIL_INTERNAL);
}

static void
ds_print_fatal_error(const char *emsg, const void *data)
{
    ds_printf(DS_LEV_ERR, "%s", emsg);
}

int
main(int argc, char *argv[])
{
    struct dpkg_ar *deb;
    struct policy *pol = NULL;
    char *originID;
    char *origin_dir = NULL, *pol_file = NULL, *force_file = NULL;
    DIR *pd = NULL;
    struct dirent *pd_ent;
    struct group *grp;
    int i, list_only = 0;
    bool signature_types [NUM_SIGNATURE_TYPES] = {false};

    dpkg_set_progname(argv[0]);

    push_error_context_func(ds_catch_fatal_error, ds_print_fatal_error, NULL);

    if (argc < 2) {
	ds_printf(DS_LEV_ERR, "missing <deb> filename argument");
	outputBadUsage();
    }

    for (i = 1; i < argc && argv[i][0] == '-'; i++) {
	if (strcmp(argv[i], "-v") == 0|| strcmp(argv[i], "--verbose") == 0)
	    ds_debug_level = DS_LEV_VER;
	else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0)
	    ds_debug_level = DS_LEV_ERR;
	else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0)
	    ds_debug_level = DS_LEV_DEBUG;
	else if (strcmp(argv[i], "--version") == 0) {
	    /* Make sure we exit non-zero if there are any more args. This
	     * makes sure someone doesn't do something stupid like pass
	     * --version and a .deb, and expect it to return a validation
	     * exit status.  */
	    if (argc > 2) {
		ds_printf(DS_LEV_ERR, "--version accepts no arguments");
		exit(1);
	    }

	    outputVersion();
	    exit(0);
	} else if (strcmp(argv[i], "--help") == 0) {
	    outputUsage();
	    exit(0);
	} else if (strcmp(argv[i], "--list-policies") == 0) {
	    /* Just create a list of policies we can use */
	    list_only = 1;
	    ds_printf(DS_LEV_ALWAYS, "Listing usable policies");
	} else if (strcmp(argv[i], "--use-policy") == 0) {
	    /* We take one arg */
	    force_file = argv[++i];
	    if (i == argc || force_file[0] == '-') {
		ds_printf(DS_LEV_ERR, "--use-policy requires an argument");
		outputBadUsage();
	    }
	} else if (strcmp(argv[i], "--policies-dir") == 0) {
	    policies_dir = argv[++i];
	    if (i == argc || policies_dir[0] == '-') {
		ds_printf(DS_LEV_ERR, "--policies-dir requires an argument");
		outputUsage();
	    }
	} else if (strcmp(argv[i], "--keyrings-dir") == 0) {
	    keyrings_dir = argv[++i];
	    if (i == argc || keyrings_dir[0] == '-') {
		ds_printf(DS_LEV_ERR, "--keyrings-dir requires an argument");
		outputUsage();
	    }
	} else if (strcmp(argv[i], "--root") == 0) {
	    rootdir = argv[++i];
	    if (i == argc || rootdir[0] == '-') {
		ds_printf(DS_LEV_ERR, "--root requires an argument");
		outputBadUsage();
	    }
	} else {
	    ds_printf(DS_LEV_ERR, "unknown argument '%s'", argv[i]);
	    outputUsage();
	    exit(1);
	}
    }

    /* There should only be one arg left. */
    if (i == argc) {
	ds_printf(DS_LEV_ERR, "missing .deb archive");
	outputBadUsage();
    } else if (i + 1 > argc) {
	ds_printf(DS_LEV_ERR, "too many arguments");
	outputBadUsage();
    }

    deb = dpkg_ar_open(argv[i]);

    if (!list_only)
	ds_printf(DS_LEV_VER, "Starting verification for: %s", deb->name);

    if (!checkIsDeb(deb))
	ohshit("%s does not appear to be a deb format package", deb->name);

    originID = getSigKeyID(deb, "origin");
    if (originID == NULL)
	ds_fail_printf(DS_FAIL_NOSIGS, "Origin Signature check failed. This deb might not be signed.\n");

    /* Now we have an ID, let's check the policy to use */
    origin_dir = getDbPathname(rootdir, policies_dir, originID, NULL);
    if (origin_dir == NULL)
        ds_fail_printf(DS_FAIL_UNKNOWN_ORIGIN,
                       "Could not find Origin directory for %s\n", originID);

    pd = opendir(origin_dir);
    if (pd == NULL)
	ds_fail_printf(DS_FAIL_UNKNOWN_ORIGIN,
                       "Could not open Origin directory %s: %s\n",
                       origin_dir, strerror(errno));

    ds_printf(DS_LEV_VER, "Using policy directory: %s", origin_dir);

    if (list_only)
        ds_printf(DS_LEV_ALWAYS, "  Policies in: %s", origin_dir);

    while ((pd_ent = readdir(pd)) != NULL && (pol == NULL || list_only)) {
        free(pol_file);
        pol_file = NULL;
	bool sig_types_this_policy [NUM_SIGNATURE_TYPES] = {false};

	/* Make sure we have the right name format */
	if (!str_match_end(pd_ent->d_name, ".pol"))
	    continue;

	if (force_file != NULL && strcmp(pd_ent->d_name, force_file) != 0)
	    continue;

	/* Now try to parse the file */
        m_asprintf(&pol_file, "%s/%s", origin_dir, pd_ent->d_name);
	ds_printf(DS_LEV_VER, "  Parsing policy file: %s", pol_file);
	pol = parsePolicyFile(pol_file);

	if (pol == NULL)
	    continue;

	/* Now let's see if this policy's selection is useful for this .deb  */
	ds_printf(DS_LEV_VER, "    Checking Selection group(s).");
	for (grp = pol->sels; grp != NULL; grp = grp->next) {
	    if (!checkSelRules(deb, originID, grp, sig_types_this_policy)) {
		clear_policy();
		ds_printf(DS_LEV_VER, "    Selection group failed checks.");
		pol = NULL;
		break;
	    }
	}

	if (pol && list_only) {
	    ds_printf(DS_LEV_ALWAYS, "    Usable: %s", pd_ent->d_name);
	    list_only++;
	} else if (pol) {
	    ds_printf(DS_LEV_VER, "    Selection group(s) passed, policy is usable.");
	    /* Update the global state of which signature types we're
	     * using. */
	    for (i = 0; i < NUM_SIGNATURE_TYPES; i++) {
	        if (sig_types_this_policy[i])
                    signature_types[i] = true;
	    }
	}
    }
    closedir(pd);

    free(origin_dir);

    if ((pol == NULL && !list_only) || list_only == 1) /* Damn, can't verify this one */
	ds_fail_printf(DS_FAIL_NOPOLICIES, "No applicable policy found.");

    if (list_only)
	exit(0); /* our job is done */

    ds_printf(DS_LEV_VER, "Using policy file: %s", pol_file);
    free(pol_file);

    /* This should actually be caught in the xml-parsing. */
    if (pol->vers == NULL)
	ds_fail_printf(DS_FAIL_NOPOLICIES, "Failed, no Verification groups in policy.");

    /* Now the final test */
    ds_printf(DS_LEV_VER, "    Checking Verification group(s).");

    for (grp = pol->vers; grp; grp = grp->next) {
	if (!verifyGroupRules(deb, originID, grp, signature_types)) {
	    ds_printf(DS_LEV_VER, "    Verification group failed checks.");
	    ds_fail_printf(DS_FAIL_BADSIG, "Failed verification for %s.", deb->name);
	}
    }

    ds_printf(DS_LEV_VER, "    Verification group(s) passed, deb is validated.");

    ds_printf(DS_LEV_INFO, "Verified package from '%s' (%s)",
	      pol->description, pol->name);

    pop_error_context(ehflag_normaltidy);

    /* If we get here, then things passed just fine */
    exit(DS_SUCCESS);
}
