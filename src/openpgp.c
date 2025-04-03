/*
 * debsig-verify - Debian package signature verification tool
 * openpgp.c - OpenPGP frontend
 *
 * Copyright © 2021 Guillem Jover <guillem@debian.org>
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

#include <config.h>

#include <string.h>
#include <unistd.h>

#include <dpkg/dpkg.h>
#include <dpkg/path.h>

#include "debsig.h"

extern const struct openpgp openpgp_gpg;

static const struct openpgp *openpgp_impl[] = {
	&openpgp_gpg,
	NULL,
};

const struct signature_check sig_types[] =
{
    { SUM_SHA512, "sha512 checksum", "_sha512%s", },
    { SUM_SHA256, "sha256 checksum", "_sha256%s", },
    { PGP_DIRECT, "direct PGP", "_gpg%s", },
};

static const struct openpgp *
getOpenPGP(void)
{
	const struct openpgp *openpgp;

	for (openpgp = *openpgp_impl; openpgp; openpgp++)
		if (find_command(openpgp->cmd))
			break;

	if (openpgp == NULL)
		ohshit("cannot find an OpenPGP implementation");

	return openpgp;
}

static const char *
mapFprToKeyID(const char *id)
{
	if (strlen(id) == OPENPGP_FPR_LEN)
		return id + OPENPGP_FPR_LEN - OPENPGP_KEY_LEN;
	return id;
}

static char *
genDbPathname(const char *rootdir, const char *dir, const char *id,
                    const char *filename)
{
	char *pathname;

	if (filename)
		m_asprintf(&pathname, "%s%s/%s/%s", rootdir, dir, id, filename);
	else
		m_asprintf(&pathname, "%s%s/%s", rootdir, dir, id);
	if (access(pathname, F_OK) == 0)
		return pathname;
	return NULL;
}

char *
getDbPathname(const char *rootdir, const char *dir, const char *id,
              const char *filename)
{
	const char *keyid = mapFprToKeyID(id);
	char *pathname;

	pathname = genDbPathname(rootdir, dir, id, filename);

	if (id != keyid && pathname == NULL)
		pathname = genDbPathname(rootdir, dir, keyid, filename);

	if (pathname)
		ds_printf(DS_LEV_DEBUG, "getDbPathname: using %s keyring", pathname);

	return pathname;
}

bool
eqKeyID(const char *fprA, const char *fprB)
{
	size_t lenA, lenB, len;

	if (fprA == NULL || fprB == NULL)
		return false;

	lenA = strlen(fprA);
	lenB = strlen(fprB);

	if (lenA == 0 || lenB == 0)
		return false;

	if (lenA == lenB) {
		len = lenA;
	} else if (lenA > lenB) {
		len = lenB;
		fprA += lenA - lenB;
	} else {
		len = lenA;
		fprB += lenB - lenA;
	}

	return strncmp(fprA, fprB, len) == 0;
}

char *
getKeyID(const char *keyring, const char *match_id)
{
	const struct openpgp *openpgp = getOpenPGP();

	return openpgp->getKeyID(keyring, match_id);
}

char *
getSigKeyID(struct dpkg_ar *deb, const char *name)
{
	const struct openpgp *openpgp = getOpenPGP();

	return openpgp->getSigKeyID(deb, name);
}

off_t
checkSigExist(struct dpkg_ar *deb, const char *name, enum signature_type *sigtype)
{
    char buf[SIGFILE_NAME_LEN];
    off_t member = 0;
    int sig = 0;

    if (name == NULL || sigtype == NULL) {
        ds_printf(DS_LEV_DEBUG, "checkSigExist: NULL values passed");
        return 0;
    }

    *sigtype = 0;

    for (sig = 0; sig < NUM_SIGNATURE_TYPES; sig++) {
        snprintf(buf, sizeof(buf) - 1, sig_types[sig].name_format, name);
        member = findMember(deb, buf);
        if (member) {
            ds_printf(DS_LEV_DEBUG, "checkSigExist: found a %s signature file, len %jd",
                      sig_types[sig].signame, member);
            *sigtype = sig;
            return member;
        }
    }

    return 0;
}

int
sigVerify(const char *keyring, const char *data, const char *sig)
{
	const struct openpgp *openpgp = getOpenPGP();

	return openpgp->sigVerify(keyring, data, sig);
}

int
sigVerifyInline(const char *keyring, const char *data, const char *compare)
{
	const struct openpgp *openpgp = getOpenPGP();

	return openpgp->sigVerifyInline(keyring, data, compare);
}
