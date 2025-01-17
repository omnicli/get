#!/bin/sh
#
#    :?:.!YG#&@@@&#GJ~.
#   7#@&#@@@&#BGB#&@@@#Y^
#   ^&@@@@&?.     :~Y#@@@Y
#  .G@@&#@@&5^       .J@@@G.   OMNI
#  P@@@! 7B@@@P~       7@@@5
#  @@@P    !B@@@G~      G@@&     THE OMNIPOTENT
#  @@@P    !B@@@B!      G@@&        DEV TOOL
#  P@@@~ 7B@@@P~       !@@@5
#  .G@@&B@@&P~       .?@@@G.
#   ^#@@@@&?.     .~J#@@@Y.
#   7&@&#@@@&BGGGB&@@@#5^
#    :?^.!YG#@@@@@#GY!.
#
# omni install script
#
# This aims at being a POSIX compliant install script for omni.
# It is intended to be run directly from the web:
#  $ sh -c "$(curl -fsLS get.omnicli.dev)" -- clone git@github.com:<org>/<repo>
#
# This contains code from and inspired by the install
# script for https://github.com/twpayne/chezmoi

set -e

if [ -z "${BINDIR}" ]; then
	for path in "$HOME/.local/bin" "$HOME/bin" /usr/local/bin; do
		[ -n "${BINDIR}" ] && break
		case :$PATH: in
			*:$path:*) BINDIR="${path}" ;;
			*) ;;
		esac
	done
	BINDIR="${BINDIR:-./bin}"
fi

TAGARG=latest
LOG_LEVEL=2
INSTALL_WITH=

GITHUB_NAME=xaf/omni
GITHUB_REPO="https://github.com/${GITHUB_NAME}"
GITHUB_RELEASES="${GITHUB_REPO}/releases"
GITHUB_DOWNLOAD="${GITHUB_RELEASES}/download"

tmpdir="$(mktemp -d -t get-omni.XXXXXXXXXX)"
trap 'rm -rf -- "${tmpdir}"' EXIT
trap 'exit' INT TERM

usage() {
	this="${1}"
	cat <<EOF
${this}: download omni and optionally run omni

Usage: ${this} [-b bindir] [-dBCD] [omni-args]
  -b sets the installation directory, default is ${BINDIR}.
  -d enables debug logging.
  -B install omni via brew.
  -C install omni via cargo.
  -D install omni via download.
If omni-args are given, after install omni is executed with omni-args.
EOF
	exit 2
}

main() {
	parse_args "${@}"
	shift "$((OPTIND - 1))"

	BINSUFFIX=
	BINARY="omni${BINSUFFIX}"

	if install_via_brew; then
		BINDIR="$(brew --prefix)/bin"
	elif [ "${INSTALL_WITH:-download}" = "download" ] && install_via_download; then
		: # Nothing to do
	elif [ "${INSTALL_WITH:-cargo}" = "cargo" ] && install_via_cargo; then
		: # Nothing to do
	else
		log_crit "unable to install omni"
		exit 1
	fi

	if [ -n "${1+n}" ]; then
		exec "${BINDIR}/${BINARY}" "${@}"
	fi
}

install_via_brew() {
	if [ "${INSTALL_WITH:-brew}" != "brew" ]; then
		return 1
	fi

	if is_command brew; then
		log_info "brew is installed; installing omni via brew"
		brew tap xaf/omni
		brew install omni
		return 0
	fi

	return 1
}

install_via_download() {
	if [ "${INSTALL_WITH:-download}" != "download" ]; then
		return 1
	fi

	OS="$(get_os)"
	ARCH="$(get_arch)"
	if ! check_os_arch "${OS}/${ARCH}"; then
		return 1
	fi

	TAG="$(real_tag "${TAGARG}")"
	if [ -z "${TAG}" ]; then
		return 1
	fi

	VERSION="${TAG#v}"

	log_info "found version ${VERSION} for ${TAGARG}/${OS}/${ARCH}"

	FORMAT=tar.gz

	# download tarball
	NAME="omni-${VERSION}-${ARCH}-${OS}"
	TARBALL="${NAME}.${FORMAT}"
	TARBALL_URL="${GITHUB_DOWNLOAD}/${TAG}/${TARBALL}"
	http_download "${tmpdir}/${TARBALL}" "${TARBALL_URL}" || exit 1

	# download checksums
	CHECKSUMS="${NAME}.sha256"
	CHECKSUMS_URL="${GITHUB_DOWNLOAD}/${TAG}/${CHECKSUMS}"
	http_download "${tmpdir}/${CHECKSUMS}" "${CHECKSUMS_URL}" || exit 1

	# verify checksums
	hash_sha256_verify "${tmpdir}/${TARBALL}" "${tmpdir}/${CHECKSUMS}"

	# verify signature
	keyless_sig_verify "${TARBALL}" "${NAME}" "${TAG}" "${tmpdir}" || exit 1

	(cd -- "${tmpdir}" && untar "${TARBALL}")

	# install binary
	if [ ! -d "${BINDIR}" ]; then
		install -d "${BINDIR}"
	fi
	install -- "${tmpdir}/${BINARY}" "${BINDIR}/"
	log_info "installed ${BINDIR}/${BINARY}"

	return 0
}

install_via_cargo() {
	if [ "${INSTALL_WITH:-cargo}" != "cargo" ]; then
		return 1
	fi

	cargo install omnicli --root "${BINDIR}"
	return $?
}

parse_args() {
	while getopts "b:dh?V:BCD" arg; do
		case "${arg}" in
		b) BINDIR="${OPTARG}" ;;
		d) LOG_LEVEL=3 ;;
		B) INSTALL_WITH=brew ;;
		C) INSTALL_WITH=cargo ;;
		D) INSTALL_WITH=download ;;
		h | \?) usage "${0}" ;;
		*) return 1 ;;
		esac
	done
}

get_os() {
	read_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
	case "${read_os}" in
	cygwin_nt*) os="windows" ;;
	mingw*) os="windows" ;;
	msys_nt*) os="windows" ;;
	*) os="${read_os}" ;;
	esac
	printf '%s' "${os}"
}

get_arch() {
	read_arch="$(uname -m)"
	case "${read_arch}" in
	aarch64) arch="arm64" ;;
	armv*) arch="arm" ;;
	i386) arch="386" ;;
	i686) arch="386" ;;
	i86pc) arch="x86_64" ;;
	x86) arch="386" ;;
	x86_64) arch="x86_64" ;;
	*) arch="${read_arch}" ;;
	esac
	printf '%s' "${arch}"
}

check_os_arch() {
	case "${1}" in
	darwin/x86_64) return 0 ;;
	darwin/arm64) return 0 ;;
	# freebsd/x86_64) return 0 ;;
	# freebsd/arm64) return 0 ;;
	linux/x86_64) return 0 ;;
	linux/arm64) return 0 ;;
	# openbsd/x86_64) return 0 ;;
	# openbsd/arm64) return 0 ;;
	*)
		printf '%s: unsupported platform\n' "${1}" 1>&2
		return 1
		;;
	esac
}

get_libc() {
	if is_command ldd; then
		case "$(ldd --version 2>&1 | tr '[:upper:]' '[:lower:]')" in
		*glibc* | *"gnu libc"*)
			printf glibc
			return
			;;
		*musl*)
			printf musl
			return
			;;
		esac
	fi
	if is_command getconf; then
		case "$(getconf GNU_LIBC_VERSION 2>&1)" in
		*glibc*)
			printf glibc
			return
			;;
		esac
	fi
	log_crit "unable to determine libc" 1>&2
	exit 1
}

real_tag() {
	tag="${1}"
	log_debug "checking GitHub for tag ${tag}"
	release_url="${GITHUB_RELEASES}/${tag}"
	json="$(http_get "${release_url}" "Accept: application/json")"
	if [ -z "${json}" ]; then
		log_err "real_tag error retrieving GitHub release ${tag}"
		return 1
	fi
	real_tag="$(printf '%s\n' "${json}" | tr -s '\n' ' ' | sed 's/.*"tag_name":"//' | sed 's/".*//')"
	if [ -z "${real_tag}" ]; then
		log_err "real_tag error determining real tag of GitHub release ${tag}"
		return 1
	fi
	if [ -z "${real_tag}" ]; then
		return 1
	fi
	log_debug "found tag ${real_tag} for ${tag}"
	printf '%s' "${real_tag}"
}

http_get() {
	tmpfile="$(mktemp)"
	http_download "${tmpfile}" "${1}" "${2}" || return 1
	body="$(cat "${tmpfile}")"
	rm -f "${tmpfile}"
	printf '%s\n' "${body}"
}

http_download_curl() {
	local_file="${1}"
	source_url="${2}"
	header="${3}"
	if [ -z "${header}" ]; then
		code="$(curl -w '%{http_code}' -sL -o "${local_file}" "${source_url}")"
	else
		code="$(curl -w '%{http_code}' -sL -H "${header}" -o "${local_file}" "${source_url}")"
	fi
	if [ "${code}" != "200" ]; then
		log_debug "http_download_curl received HTTP status ${code}"
		return 1
	fi
	return 0
}

http_download_wget() {
	local_file="${1}"
	source_url="${2}"
	header="${3}"
	if [ -z "${header}" ]; then
		wget -q -O "${local_file}" "${source_url}" || return 1
	else
		wget -q --header "${header}" -O "${local_file}" "${source_url}" || return 1
	fi
}

http_download() {
	log_debug "http_download ${2}"
	if is_command curl; then
		http_download_curl "${@}" || return 1
		return
	elif is_command wget; then
		http_download_wget "${@}" || return 1
		return
	fi
	log_crit "http_download unable to find wget or curl"
	return 1
}

hash_sha256() {
	target="${1}"
	if is_command sha256sum; then
		hash="$(sha256sum "${target}")" || return 1
		printf '%s' "${hash}" | cut -d ' ' -f 1
	elif is_command shasum; then
		hash="$(shasum -a 256 "${target}" 2>/dev/null)" || return 1
		printf '%s' "${hash}" | cut -d ' ' -f 1
	elif is_command sha256; then
		hash="$(sha256 -q "${target}" 2>/dev/null)" || return 1
		printf '%s' "${hash}" | cut -d ' ' -f 1
	elif is_command openssl; then
		hash="$(openssl dgst -sha256 "${target}")" || return 1
		printf '%s' "${hash}" | cut -d ' ' -f a
	else
		log_crit "hash_sha256 unable to find command to compute SHA256 hash"
		return 1
	fi
}

hash_sha256_verify() {
	target="${1}"
	checksums="${2}"
	basename="${target##*/}"

	want="$(grep "${basename}" "${checksums}" 2>/dev/null | tr '\t' ' ' | cut -d ' ' -f 1)"
	if [ -z "${want}" ]; then
		log_err "hash_sha256_verify unable to find checksum for ${target} in ${checksums}"
		return 1
	fi

	got="$(hash_sha256 "${target}")"
	if [ "${want}" != "${got}" ]; then
		log_err "hash_sha256_verify checksum for ${target} did not verify ${want} vs ${got}"
		return 1
	fi

	log_info "checksum verified"
}

keyless_sig_verify() {
	TARBALL="${1}"
	NAME="${2}"
	TAG="${3}"
	tmpdir="${4}"

	SIGNATURE="${NAME}-keyless.sig"
	SIGNATURE_URL="${GITHUB_DOWNLOAD}/${TAG}/${SIGNATURE}"
	CERTIFICATE="${NAME}-keyless.pem"
	CERTIFICATE_URL="${GITHUB_DOWNLOAD}/${TAG}/${CERTIFICATE}"

	has_cosign=$(is_command cosign && echo cosign)
	has_openssl=$(is_command openssl && echo openssl)

	if [ -n "${has_cosign}" ] || [ -n "${has_openssl}" ]; then
		http_download "${tmpdir}/${CERTIFICATE}" "${CERTIFICATE_URL}" || {
			log_warn "unable to download certificate; skipping verification"
			return 0
		}
		http_download "${tmpdir}/${SIGNATURE}" "${SIGNATURE_URL}" || {
			log_err "unable to download signature"
			return 1
		}
	fi

	# Use a regex since the account was renamed from XaF to xaf
	CERTIFICATE_ID_PATH="\\.github/workflows/build-and-test-target\\.yaml@refs/tags/${TAG}"
	CERTIFICATE_ID_REG="^https://github.com/[xX]a[fF]/omni/${CERTIFICATE_ID_PATH}\$"

	if [ -n "${has_cosign}" ]; then
		cosign verify-blob \
			--signature "${tmpdir}/${SIGNATURE}" \
			--certificate "${tmpdir}/${CERTIFICATE}" \
			--certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
			--certificate-identity-regexp "${CERTIFICATE_ID_REG}" \
			--certificate-github-workflow-ref "refs/tags/${TAG}" \
			"${tmpdir}/${TARBALL}" \
		&& {
			log_info "(cosign) signature verified"
			return 0
		}

		log_err "(cosign) signature verification failed"
		return 1
	fi

	if [ -n "${has_openssl}" ]; then
		# Decode the base64 certificate first
		base64_decode_file "${tmpdir}/${CERTIFICATE}" "${tmpdir}/decoded.pem" || {
			log_err "(openssl) failed to decode certificate"
			return 1
		}

		# Extract the claims from the certificate
		check_oidc_claims "${tmpdir}/decoded.pem" "${CERTIFICATE_ID_REG}" || {
			log_err "(openssl) failed to verify certificate claims"
			return 1
		}

		# Extract public key from certificate first
		openssl x509 \
			-in "${tmpdir}/decoded.pem" \
			-pubkey -noout >"${tmpdir}/pubkey.pem" \
		|| {
			log_err "(openssl) failed to extract public key from certificate"
			return 1
		}

		# Decode the base64 signature if needed
		base64_decode_file "${tmpdir}/${SIGNATURE}" "${tmpdir}/decoded.sig" || {
			# If the signature is not base64 encoded, it is a raw signature
			cp "${tmpdir}/${SIGNATURE}" "${tmpdir}/decoded.sig"
		}

		# Verify using the extracted public key
		openssl dgst \
			-sha256 \
			-verify "${tmpdir}/pubkey.pem" \
			-signature "${tmpdir}/decoded.sig" \
			"${tmpdir}/${TARBALL}" \
		&& {
			log_info "(openssl) signature verified"
			return 0
		}

		log_err "(openssl) signature verification failed"
		return 1
	fi

	log_warn "cosign and openssl not found; skipping signature verification"
	return 0
}

base64_decode_file() {
	source="${1:?}"
	target="${2:?}"

	# The base64 binary can be either GNU or BSD, which takes different
	# arguments for decoding.
	if base64 --version 2>&1 | grep -q 'BSD'; then
		base64 -d -i "${source}" -o "${target}"
	else
		base64 -d "${source}" > "${target}"
	fi
}

check_oidc_claims() {
	certificate="${1:?}"
	identity_regex="${2:?}"

	# Extract the issuer claim from the certificate
	issuer_claim=$(openssl x509 -text -noout -in "${certificate}" | \
		grep -E -A1 '^\s+1\.3\.6\.1\.4\.1\.57264\.1\.1:' | \
		tail -n1 | \
		sed 's/^\s*[^a-zA-Z]*//')
	if [ -z "${issuer_claim}" ]; then
		log_err "certificate does not contain an issuer claim"
		return 1
	fi

	# Check if the issuer claim matches the expected value
	if [ "${issuer_claim}" != "https://token.actions.githubusercontent.com" ]; then
		log_err "certificate issuer claim (${issuer_claim}) does not match expected value"
		return 1
	fi

	# Extract the identity claim from the certificate
	identity_claim=$(openssl x509 -text -noout -in "${certificate}" | \
		grep -E -A1 '^\s+1\.3\.6\.1\.4\.1\.57264\.1\.9:' | \
		tail -n1 | \
		sed 's/^\s*[^a-zA-Z]*//')
	if [ -z "${identity_claim}" ]; then
		log_err "certificate does not contain an identity claim"
		return 1
	fi

	# Check if the identity claim matches the expected value
	if ! echo "${identity_claim}" | grep -q -E "${identity_regex}"; then
		log_err "certificate identity claim (${identity_claim}) does not match expected value"
		return 1
	fi

	return 0
}

untar() {
	tarball="${1}"
	case "${tarball}" in
	*.tar.gz | *.tgz) tar -xzf "${tarball}" ;;
	*.tar) tar -xf "${tarball}" ;;
	*.zip) unzip -- "${tarball}" ;;
	*)
		log_err "untar unknown archive format for ${tarball}"
		return 1
		;;
	esac
}

is_command() {
	type "${1}" >/dev/null 2>&1
}

log_debug() {
	[ 3 -le "${LOG_LEVEL}" ] || return 0
	printf 'debug %s\n' "${*}" 1>&2
}

log_info() {
	[ 2 -le "${LOG_LEVEL}" ] || return 0
	printf 'info %s\n' "${*}" 1>&2
}

log_err() {
	[ 1 -le "${LOG_LEVEL}" ] || return 0
	printf 'error %s\n' "${*}" 1>&2
}

log_crit() {
	[ 0 -le "${LOG_LEVEL}" ] || return 0
	printf 'critical %s\n' "${*}" 1>&2
}

main "${@}"
