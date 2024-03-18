#!/usr/bin/env sh

# This is the OpenProvider API wrapper for acme.sh
#
# Author: René Kalff
# Report Bugs here: https://github.com/acmesh-official/acme.sh/issues/2104
#
#     export OPENPROVIDER_USER="username"
#     export OPENPROVIDER_PASSWORDHASH="hashed_password"
#
# Usage:
#     acme.sh --issue --dns dns_openprovider -d example.com

OPENPROVIDER_API="https://api.openprovider.eu/v1beta"

########  Public functions #####################

# Add a TXT value to the domain
# Usage: dns_openprovider_add fulldomain txtvalue
dns_openprovider_add() {
	fulldomain="$1"
	txtvalue="$2"

	_debug "First detect the root zone"
	if ! _get_root "$fulldomain"; then
		_err "invalid domain"
		return 1
	fi

	# Lets set the ttl to 900 as the Openprovider webinterface only supports a limited set of values.
	if ! _openprovider_api PUT "dns/zones/$_domain" "{\"records\": {\"add\": [{\"name\": \"$_sub_domain\",\"type\": \"TXT\", \"ttl\": 900, \"value\": \"$txtvalue\"}]}}"; then
		_err "Could not add TXT record."
		return 1
	fi
	return 0
}

# Removes a TXT record from the domain
# Usage: dns_openprovider_rm fulldomain txtvalue
# Remove the txt record after validation.
dns_openprovider_rm() {
	fulldomain="$1"
	txtvalue="$2"

	_debug "First detect the root zone"
	if ! _get_root "$fulldomain"; then
		_err "invalid domain"
		return 1
	fi

	# For some reason the value must be quoted on removal.
	if ! _openprovider_api PUT "dns/zones/$_domain" "{\"records\": {\"remove\": [{\"name\": \"$_sub_domain\",\"type\": \"TXT\", \"value\": \"\\\"$txtvalue\\\"\"}]}}"; then
		_err "Could not remove TXT record."
		return 1
	fi
	return 0
}

####################  Private functions below ##################################
# Returns the root for a given dns name
# Usage: _get_root _acme-challenge.www.domain.com
# Returns:
#  _sub_domain=_acme-challenge.www
#  _domain=domain.com
_get_root() {
	domain="$1"
	i=2
	p=1
	while true; do
		h=$(printf "%s" "$domain" | cut -d . -f $i-100)

		if [ -z "$h" ]; then
			#not valid
			return 1
		fi

		_sub_domain=$(printf "%s" "$domain" | cut -d . -f 1-$p)
		_domain="$h"

		if _openprovider_api GET "/dns/zones/$h" && _contains "$response" "master"; then
			_debug root_domain $_domain
			_debug sub_domain $_sub_domain
			return 0
		fi

		p=$i
		i=$(_math "$i" + 1)
	done
	_err "Unable to parse this domain"
	return 1
}

# Usage: _openprovider_api PUT /dns/zones/example.com '{"data": "value"}'
# Returns:
#  response='{"code": 0, "data": "api response"}'
_openprovider_api() {
	method=$1
	endpoint="$2"
	data="$3"
	_debug endpoint "$endpoint"

	if [ -z "$OPENPROVIDER_TOKEN" ]; then
		if ! _openprovider_login; then
			return 1
		fi
	fi
	_debug OPENPROVIDER_TOKEN "$OPENPROVIDER_TOKEN"

	export _H1="Content-Type: application/json"
	export _H2="Authorization: Bearer $OPENPROVIDER_TOKEN"

	if [ "$method" != "GET" ]; then
		_debug data "$data"
		response="$(_post "$data" "$OPENPROVIDER_API/$endpoint" "" "$method" | tr -d '\t\r\n ')"
	else
		response="$(_get "$OPENPROVIDER_API/$endpoint" | tr -d '\t\r\n ')"
	fi

	_debug response "$response"

	if ! _contains "$response" "\"code\":0"; then
		_err "Error $endpoint"
		return 1
	fi

	return 0
}

# Returns:
#  OPENPROVIDER_TOKEN=<sometoken>
_openprovider_login() {
	OPENPROVIDER_USER="${OPENPROVIDER_USER:-$(_readaccountconf_mutable OPENPROVIDER_USER)}"
	OPENPROVIDER_PASSWORD="${OPENPROVIDER_PASSWORD:-$(_readaccountconf_mutable OPENPROVIDER_PASSWORD)}"

	if [ -z "$OPENPROVIDER_USER" ] || [ -z "$OPENPROVIDER_PASSWORD" ]; then
		_err "You didn't specify the openprovider user and/or password."
		return 1
	fi

	_info "Retrieving access token"
	login_data="{\"username\": \"$OPENPROVIDER_USER\", \"password\": \"$OPENPROVIDER_PASSWORD\", \"ip\": \"0.0.0.0\"}"
	response="$(_post "$login_data" "$OPENPROVIDER_API/auth/login" "" "POST" "Content-Type: application/json")"
	_debug response "$response"

	if _contains "$response" "\"token\":\""; then
		OPENPROVIDER_TOKEN=$(echo "$response" | _egrep_o "\"token\":\"[^\"]*\"" | cut -d : -f 2 | tr -d \")
		_debug token "$OPENPROVIDER_TOKEN"
		export OPENPROVIDER_TOKEN

		# save the username and password to the account conf file.
		_saveaccountconf_mutable OPENPROVIDER_USER "$OPENPROVIDER_USER"
		_saveaccountconf_mutable OPENPROVIDER_PASSWORD "$OPENPROVIDER_PASSWORD"
	else
		_err 'Could not get Openprovider access token; check your credentials'
		return 1
	fi
	return 0
}
