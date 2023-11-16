/*
 * Copyright 2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.lambdaconfig.web;

import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * @author pwebb
 */
public interface XRequestAuthorizations {

	// FIXME for servlet path

	AuthorizationDecision DENY = new AuthorizationDecision(false);

	AuthorizationDecision PERMIT = new AuthorizationDecision(true);

	default RequestMatching permit() {
		return add(PERMIT);
	}

	default RequestMatching permitIfHasRole(String role) {
		return permitIfHasAnyRole(role);
	}

	RequestMatching permitIfHasAnyRole(String... roles);

	default RequestMatching permitIfHasAuthority(String authority) {
		return permitIfHasAnyAuthority(authority);
	}

	RequestMatching permitIfHasAnyAuthority(String... authorities);

	default RequestMatching permitIfAuthenticated() {
		return check(AuthenticatedAuthorizationManager.authenticated());
	}

	default RequestMatching permitIfFullyAuthenticated() {
		return check(AuthenticatedAuthorizationManager.fullyAuthenticated());
	}

	default RequestMatching permitIfRemembered() {
		return check(AuthenticatedAuthorizationManager.rememberMe());
	}

	default RequestMatching permitIfAnonymous() {
		return check(AuthenticatedAuthorizationManager.anonymous());
	}

	default RequestMatching deny() {
		return add(DENY);
	}

	default RequestMatching add(AuthorizationDecision decision) {
		return check((authentication, object) -> decision);
	}

	default RequestMatching check(AuthorizationManager<RequestAuthorizationContext> manager) {
		return null;
	}

}
