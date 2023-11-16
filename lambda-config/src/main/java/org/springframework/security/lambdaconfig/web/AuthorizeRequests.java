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

import java.util.function.Consumer;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.lambdaconfig.web.AuthorizeRequests.Configurer;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * @author pwebb
 */
public class AuthorizeRequests implements SecurityFilterChainContributor<Configurer> {

	static final AuthorizeRequests instance = new AuthorizeRequests();

	private AuthorizeRequests() {
	}

	@Override
	public SecurityFilterChainContribution contribute(ContributionContext contributionContext,
			Consumer<Configurer> authorizations) {
		return null;
	}

	interface Configurer extends SecurityFilterChainContributor.Configurer {

		RequestMatching permit();

		RequestMatching permitIfHasRole(String role);

		RequestMatching permitIfHasAnyRole(String... roles);

		RequestMatching permitIfHasAuthority(String authority);

		RequestMatching permitIfHasAnyAuthority(String... authorities);

		RequestMatching permitIfAuthenticated();

		RequestMatching permitIfFullyAuthenticated();

		RequestMatching permitIfRemembered();

		RequestMatching permitIfAnonymous();

		RequestMatching deny();

		RequestMatching add(AuthorizationDecision decision);

		RequestMatching check(AuthorizationManager<RequestAuthorizationContext> manager);

		void forServletPath(String servletPath, Consumer<Configurer> servletAuthorizations);

	}

}
