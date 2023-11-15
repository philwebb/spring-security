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
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * @author Evgeniy Cheban
 * @author Phillip Webb
 */
public class AuthorizeRequestsContributor
		implements SecurityFilterChainContributor<AuthorizeRequestsContributor.Configurer> {

	private static final AuthorizeRequestsContributor INSTANCE = new AuthorizeRequestsContributor();

	public static AuthorizeRequestsContributor instance() {
		return INSTANCE;
	}

	private AuthorizeRequestsContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> authorizations) {
		return SecurityFilterChainContribution.create(AuthorizeRequestsContribution::new, contributionContext,
				authorizations);
	}

	/**
	 * Callback for configuring an {@link AuthorizeRequestsContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.
		AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry<H>

		All method calls are additive but naming them addPermitIf... feels a bit clunky

		There's scope to add permitIf methods that take a Predicate

		// AuthorizationDecision could offer PERMIT / DENY constants to use with add(..)

		// ferServletPath should be reviewed

		*/
		// @formatter:on

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

		void forServletPath(String servletPath, Consumer<Configurer> servletAuthorizeRequests);

	}

}
