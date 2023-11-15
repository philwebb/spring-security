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
public class AuthorizationRulesContributor
		implements SecurityFilterChainContributor<AuthorizationRulesContributor.Configurer> {

	private static final AuthorizationRulesContributor INSTANCE = new AuthorizationRulesContributor();

	public static AuthorizationRulesContributor instance() {
		return INSTANCE;
	}

	private AuthorizationRulesContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> authorizations) {
		return SecurityFilterChainContribution.create(AuthorizationRulesContribution::new, contributionContext,
				authorizations);
	}

	/**
	 * Callback for configuring an {@link AuthorizationRulesContributor}.
	 */
	public interface Configurer
			extends SecurityFilterChainContributor.Configurer, RequestMatchable<RequestMatchableReturns> {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.
		AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry<H>

		There's scope to add permitIf methods that take a Predicate

		// AuthorizationDecision could offer PERMIT / DENY constants to use with add(..)

		// ferServletPath should be reviewed

		*/
		// @formatter:on

		Returns ifAnyRequest();

		void forServletPath(String servletPath, Consumer<Configurer> servletAuthorizeRequests);

	}

	public interface RequestMatchableReturns extends RequestMatchable<RequestMatchableReturns>, Returns {

	}

	public interface Returns {

		void thenReturnPermitted();

		void thenReturnDenied();

		void thenReturnDecision(AuthorizationDecision decision);

		void thenReturnChecking(AuthorizationManager<RequestAuthorizationContext> authorizationManager);

		Checking thenReturnChecking();

	}

	public interface Checking {

		Checking hasRole(String role);

		Checking hasAnyRole(String... roles);

		Checking hasAuthority(String authority);

		Checking hasAnyAuthority(String... authorities);

		Checking isAuthenticated();

		Checking isFullyAuthenticated();

		Checking isRemembered();

		Checking isAnonymous();

	}

}
