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

import java.time.Duration;
import java.util.function.Consumer;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

/**
 * @author Rob Winch
 * @author Eddú Meléndez
 * @author Phillip Webb
 */
public class RememberMeContributor implements SecurityFilterChainContributor<RememberMeContributor.Configurer> {

	private static final RememberMeContributor INSTANCE = new RememberMeContributor();

	public static RememberMeContributor instance() {
		return INSTANCE;
	}

	private RememberMeContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> rememberMe) {
		return SecurityFilterChainContribution.create(RememberMeContribution::new, contributionContext, rememberMe);
	}

	/**
	 * Callback for configuring a {@link RememberMeContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.
		RememberMeConfigurer<H>

		- Drop rememberMe prefix from method names
		- Change tokenValiditySeconds to Duration

		*/
		// @formatter:on

		void key(String key);

		void tokenValidity(Duration tokenValidity);

		void userDetailsService(UserDetailsService userDetailsService);

		void tokenRepository(PersistentTokenRepository tokenRepository);

		void parameter(String parameter);

		void useSecureCookie(boolean useSecureCookie);

		void cookieName(String cookieName);

		void cookieDomain(String cookieDomain);

		void authenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler);

		void services(RememberMeServices rememberMeServices);

		void alwaysRemember(boolean alwaysRemember);

	}

}
