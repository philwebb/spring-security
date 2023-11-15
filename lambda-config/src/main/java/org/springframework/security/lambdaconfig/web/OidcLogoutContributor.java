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

import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * @author Josh Cummings
 * @author Phillip Webb
 */
public class OidcLogoutContributor implements SecurityFilterChainContributor<OidcLogoutContributor.Configurer> {

	private static final OidcLogoutContributor INSTANCE = new OidcLogoutContributor();

	public static OidcLogoutContributor instance() {
		return INSTANCE;
	}

	private OidcLogoutContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> oidcLogout) {
		return SecurityFilterChainContribution.create(OidcLogoutContribution::new, contributionContext, oidcLogout);
	}

	/**
	 * Callback for configuring a {@link OidcLogoutContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.oauth2.client.
		OidcLogoutConfigurer<B>

		- oidcSessionRegistry renamed to sessionRegistry
		- Drop BackChannelLogoutConfigurer since it does nothing. Can be added later if needed

		*/
		// @formatter:on

		void clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository);

		void sessionRegistry(OidcSessionRegistry sessionRegistry);

		void backChannel();

	}

}
