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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.authentication.AuthenticationConverter;

/**
 * @author Filip Hanik
 * @author Josh Cummings
 * @author Phillip Webb
 */
public class Saml2LoginContributor implements SecurityFilterChainContributor<Saml2LoginContributor.Configurer> {

	private static final Saml2LoginContributor INSTANCE = new Saml2LoginContributor();

	public static Saml2LoginContributor instance() {
		return INSTANCE;
	}

	private Saml2LoginContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> saml2Login) {
		return SecurityFilterChainContribution.create(Saml2LoginContribution::new, contributionContext, saml2Login);
	}

	/**
	 * Callback for configuring a {@link Saml2LoginContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer, LoginConfigurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.saml2.
		Saml2LoginConfigurer<B>

		- rename loginPage to page

		*/
		// @formatter:on

		void authenticationConverter(AuthenticationConverter authenticationConverter);

		void authenticationManager(AuthenticationManager authenticationManager);

		void relyingPartyRegistrationRepository(RelyingPartyRegistrationRepository repo);

		void page(String page);

		void authenticationRequestResolver(Saml2AuthenticationRequestResolver authenticationRequestResolver);

		void authenticationRequestUri(String authenticationRequestUri);

	}

}
