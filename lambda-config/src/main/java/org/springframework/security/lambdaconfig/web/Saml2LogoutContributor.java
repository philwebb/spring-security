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

import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseResolver;

/**
 * @author Josh Cummings
 * @author Phillip Webb
 */
public class Saml2LogoutContributor implements SecurityFilterChainContributor<Saml2LogoutContributor.Configurer> {

	private static final Saml2LogoutContributor INSTANCE = new Saml2LogoutContributor();

	public static Saml2LogoutContributor instance() {
		return INSTANCE;
	}

	private Saml2LogoutContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> saml2Logout) {
		return SecurityFilterChainContribution.create(Saml2LogoutContribution::new, contributionContext, saml2Logout);
	}

	/**
	 * Callback for configuring a {@link Saml2LogoutContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.saml2.
		Saml2LogoutConfigurer<H>

		- rename logoutUrl to url
		- remove logout prefixes
		- remove prefixes from LogoutRequestConfigurer
		- remove prefixes from LogoutResponseConfigurer
		- added overloader request/response with URLs

		*/
		// @formatter:on

		void url(String url);

		void relyingPartyRegistrationRepository(RelyingPartyRegistrationRepository repo);

		LogoutRequestConfigurer request();

		void request(Consumer<LogoutRequestConfigurer> logoutRequest);

		LogoutResponseConfigurer response();

		void response(Consumer<LogoutResponseConfigurer> logoutResponse);

		interface LogoutRequestConfigurer {

			void url(String url);

			void validator(Saml2LogoutRequestValidator authenticator);

			void resolver(Saml2LogoutRequestResolver logoutRequestResolver);

			void repository(Saml2LogoutRequestRepository logoutRequestRepository);

		}

		interface LogoutResponseConfigurer {

			void url(String url);

			void validator(Saml2LogoutResponseValidator authenticator);

			void resolver(Saml2LogoutResponseResolver logoutResponseResolver);

		}

	}

}
