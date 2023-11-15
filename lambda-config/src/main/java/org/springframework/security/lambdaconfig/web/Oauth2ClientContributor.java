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

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.RedirectStrategy;

/**
 * @author Joe Grandja
 * @author Parikshit Dutta
 * @author Phillip Webb
 */
public class Oauth2ClientContributor implements SecurityFilterChainContributor<Oauth2ClientContributor.Configurer> {

	private static final Oauth2ClientContributor INSTANCE = new Oauth2ClientContributor();

	public static Oauth2ClientContributor instance() {
		return INSTANCE;
	}

	private Oauth2ClientContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> oauth2Client) {
		return SecurityFilterChainContribution.create(Oauth2ClientContribution::new, contributionContext, oauth2Client);
	}

	/**
	 * Callback for configuring a {@link Oauth2ClientContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.oauth2.client.
		OAuth2ClientConfigurer<B>

		- Renamed a few methods in AuthorizationCodeGrantConfigurer

		*/
		// @formatter:on

		void clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository);

		void authorizedClientRepository(OAuth2AuthorizedClientRepository authorizedClientRepository);

		void authorizedClientService(OAuth2AuthorizedClientService authorizedClientService);

		AuthorizationCodeGrantConfigurer authorizationCodeGrant();

		void authorizationCodeGrant(Consumer<AuthorizationCodeGrantConfigurer> authorizationCodeGrantCustomizer);

		interface AuthorizationCodeGrantConfigurer {

			void requestResolver(OAuth2AuthorizationRequestResolver authorizationRequestResolver);

			void requestRepository(
					AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository);

			void redirectStrategy(RedirectStrategy authorizationRedirectStrategy);

			void accessTokenResponseClient(
					OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient);

		}

	}

}
