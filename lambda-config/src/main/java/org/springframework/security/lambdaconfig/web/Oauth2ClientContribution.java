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
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * A {@link SecurityFilterChainContribution} made by the {@link Oauth2ClientContributor}.
 *
 * @author Joe Grandja
 * @author Parikshit Dutta
 * @author Phillip Webb
 * @see Oauth2ClientContributor
 */
final class Oauth2ClientContribution extends AbstractSecurityFilterChainContribution
		implements Oauth2ClientContributor.Configurer {

	Oauth2ClientContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authorizedClientRepository(OAuth2AuthorizedClientRepository authorizedClientRepository) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authorizedClientService(OAuth2AuthorizedClientService authorizedClientService) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AuthorizationCodeGrantConfigurer authorizationCodeGrant() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authorizationCodeGrant(Consumer<AuthorizationCodeGrantConfigurer> authorizationCodeGrantCustomizer) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
		throw new UnsupportedOperationException();
	}

}
