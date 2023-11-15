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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.authentication.AuthenticationConverter;

/**
 * A {@link SecurityFilterChainContribution} made by the {@link Saml2LoginContributor}.
 *
 * @author Filip Hanik
 * @author Josh Cummings
 * @author Phillip Webb
 * @see Saml2LoginContributor
 */
final class Saml2LoginContribution extends AbstractAuthenticationSecurityFilterChainContribution
		implements Saml2LoginContributor.Configurer {

	Saml2LoginContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void authenticationConverter(AuthenticationConverter authenticationConverter) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authenticationManager(AuthenticationManager authenticationManager) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void relyingPartyRegistrationRepository(RelyingPartyRegistrationRepository repo) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void page(String page) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authenticationRequestResolver(Saml2AuthenticationRequestResolver authenticationRequestResolver) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authenticationRequestUri(String authenticationRequestUri) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
		throw new UnsupportedOperationException();
	}

}
