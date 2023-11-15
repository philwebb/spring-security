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

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

/**
 * A {@link SecurityFilterChainContribution} made by the {@link RememberMeContributor}.
 *
 * @author Rob Winch
 * @author Eddú Meléndez
 * @author Phillip Webb
 * @see RememberMeContributor
 */
final class RememberMeContribution extends AbstractSecurityFilterChainContribution
		implements RememberMeContributor.Configurer {

	RememberMeContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void key(String key) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void tokenValidity(Duration tokenValidity) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void userDetailsService(UserDetailsService userDetailsService) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void tokenRepository(PersistentTokenRepository tokenRepository) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void parameter(String parameter) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void useSecureCookie(boolean useSecureCookie) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void cookieName(String cookieName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void cookieDomain(String cookieDomain) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void services(RememberMeServices rememberMeServices) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void alwaysRemember(boolean alwaysRemember) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
		throw new UnsupportedOperationException();
	}

}
