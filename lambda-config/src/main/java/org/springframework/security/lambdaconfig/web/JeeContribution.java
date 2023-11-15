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

import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter;

/**
 * A {@link SecurityFilterChainContribution} made by the {@link JeeContributor}.
 *
 * @author Rob Winch
 * @author Phillip Webb
 * @see JeeContributor
 */
final class JeeContribution extends AbstractSecurityFilterChainContribution implements JeeContributor.Configurer {

	JeeContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void addMappableAuthorities(String... mappableAuthorities) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addMappableRoles(String... mappableRoles) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authenticatedUserDetailsService(
			AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticatedUserDetailsService) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void preAuthenticatedProcessingFilter(
			J2eePreAuthenticatedProcessingFilter preAuthenticatedProcessingFilter) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
		throw new UnsupportedOperationException();
	}

}
