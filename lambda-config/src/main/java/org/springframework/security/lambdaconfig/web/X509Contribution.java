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

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

/**
 * A {@link SecurityFilterChainContribution} made by the {@link X509Contributor}.
 *
 * @author Rob Winch
 * @author Phillip Webb
 * @see X509Contributor
 */
final class X509Contribution extends AbstractSecurityFilterChainContribution implements X509Contributor.Configurer {

	X509Contribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void authenticationFilter(X509AuthenticationFilter authenticationFilter) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void principalExtractor(X509PrincipalExtractor principalExtractor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void principalExtractor(String principalExtractorRegex) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails> authenticationDetailsSource) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void userDetailsService(UserDetailsService userDetailsService) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void userDetailsService(
			AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> userDetailsService) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
		throw new UnsupportedOperationException();
	}

}
