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
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * @author Rob Winch
 * @author Phillip Webb
 */
abstract class AbstractAuthenticationSecurityFilterChainContribution extends AbstractSecurityFilterChainContribution
		implements LoginConfigurer {

	AbstractAuthenticationSecurityFilterChainContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void successUrl(String successUrl) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void successUrl(String successUrl, boolean alwaysUse) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void successHandler(AuthenticationSuccessHandler successHandler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void processingUrl(String loginProcessingUrl) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void securityContextRepository(SecurityContextRepository securityContextRepository) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void failureUrl(String failureUrl) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void failureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void permitRequests() {
		throw new UnsupportedOperationException();
	}

}
