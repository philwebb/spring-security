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
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * A {@link SecurityFilterChainContribution} made by the {@link HttpBasicContributor}.
 *
 * @author Rob Winch
 * @author Evgeniy Cheban
 * @author Phillip Webb
 * @see HttpBasicContributor
 */
final class HttpBasicContribution extends AbstractSecurityFilterChainContribution
		implements HttpBasicContributor.Configurer {

	HttpBasicContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void realmName(String realmName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void securityContextRepository(SecurityContextRepository securityContextRepository) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
		throw new UnsupportedOperationException();
	}

}
