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

import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.session.InvalidSessionStrategy;

/**
 * A {@link SecurityFilterChainContribution} made by the
 * {@link SessionManagementContributor}.
 *
 * @author Rob Winch
 * @author Onur Kagan Ozcan
 * @author Phillip Webb
 * @see SessionManagementContributor
 */
final class SessionManagementContribution extends AbstractSecurityFilterChainContribution
		implements SessionManagementContributor.Configurer {

	SessionManagementContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void requireExplicitAuthenticationStrategy(boolean requireExplicitAuthenticationStrategy) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void invalidSessionUrl(String invalidSessionUrl) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void invalidSessionStrategy(InvalidSessionStrategy invalidSessionStrategy) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authenticationErrorUrl(String sessionAuthenticationErrorUrl) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void authenticationFailureHandler(AuthenticationFailureHandler sessionAuthenticationFailureHandler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void enableUrlRewriting() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void policy(Policy policy) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addAuthenticationStrategy(SessionAuthenticationStrategy authenticationStrategy) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void fixation(Fixation fixation) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ConcurrencyControlConfigurer concurrency() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void concurrency(Consumer<ConcurrencyControlConfigurer> concurrency) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
		throw new UnsupportedOperationException();
	}

}
