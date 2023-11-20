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

import java.util.Collection;
import java.util.function.Consumer;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.lambdaconfig.web.AuthorizationRulesContributor.Configurer;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * A {@link SecurityFilterChainContribution} made by the
 * {@link AuthorizationRulesContributor}.
 *
 * @author Evgeniy Cheban
 * @author Phillip Webb
 * @see AuthorizationRulesContributor
 */
final class AuthorizeRequestsContribution extends AbstractSecurityFilterChainContribution
		implements AuthorizationRulesContributor.Configurer {

	AuthorizationDecision DENY = new AuthorizationDecision(false);

	AuthorizationDecision PERMIT = new AuthorizationDecision(true);

	AuthorizeRequestsContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public Configurer ifMatches(Patterns patterns) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Configurer ifMatches(Collection<? extends RequestMatcher> matchers) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Configurer ignoring(Patterns patterns) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Configurer ignoring(Collection<? extends RequestMatcher> matchers) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void thenReturnPermitted() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void thenReturnDenied() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void thenReturn(AuthorizationDecision decision) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void thenReturnChecking(AuthorizationManager<RequestAuthorizationContext> authorizationManager) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CheckingConfigurer thenReturnChecking() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void forServletPath(String servletPath, Consumer<Configurer> servletAuthorizeRequests) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
		throw new UnsupportedOperationException();
	}

}
