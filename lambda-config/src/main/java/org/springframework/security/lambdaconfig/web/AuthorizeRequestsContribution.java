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

import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.lambdaconfig.web.AuthorizationRulesContributor.Configurer;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

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
	public RequestMatching addThatRequestIsPermitted() {
		return addThatRequestIs(this.PERMIT);
	}

	@Override
	public RequestMatching addThatRequestMustHaveRole(String role) {
		return addThatRequestMustHaveAnyRole(role);
	}

	@Override
	public RequestMatching addThatRequestMustHaveAnyRole(String... roles) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	@Override
	public RequestMatching addThatRequestMustHaveAuthority(String authority) {
		return addThatRequestMustHaveAnyAuthority(authority);
	}

	@Override
	public RequestMatching addThatRequestMustHaveAnyAuthority(String... authorities) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	@Override
	public RequestMatching addThatRequestMustBeAuthenticated() {
		return addThatRequestIsChecked(AuthenticatedAuthorizationManager.authenticated());
	}

	@Override
	public RequestMatching addThatRequestMustBeFullyAuthenticated() {
		return addThatRequestIsChecked(AuthenticatedAuthorizationManager.fullyAuthenticated());
	}

	@Override
	public RequestMatching addThatRequestMustBeRemembered() {
		return addThatRequestIsChecked(AuthenticatedAuthorizationManager.rememberMe());
	}

	@Override
	public RequestMatching addThatRequestMustBeAnonymous() {
		return addThatRequestIsChecked(AuthenticatedAuthorizationManager.anonymous());
	}

	@Override
	public RequestMatching addThatRequestIsDenied() {
		return addThatRequestIs(this.DENY);
	}

	@Override
	public RequestMatching addThatRequestIs(AuthorizationDecision decision) {
		return addThatRequestIsChecked((authentication, object) -> decision);
	}

	@Override
	public RequestMatching addThatRequestIsChecked(AuthorizationManager<RequestAuthorizationContext> manager) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	@Override
	public void forServletPath(String servletPath, Consumer<Configurer> servletAuthorizations) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

}
