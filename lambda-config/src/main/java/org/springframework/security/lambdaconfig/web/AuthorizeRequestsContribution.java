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
import org.springframework.security.lambdaconfig.web.AuthorizeRequestsContributor.Configurer;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * @author Phillip Webb
 */
final class AuthorizeRequestsContribution extends AbstractSecurityFilterChainContribution
		implements AuthorizeRequestsContributor.Configurer {

	AuthorizationDecision DENY = new AuthorizationDecision(false);

	AuthorizationDecision PERMIT = new AuthorizationDecision(true);

	AuthorizeRequestsContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public RequestMatching permit() {
		return add(this.PERMIT);
	}

	@Override
	public RequestMatching permitIfHasRole(String role) {
		return permitIfHasAnyRole(role);
	}

	@Override
	public RequestMatching permitIfHasAnyRole(String... roles) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	@Override
	public RequestMatching permitIfHasAuthority(String authority) {
		return permitIfHasAnyAuthority(authority);
	}

	@Override
	public RequestMatching permitIfHasAnyAuthority(String... authorities) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	@Override
	public RequestMatching permitIfAuthenticated() {
		return check(AuthenticatedAuthorizationManager.authenticated());
	}

	@Override
	public RequestMatching permitIfFullyAuthenticated() {
		return check(AuthenticatedAuthorizationManager.fullyAuthenticated());
	}

	@Override
	public RequestMatching permitIfRemembered() {
		return check(AuthenticatedAuthorizationManager.rememberMe());
	}

	@Override
	public RequestMatching permitIfAnonymous() {
		return check(AuthenticatedAuthorizationManager.anonymous());
	}

	@Override
	public RequestMatching deny() {
		return add(this.DENY);
	}

	@Override
	public RequestMatching add(AuthorizationDecision decision) {
		return check((authentication, object) -> decision);
	}

	@Override
	public RequestMatching check(AuthorizationManager<RequestAuthorizationContext> manager) {
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
