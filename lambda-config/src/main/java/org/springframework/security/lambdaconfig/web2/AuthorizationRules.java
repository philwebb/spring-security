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

package org.springframework.security.lambdaconfig.web2;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import jakarta.servlet.DispatcherType;

import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author pwebb
 */
public class AuthorizationRules {

	public static final AuthorizationDecision DENY = new AuthorizationDecision(false);

	public static final AuthorizationDecision PERMIT = new AuthorizationDecision(true);

	private String rolePrefix;

	private RoleHierarchy roleHierarchy;

	public Rule permit() {
		return add(PERMIT);
	}

	public Rule permitIfHasRole(String role) {
		return permitIfHasAnyRole(role);
	}

	public Rule permitIfHasAnyRole(String... roles) {
		return check(AuthorityAuthorizationManager.hasAnyRole(this.rolePrefix, roles));
	}

	public Rule permitIfHasAuthority(String authority) {
		return permitIfHasAnyAuthority(authority);
	}

	public Rule permitIfHasAnyAuthority(String... authorities) {
		return check(withRoleHierarchy(AuthorityAuthorizationManager.hasAnyAuthority(authorities)));
	}

	private <T> AuthorityAuthorizationManager<T> withRoleHierarchy(AuthorityAuthorizationManager<T> manager) {
		manager.setRoleHierarchy(this.roleHierarchy);
		return manager;
	}

	public Rule permitIfAuthenticated() {
		return check(AuthenticatedAuthorizationManager.authenticated());
	}

	public Rule permitIfFullyAuthenticated() {
		return check(AuthenticatedAuthorizationManager.fullyAuthenticated());
	}

	public Rule permitIfRemembered() {
		return check(AuthenticatedAuthorizationManager.rememberMe());
	}

	public Rule permitIfAnonymous() {
		return check(AuthenticatedAuthorizationManager.anonymous());
	}

	public Rule deny() {
		return add(DENY);
	}

	public Rule add(AuthorizationDecision decision) {
		return check((authentication, object) -> decision);
	}

	public Rule check(AuthorizationManager<RequestAuthorizationContext> manager) {
		return null;
	}

	public static class Rule {

		private RequestMatcherBuilder builder;

		private static final HttpMethod ANY_METHOD = null;

		public Rule whenMatches(DispatcherType... dispatcherTypes) {
			return whenMatches(ANY_METHOD, dispatcherTypes);
		}

		public Rule whenMatches(@Nullable HttpMethod method, DispatcherType... dispatcherTypes) {
			return whenMatches(Arrays.stream(dispatcherTypes)
				.map((dispatcherType) -> new DispatcherTypeRequestMatcher(dispatcherType, method))
				.toList());
		}

		public Rule whenMatches(RequestMatcher... requestMatchers) {
			return whenMatches(List.of(requestMatchers));
		}

		public Rule whenMatches(String... patterns) {
			return whenMatches(ANY_METHOD, patterns);
		}

		public Rule whenMatches(HttpMethod method, String... patterns) {
			return whenMatches(this.builder.matchers(method, patterns));
		}

		public Rule whenMatches(HttpMethod method) {
			return whenMatches(method, "/**");
		}

		public Rule whenMatches(Collection<? extends RequestMatcher> matchers) {
			return new Rule();
		}

	}

}
