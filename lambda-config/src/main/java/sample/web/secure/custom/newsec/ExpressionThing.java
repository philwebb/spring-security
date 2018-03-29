/*
 * Copyright 2012-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample.web.secure.custom.newsec;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author pwebb
 */
public class ExpressionThing {

	// Like ExpressionUrlAuthorizationConfigurer

	public MoreThing mustHaveRole(String role) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	public MoreThing mustNotHaveRole(String role) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	public MoreThing mustHaveAtLeastOneRoleFrom(String... roles) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	public MoreThing mustNotHaveAnyRoleFrom(String... roles) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	public MoreThing mustHaveAuthority(String authority) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	public MoreThing mustNotHaveAuthority(String authority) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	public MoreThing mustHaveAtLeastOneAuthorityFrom(String... authorities) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	public MoreThing mustNotHaveAnyAuthorityFrom(String... authorities) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	public MoreThing mustHaveIpAddress(String addressExpression) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	public MoreThing mustNotHaveIpAddress(String addressExpression) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	public MoreThing mustBeAnonymous() {
		return mustMatch("anonymous");
	}

	public MoreThing mustNotBeAnonymous() {
		return mustMatch("anonymous");
	}

	public MoreThing mustBeRemembered() {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	public MoreThing mustNotBeRemembered() {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	public MoreThing mustBeAuthenticated() {
		return mustMatch("authenticated");
	}

	public MoreThing mustNotBeAuthenticated() {
		return mustMatch("authenticated");
	}

	public MoreThing mustBeAuthenticatedAndNotRemembered() {
		return mustMatch("authenticated");
	}

	public MoreThing isPermitted() {
		return mustMatch("permitAll");
	}

	public MoreThing isDenied() {
		return mustMatch("denyAll");
	}

	public MoreThing mustMatch(String expression) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	public MoreThing mustNotMatch(String expression) {
		throw new UnsupportedOperationException("Auto-generated method stub");
	}

	// Somehow ultimately get a LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>

	public static class MoreThing {

		private static final RequestMatcher ALWAYS = (request) -> true;

		private RequestMatcher requestMatcher = ALWAYS;

		public MoreThing(String expression) {
		}

		public void whenMatchesAntPattern(String... antPaths) {
		}

		public void whenMatchesMvcPattern(String... mvcPatterns) {
		}

		public void whenMatchesMvcPattern(HttpMethod method, String... mvcPatterns) {
		}

		public void whenMatches(RequestMatcher matcher) {
			throw new UnsupportedOperationException("Auto-generated method stub");
		}

	}

}
