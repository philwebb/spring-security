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

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;

/**
 * @author pwebb
 */
public class NewSecurity extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests = http
				.authorizeRequests();
		ExpressionUrlAuthorizationConfigurer<HttpSecurity>.AuthorizedUrl antMatchers = authorizeRequests.antMatchers("d");
		antMatchers.authenticated();

		antMatchers.access(attribute);

		ExpressionThing request = null;

		request.mustMatch("expression").whenRequestMatchesAntPath("/**")
		antMatchers.anonymous();
		request.mustBeAnonymous().whenMatches(null);
		antMatchers.authenticated();
		request.mustBeAuthenticated().whenMatchesMvcPath("/**");
		antMatchers.denyAll();
		//request.isDenied().when(...)
		antMatchers.fullyAuthenticated();
		request.mustBeFullyAuthenticated().whenMathesAntPath("/**");
		antMatchers.hasAnyAuthority(authorities);
		antMatchers.hasAnyRole(roles);
		request.mustHaveRole();
		antMatchers.hasAuthority(authority)
		antMatchers.hasIpAddress(ipaddressExpression)
		antMatchers.permitAll();
		request.isPermitted()
		// request.isDenied()
		antMatchers.rememberMe();
		request.mustBePreviouslyRemembered().when()




		http.authorizeRequests().antMatchers("/css/**").permitAll().anyRequest()
				.fullyAuthenticated().and().formLogin().loginPage("/login")
				.failureUrl("/login?error").permitAll().and().logout().permitAll();
	}

	void to() {

	}

	public Dunno dunno() {
		// Authorized Requests Using SpEL
		// In order of expressions
		// With shoortcusts

		// ExpressionAuthorization x;
		// // matching pattern, the expression
		// authorizations.add("/**").permitAll();
		// authorizations.add(RequestMatcher.toAntPath("/css/**), Exression.permitAll());
		// authorizations.addAntPath("/**").permitAll();
		// authorizations.add(RequestMatcher.toAnyRequest(), "permitAll");
		// expessionss.permitAll().whenMatchesAntPath("/**")
		// expressions.denyAll().whenMatchesAnyRequest();

		// AuthorizedRequests requests;
		// requests.permitAll().to("/**)
		// requests.matching(RequestMatcher.toAntPath("/css/**"),

		// authorizedRequests
		// .to(RequestMatcher.antPath("/css/**").
	}

}
