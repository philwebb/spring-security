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

import java.util.List;
import java.util.function.Consumer;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

/**
 * @author Rob Winch
 * @author Phillip Webb
 */
public class AnonymousContributor implements SecurityFilterChainContributor<AnonymousContributor.Configurer> {

	private static final AnonymousContributor INSTANCE = new AnonymousContributor();

	public static AnonymousContributor instance() {
		return INSTANCE;
	}

	private AnonymousContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> anonymous) {
		return SecurityFilterChainContribution.create(AnonymousContribution::new, contributionContext, anonymous);
	}

	/**
	 * Callback for configuring an {@link AnonymousContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.
		AnonymousConfigurer<H>

		We need to decide if methods like authorities can be called multiple times

		authenticationProvider and authenticationFilter should have javadoc that sates
		which attributes are ignored. For authenticationProvider it's key. For
		authenticationFilter it's key, principal and authorities. We could even
		fail hard if the user has set those attributes

		*/
		// @formatter:on

		void key(String key);

		void principal(Object principal);

		void addAuthorities(List<GrantedAuthority> authorities);

		void addAuthorities(String... authorities);

		void authenticationProvider(AuthenticationProvider authenticationProvider);

		void authenticationFilter(AnonymousAuthenticationFilter authenticationFilter);

	}

}
