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

import org.springframework.lang.Nullable;

/**
 * Contributes customizable configuration to a {@link HttpSecurityFilterChain}.
 *
 * @author Phillip Webb
 * @param <C> the configurer used to customize configuration
 */
public interface SecurityFilterChainContributor<C> {

	// FIXME We could generalize this if needed. The original config modules has lots of
	// SecurityConfigurer instances

	// FIXME The original gets passed HttpSercurityBuilder and get get other configureres

	/**
	 * Return the contribution to be applied to the {@link HttpSecurityFilterChain}.
	 * @param contributionContext the contribution context
	 * @param customizer a callback used to customize the contribution
	 * @return a new {@link SecurityFilterChainContribution}
	 */
	SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			@Nullable Consumer<C> customizer);

	/**
	 * Base interface recommended for contributors.
	 */
	interface Configurer {

		/**
		 * Disable configuration from this contributor.
		 */
		void disable();

	}

}
