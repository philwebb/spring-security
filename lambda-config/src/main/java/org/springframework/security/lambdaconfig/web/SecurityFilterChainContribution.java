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
import java.util.function.Function;

import org.springframework.lang.Nullable;

/**
 * A contribution to an {@link SecurityFilterChainBuilder}.
 *
 * @author Phillip Webb
 * @see SecurityFilterChainContributor
 */
public interface SecurityFilterChainContribution {

	// FIXME Design note: Similar to
	// org.springframework.security.config.annotation.SecurityConfigurer<O, B>

	/**
	 * Initialize the given {@link SharedObjects} instance with any times that other
	 * contributions may need to access. Initialization of <b>all</b> contributors occurs
	 * before {@link #contribute(SharedObjects, SecurityFilterChainBuilder) contributions}
	 * are accepted.
	 * @param sharedObjects access to the shared objects
	 */
	default void initialize(SharedObjects sharedObjects) {
	}

	/**
	 * Provide the contribution to the given {@link SecurityFilterChainBuilder}.
	 * @param sharedObjects previously {@link #initialize(SharedObjects) initialized}
	 * shared objects
	 * @param builder the security filter chain builder to contribute to
	 */
	void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder);

	/**
	 * Helper method that can be used to create and customize a
	 * {@link SecurityFilterChainContribution}.
	 * @param <C> the configurer type
	 * @param factory factory used to create the contribution
	 * @param contributionContext the contribution context
	 * @param customizer the customizer to apply or {@code null}
	 * @return a new cully customized {@link SecurityFilterChainContribution} instance
	 */
	static <C extends SecurityFilterChainContribution> C create(
			Function<SecurityFilterChainContributionContext, C> factory,
			SecurityFilterChainContributionContext contributionContext, @Nullable Consumer<? super C> customizer) {
		C contribution = factory.apply(contributionContext);
		if (customizer != null) {
			customizer.accept(contribution);
		}
		return contribution;
	}

}
