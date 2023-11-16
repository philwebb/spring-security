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

import java.util.function.Consumer;

/**
 * A {@link Contributor} used to contribute configuration to a
 * {@link SecurityFilterChainBuilder}.
 *
 * @param <C> the type of configurer used by the contributor
 * @author Phillip Webb
 */
public interface SecurityFilterChainContributor<C> extends Contributor<C, SecurityFilterChainBuilder> {

	@Override
	SecurityFilterChainContribution contribute(ContributionContext context, Consumer<C> customizer);

	interface Configurer {

		void disable(); // FIXME pull up?

	}

}
