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

/**
 * @author Josh Cummings
 * @author Evgeniy Cheban
 * @author Jerome Wacongne
 * @author Phillip Webb
 */
public class Oauth2ResourceServerContributor
		implements SecurityFilterChainContributor<Oauth2ResourceServerContributor.Configurer> {

	private static final Oauth2ResourceServerContributor INSTANCE = new Oauth2ResourceServerContributor();

	public static Oauth2ResourceServerContributor instance() {
		return INSTANCE;
	}

	private Oauth2ResourceServerContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> csrf) {
		return null;
	}

	public interface Configurer extends SecurityFilterChainContributor.Configurer {

	}

}
