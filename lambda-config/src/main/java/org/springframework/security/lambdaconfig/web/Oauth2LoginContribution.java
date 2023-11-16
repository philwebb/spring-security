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

/**
 * A {@link SecurityFilterChainContribution} made by the {@link Oauth2LoginContributor}.
 *
 * @author Joe Grandja
 * @author Parikshit Dutta
 * @author Phillip Webb
 * @see Oauth2LoginContributor
 */
final class Oauth2LoginContribution extends AbstractSecurityFilterChainContribution
		implements Oauth2LoginContributor.Configurer {

	Oauth2LoginContribution(SecurityFilterChainContributionContext contributionContext) {
		super(contributionContext);
	}

	@Override
	public void contribute(SharedObjects sharedObjects, SecurityFilterChainBuilder builder) {
	}

}
