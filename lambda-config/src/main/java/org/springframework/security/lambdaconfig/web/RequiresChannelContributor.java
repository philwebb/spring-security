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

import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.channel.ChannelProcessor;

/**
 * @author Rob Winch
 * @author Onur Kagan Ozcan
 * @author Phillip Webb
 */
public class RequiresChannelContributor
		implements SecurityFilterChainContributor<RequiresChannelContributor.Configurer> {

	private static final RequiresChannelContributor INSTANCE = new RequiresChannelContributor();

	public static RequiresChannelContributor instance() {
		return INSTANCE;
	}

	private RequiresChannelContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> requiresChannel) {
		return SecurityFilterChainContribution.create(RequiresChannelContribution::new, contributionContext,
				requiresChannel);
	}

	/**
	 * Callback for configuring a {@link RequiresChannelContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.
		ChannelSecurityConfigurer<H>.ChannelRequestMatcherRegistry
		and AbstractConfigAttributeRequestMatcherRegistry
		and AbstractRequestMatcherRegistry

		- Do we want addChannelProcessors?

		*/
		// @formatter:on

		void channelProcessors(List<ChannelProcessor> channelProcessors);

		void redirectStrategy(RedirectStrategy redirectStrategy);

		RequestMatching accept();

	}

}
