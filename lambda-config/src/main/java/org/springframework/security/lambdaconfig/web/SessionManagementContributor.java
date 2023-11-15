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

import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

/**
 * @author Rob Winch
 * @author Onur Kagan Ozcan
 * @author Phillip Webb
 */
public class SessionManagementContributor
		implements SecurityFilterChainContributor<SessionManagementContributor.Configurer> {

	private static final SessionManagementContributor INSTANCE = new SessionManagementContributor();

	public static SessionManagementContributor instance() {
		return INSTANCE;
	}

	private SessionManagementContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> sessionManagement) {
		return SecurityFilterChainContribution.create(SessionManagementContribution::new, contributionContext,
				sessionManagement);
	}

	/**
	 * Callback for configuring a {@link SessionManagementContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.
		SessionManagementConfigurer<H>

		- Rename SessionCreationPolicy to SessionPolicy and rename enums
		- Rename sessionCreationPolicy to policy (think it's not just related to creation)
		- Rename sessionFixation to fixation and make it an enum
		- Rename expiredSessionStrategy to expiredStrategy
		- Rename maxSessionsPreventsLogin to maximumSessionsPreventsLogin (align with maximumSessions)
		- Drop session from method names (except invalidSession because that reads weird)
		- Drop maximumSessions(int maximumSessions) from main configurer (now only via ConcurrencyControlConfigurer)
		- Drop authenticationStrategy in favor of using a single call to addAuthenticationStrategy
		  (need to review getSessionAuthenticationStrategy to see if this is actually possible)
		- Add concurrency shortcut
		- Remove boolean from enableSessionUrlRewriting since default is false

		*/
		// @formatter:on

		void requireExplicitAuthenticationStrategy(boolean requireExplicitAuthenticationStrategy);

		void invalidSessionUrl(String invalidSessionUrl);

		void invalidSessionStrategy(InvalidSessionStrategy invalidSessionStrategy);

		void authenticationErrorUrl(String sessionAuthenticationErrorUrl);

		void authenticationFailureHandler(AuthenticationFailureHandler sessionAuthenticationFailureHandler);

		void enableUrlRewriting();

		void policy(Policy policy);

		void addAuthenticationStrategy(SessionAuthenticationStrategy authenticationStrategy);

		void fixation(Fixation fixation);

		ConcurrencyControlConfigurer concurrency();

		void concurrency(Consumer<ConcurrencyControlConfigurer> concurrency);

		interface ConcurrencyControlConfigurer {

			void maximumSessions(int maximumSessions);

			void expiredUrl(String expiredUrl);

			void expiredStrategy(SessionInformationExpiredStrategy expiredSessionStrategy);

			void maximumSessionsPreventsLogin(boolean maxSessionsPreventsLogin);

			void sessionRegistry(SessionRegistry sessionRegistry);

		}

		enum Policy {

			CREATE, CREATE_IF_REQUIRED, USE_EXISTING, DISABLE

		}

		enum Fixation {

			NEW, MIGRATED, CHANGE_ID, NONE

		}

	}

}
