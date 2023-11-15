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

import java.time.Duration;
import java.util.function.Consumer;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy;
import org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

/**
 * @author Rob Winch
 * @author Tim Ysewyn
 * @author Joe Grandja
 * @author Eddú Meléndez
 * @author Vedran Pavic
 * @author Ankur Pathak
 * @author Daniel Garnier-Moiroux
 * @author Phillip Webb
 */
public class HeadersContributor implements SecurityFilterChainContributor<HeadersContributor.Configurer> {

	private static final HeadersContributor INSTANCE = new HeadersContributor();

	public static HeadersContributor instance() {
		return INSTANCE;
	}

	private HeadersContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> headers) {
		return SecurityFilterChainContribution.create(HeadersContribution::new, contributionContext, headers);
	}

	/**
	 * Callback for configuring a {@link HeadersContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.
		HeadersConfigurer<H>

		- defaultsDisabled renamed to disableAll
		- drop nested enable() methods in favor of just calling the method (as done on HttpServletFilterChain)
		- Nested *Config classes renamed to *Configurer and made interfaces
		- maxAgeInSeconds changed to duration
		- HttpStrictTransportSecurityConfigurer uses apply() rather than request matcher
		- Drop "policy" from some method names since it's not just the policy

		- Seems like the original doesn't offer a way to just disable ContentSecurityPolicyConfig but I think it should

		*/
		// @formatter:on

		void disableAll();

		void addHeaderWriter(HeaderWriter headerWriter);

		ContentTypeOptionsConfigurer contentTypeOptions();

		void contentTypeOptions(Consumer<ContentTypeOptionsConfigurer> contentTypeOptions);

		XssProtectionConfigurer xssProtection();

		void xssProtection(Consumer<XssProtectionConfigurer> xss);

		CacheControlConfigurer cacheControl();

		void cacheControl(Consumer<CacheControlConfigurer> xss);

		HttpStrictTransportSecurityConfigurer httpStrictTransportSecurity();

		void httpStrictTransportSecurity(Consumer<HttpStrictTransportSecurityConfigurer> hsts);

		FrameOptionsConfigurer frameOptions();

		void frameOptions(Consumer<FrameOptionsConfigurer> frameOptions);

		ContentSecurityConfigurer contentSecurity();

		void contentSecurity(Consumer<ContentSecurityConfigurer> contentSecurityPolicy);

		ReferrerConfigurer referrer();

		void referrer(Consumer<ReferrerConfigurer> referrerPolicy);

		PermissionsConfigurer permissions();

		void permissions(Consumer<PermissionsConfigurer> permissionsPolicy);

		CrossOriginOpenerConfigurer crossOriginOpener();

		void crossOriginOpener(Consumer<CrossOriginOpenerConfigurer> crossOriginOpenerPolicy);

		CrossOriginEmbedderConfigurer crossOriginEmbedder();

		void crossOriginEmbedder(Consumer<CrossOriginEmbedderConfigurer> crossOriginEmbedderPolicy);

		CrossOriginResourceConfigurer crossOriginResource();

		void crossOriginResource(Consumer<CrossOriginResourceConfigurer> crossOriginResourcePolicy);

		interface HeadersConfigurer {

			void disable();

		}

		interface ContentTypeOptionsConfigurer extends HeadersConfigurer {

		}

		interface XssProtectionConfigurer extends HeadersConfigurer {

			void headerValue(XXssProtectionHeaderWriter.HeaderValue headerValue);

		}

		interface CacheControlConfigurer extends HeadersConfigurer {

		}

		interface HttpStrictTransportSecurityConfigurer extends HeadersConfigurer {

			void preload(boolean preload);

			void maxAge(Duration maxAge);

			RequestMatching apply();

			void includeSubDomains(boolean includeSubDomains);

		}

		interface FrameOptionsConfigurer extends HeadersConfigurer {

			void sameOrigin();

		}

		interface ContentSecurityConfigurer extends HeadersConfigurer {

			void policyDirectives(String policyDirectives);

			void reportOnly();

		}

		interface HeadersPolicyConfigurer<P> extends HeadersConfigurer {

			void policy(P policy);

		}

		interface ReferrerConfigurer extends HeadersPolicyConfigurer<ReferrerPolicy> {

		}

		interface PermissionsConfigurer extends HeadersPolicyConfigurer<String> {

		}

		interface CrossOriginOpenerConfigurer extends HeadersPolicyConfigurer<CrossOriginOpenerPolicy> {

		}

		interface CrossOriginEmbedderConfigurer extends HeadersPolicyConfigurer<CrossOriginEmbedderPolicy> {

		}

		interface CrossOriginResourceConfigurer extends HeadersPolicyConfigurer<CrossOriginResourcePolicy> {

		}

	}

}
