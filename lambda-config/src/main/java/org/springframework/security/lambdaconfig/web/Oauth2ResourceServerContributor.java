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

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

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
			Consumer<Configurer> oauth2ResourceServer) {
		return SecurityFilterChainContribution.create(Oauth2ResourceServerContribution::new, contributionContext,
				oauth2ResourceServer);
	}

	public interface Configurer extends SecurityFilterChainContributor.Configurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.
		OAuth2ResourceServerConfigurer<H>

		*/
		// @formatter:on

		void accessDeniedHandler(AccessDeniedHandler accessDeniedHandler);

		void authenticationEntryPoint(AuthenticationEntryPoint entryPoint);

		void authenticationManagerResolver(
				AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver);

		void bearerTokenResolver(BearerTokenResolver bearerTokenResolver);

		JwtConfigurer jwt();

		void jwt(Consumer<JwtConfigurer> jwtCustomizer);

		OpaqueTokenConfigurer opaqueToken();

		void opaqueToken(Consumer<OpaqueTokenConfigurer> opaqueTokenCustomizer);

		interface JwtConfigurer {

			void authenticationManager(AuthenticationManager authenticationManager);

			void decoder(JwtDecoder decoder);

			void jwkSetUri(String uri);

			void authenticationConverter(
					Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter);

		}

		interface OpaqueTokenConfigurer {

			void authenticationManager(AuthenticationManager authenticationManager);

			void introspectionUri(String introspectionUri);

			void introspectionClientCredentials(String clientId, String clientSecret);

			void introspector(OpaqueTokenIntrospector introspector);

			void authenticationConverter(OpaqueTokenAuthenticationConverter authenticationConverter);

		}

	}

}
