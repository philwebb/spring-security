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

import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.RedirectStrategy;

/**
 * @author Joe Grandja
 * @author Kazuki Shimizu
 * @author Phillip Webb
 */
public class Oauth2LoginContributor implements SecurityFilterChainContributor<Oauth2LoginContributor.Configurer> {

	private static final Oauth2LoginContributor INSTANCE = new Oauth2LoginContributor();

	public static Oauth2LoginContributor instance() {
		return INSTANCE;
	}

	private Oauth2LoginContributor() {
	}

	@Override
	public SecurityFilterChainContribution contribute(SecurityFilterChainContributionContext contributionContext,
			Consumer<Configurer> oauth2Login) {
		return SecurityFilterChainContribution.create(Oauth2LoginContribution::new, contributionContext, oauth2Login);
	}

	/**
	 * Callback for configuring a {@link Oauth2LoginContributor}.
	 */
	public interface Configurer extends SecurityFilterChainContributor.Configurer, LoginConfigurer {

		// @formatter:off
		/* FIXME === DESIGN NOTES ===

		Based on org.springframework.security.config.annotation.web.configurers.oauth2.client.
		OAuth2LoginConfigurer<B>

		- Renamed nested Config to Configurer

		*/
		// @formatter:on

		void authorizedClientRepository(OAuth2AuthorizedClientRepository authorizedClientRepository);

		void authorizedClientService(OAuth2AuthorizedClientService authorizedClientService);

		void oidcSessionRegistry(OidcSessionRegistry oidcSessionRegistry);

		AuthorizationEndpointConfigurer authorizationEndpoint();

		void authorizationEndpoint(Consumer<AuthorizationEndpointConfigurer> authorizationEndpoint);

		TokenEndpointConfigurer tokenEndpoint();

		void tokenEndpoint(Consumer<TokenEndpointConfigurer> tokenEndpointCustomizer);

		RedirectionEndpointConfigurer redirectionEndpoint();

		void redirectionEndpoint(Consumer<RedirectionEndpointConfigurer> redirectionEndpoint);

		UserInfoEndpointConfigurer userInfoEndpoint();

		void userInfoEndpoint(Consumer<UserInfoEndpointConfigurer> userInfoEndpoint);

		interface AuthorizationEndpointConfigurer {

			void baseUri(String baseUri);

			void requestResolver(OAuth2AuthorizationRequestResolver authorizationRequestResolver);

			void requestRepository(
					AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository);

			void redirectStrategy(RedirectStrategy authorizationRedirectStrategy);

		}

		interface TokenEndpointConfigurer {

			void accessTokenResponseClient(
					OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient);

		}

		interface RedirectionEndpointConfigurer {

			void baseUri(String baseUri);

		}

		interface UserInfoEndpointConfigurer {

			void userService(OAuth2UserService<OAuth2UserRequest, OAuth2User> userService);

			void oidcUserService(OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService);

			void userAuthoritiesMapper(GrantedAuthoritiesMapper userAuthoritiesMapper);

		}

	}

}
