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

import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Phillip Webb
 */
public interface HttpSecurityFilterChain extends SecurityFilterChain {

	static HttpSecurityFilterChain of(Consumer<Configurer> chain) {
		// create new thing
		// addDefaults();
		// chain.accept(thing)
		// thing.createChain
		return null;
	}

	static HttpSecurityFilterChain empty(Consumer<Configurer> chain) {
		return null;
	}

	interface Configurer {

		RequestMatching apply();

		default void headers(Consumer<HeadersContributor.Configurer> headers) {
			customize(HeadersContributor.instance(), headers);
		}

		default void cors(Consumer<CorsContributor.Configurer> cors) {
			customize(CorsContributor.instance(), cors);
		}

		default void sessionManagement(Consumer<SessionManagementContributor.Configurer> sessionManagement) {
			customize(SessionManagementContributor.instance(), sessionManagement);
		}

		default void portMapper(Consumer<PortMapperContributor.Configurer> portMapper) {
			customize(PortMapperContributor.instance(), portMapper);
		}

		default void jee(Consumer<JeeContributor.Configurer> jee) {
			customize(JeeContributor.instance(), jee);
		}

		default void x509(Consumer<X509Contributor.Configurer> x509) {
			customize(X509Contributor.instance(), x509);
		}

		default void rememberMe(Consumer<RememberMeContributor.Configurer> authorizations) {
			customize(RememberMeContributor.instance(), authorizations);
		}

		default void authorizeRequests(Consumer<AuthorizeRequestsContributor.Configurer> authorizeRequests) {
			customize(AuthorizeRequestsContributor.instance(), authorizeRequests);
		}

		default void authorizeRequestsForServletPath(String servletPath,
				Consumer<AuthorizeRequestsContributor.Configurer> servletAuthorizeRequests) {
			authorizeRequests((authorizations) -> authorizations.forServletPath(servletPath, servletAuthorizeRequests));
		}

		default void requestCache(Consumer<RequestCacheContributor.Configurer> requestCache) {
			customize(RequestCacheContributor.instance(), requestCache);
		}

		default void exceptionHandling(Consumer<ExceptionHandlingContributor.Configurer> exceptionHandling) {
			customize(ExceptionHandlingContributor.instance(), exceptionHandling);
		}

		default void securityContext(Consumer<SecurityContextContributor.Configurer> securityContext) {
			customize(SecurityContextContributor.instance(), securityContext);
		}

		default void servletApi(Consumer<ServletApiContributor.Configurer> servletApi) {
			customize(ServletApiContributor.instance(), servletApi);
		}

		default void csrf(Consumer<CsrfContributor.Configurer> csrf) {
			customize(CsrfContributor.instance(), csrf);
		}

		default void logout(Consumer<LogoutContributor.Configurer> logout) {
			customize(LogoutContributor.instance(), logout);
		}

		default void anonymous(Consumer<AnonymousContributor.Configurer> anonymous) {
			customize(AnonymousContributor.instance(), anonymous);
		}

		default void formLogin(Consumer<FormLoginContributor.Configurer> formLogin) {
			customize(FormLoginContributor.instance(), formLogin);
		}

		default void saml2Login(Consumer<Saml2LoginContributor.Configurer> saml2Login) {
			customize(Saml2LoginContributor.instance(), saml2Login);
		}

		default void saml2Logout(Consumer<Saml2LogoutContributor.Configurer> saml2Logout) {
			customize(Saml2LogoutContributor.instance(), saml2Logout);
		}

		default void saml2Metadata(Consumer<Saml2MetadataContributor.Configurer> saml2Metadata) {
			customize(Saml2MetadataContributor.instance(), saml2Metadata);
		}

		default void oauth2Login(Consumer<Oauth2LoginContributor.Configurer> oauth2Login) {
			customize(Oauth2LoginContributor.instance(), oauth2Login);
		}

		default void oidcLogout(Consumer<OidcLogoutContributor.Configurer> oidcLogout) {
			customize(OidcLogoutContributor.instance(), oidcLogout);
		}

		default void oauth2Client(Consumer<Oauth2ClientContributor.Configurer> oauth2Client) {
			customize(Oauth2ClientContributor.instance(), oauth2Client);
		}

		default void oauth2ResourceServer(Consumer<Oauth2ResourceServerContributor.Configurer> oauth2ResourceServer) {
			customize(Oauth2ResourceServerContributor.instance(), oauth2ResourceServer);
		}

		default void requiresChannel(Consumer<RequiresChannelContributor.Configurer> requiresChannel) {
			customize(RequiresChannelContributor.instance(), requiresChannel);
		}

		default void httpBasic(Consumer<HttpBasicContributor.Configurer> httpBasic) {
			customize(HttpBasicContributor.instance(), httpBasic);
		}

		default void passwordManagement(Consumer<PasswordManagementContributor.Configurer> passwordManagement) {
			customize(PasswordManagementContributor.instance(), passwordManagement);
		}

		<C> void customize(SecurityFilterChainContributor<C> contributor, Consumer<C> cutomizer);

	}

}
