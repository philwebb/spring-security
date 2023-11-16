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

	/**
	 * Callback for configuring a {@link HttpSecurityFilterChain}.
	 */
	interface Configurer {

		/**
		 * Configure when the {@link HttpSecurityFilterChain} should be applied.
		 * @return a {@link RequestMatching} instance that can be used to configure when
		 * the chain is applied
		 */
		RequestMatching apply();

		/**
		 * Configure {@link HttpSecurityFilterChain} security headers settings. See
		 * {@link HeadersContributor} for more details.
		 * @param headers the callback used to apply configuration
		 */
		default void headers(Consumer<HeadersContributor.Configurer> headers) {
			configure(HeadersContributor.instance(), headers);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} CORS (Cross-origin resource sharing)
		 * settings. See {@link CorsContributor} for more details.
		 * @param cors the callback used to apply configuration
		 */
		default void cors(Consumer<CorsContributor.Configurer> cors) {
			configure(CorsContributor.instance(), cors);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} session management settings. See
		 * {@link SessionManagementContributor} for more details.
		 * @param sessionManagement the callback used to apply configuration
		 */
		default void sessionManagement(Consumer<SessionManagementContributor.Configurer> sessionManagement) {
			configure(SessionManagementContributor.instance(), sessionManagement);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} port mapper settings. See
		 * {@link PortMapperContributor} for more details.
		 * @param portMapper the callback used to apply configuration
		 */
		default void portMapper(Consumer<PortMapperContributor.Configurer> portMapper) {
			configure(PortMapperContributor.instance(), portMapper);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} JEE settings. See
		 * {@link JeeContributor} for more details.
		 * @param jee the callback used to apply configuration
		 */
		default void jee(Consumer<JeeContributor.Configurer> jee) {
			configure(JeeContributor.instance(), jee);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} X509 settings. See
		 * {@link X509Contributor} for more details.
		 * @param x509 the callback used to apply configuration
		 */
		default void x509(Consumer<X509Contributor.Configurer> x509) {
			configure(X509Contributor.instance(), x509);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} "remember me" settings. See
		 * {@link RememberMeContributor} for more details.
		 * @param rememberMe the callback used to apply configuration
		 */
		default void rememberMe(Consumer<RememberMeContributor.Configurer> rememberMe) {
			configure(RememberMeContributor.instance(), rememberMe);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} authorize requests settings. See
		 * {@link AuthorizeRequestsContributor} for more details.
		 * @param authorizeRequests the callback used to apply configuration
		 */
		default void authorizeRequests(Consumer<AuthorizeRequestsContributor.Configurer> authorizeRequests) {
			configure(AuthorizeRequestsContributor.instance(), authorizeRequests);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} authorize requests settings for a
		 * specific servlet path. Using this method is equivalent to calling
		 * {@link AuthorizeRequestsContributor.Configurer#forServletPath(String, Consumer)}
		 * from {@link #authorizeRequests(Consumer)} but removes the need for nested
		 * lambdas. See {@link AuthorizeRequestsContributor} for more details.
		 * @param servletPath the servlet path to configure
		 * @param servletAuthorizeRequests the callback used to apply configuration
		 */
		default void authorizeRequestsForServletPath(String servletPath,
				Consumer<AuthorizeRequestsContributor.Configurer> servletAuthorizeRequests) {
			authorizeRequests((authorizations) -> authorizations.forServletPath(servletPath, servletAuthorizeRequests));
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} request cache settings. See
		 * {@link RequestCacheContributor} for more details.
		 * @param requestCache the callback used to apply configuration
		 */
		default void requestCache(Consumer<RequestCacheContributor.Configurer> requestCache) {
			configure(RequestCacheContributor.instance(), requestCache);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} exception handling settings. See
		 * {@link ExceptionHandlingContributor} for more details.
		 * @param exceptionHandling the callback used to apply configuration
		 */
		default void exceptionHandling(Consumer<ExceptionHandlingContributor.Configurer> exceptionHandling) {
			configure(ExceptionHandlingContributor.instance(), exceptionHandling);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} security context settings. See
		 * {@link SecurityContextContributor} for more details.
		 * @param securityContext the callback used to apply configuration
		 */
		default void securityContext(Consumer<SecurityContextContributor.Configurer> securityContext) {
			configure(SecurityContextContributor.instance(), securityContext);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} servlet API settings. See
		 * {@link ServletApiContributor} for more details.
		 * @param servletApi the callback used to apply configuration
		 */
		default void servletApi(Consumer<ServletApiContributor.Configurer> servletApi) {
			configure(ServletApiContributor.instance(), servletApi);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} CSRF (Cross-Site Request Forgery)
		 * settings. See {@link CsrfContributor} for more details.
		 * @param csrf the callback used to apply configuration
		 */
		default void csrf(Consumer<CsrfContributor.Configurer> csrf) {
			configure(CsrfContributor.instance(), csrf);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} logout settings. See
		 * {@link LogoutContributor} for more details.
		 * @param logout the callback used to apply configuration
		 */
		default void logout(Consumer<LogoutContributor.Configurer> logout) {
			configure(LogoutContributor.instance(), logout);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} anonymous settings. See
		 * {@link AnonymousContributor} for more details.
		 * @param anonymous the callback used to apply configuration
		 */
		default void anonymous(Consumer<AnonymousContributor.Configurer> anonymous) {
			configure(AnonymousContributor.instance(), anonymous);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} form login settings. See
		 * {@link FormLoginContributor} for more details.
		 * @param formLogin the callback used to apply configuration
		 */
		default void formLogin(Consumer<FormLoginContributor.Configurer> formLogin) {
			configure(FormLoginContributor.instance(), formLogin);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} SAML 2.0 (Security Assertion Markup
		 * Language) login settings. See {@link Saml2LoginContributor} for more details.
		 * @param saml2Login the callback used to apply configuration
		 */
		default void saml2Login(Consumer<Saml2LoginContributor.Configurer> saml2Login) {
			configure(Saml2LoginContributor.instance(), saml2Login);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} SAML 2.0 (Security Assertion Markup
		 * Language) logout settings. See {@link Saml2LogoutContributor} for more details.
		 * @param saml2Logout the callback used to apply configuration
		 */
		default void saml2Logout(Consumer<Saml2LogoutContributor.Configurer> saml2Logout) {
			configure(Saml2LogoutContributor.instance(), saml2Logout);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} SAML 2.0 (Security Assertion Markup
		 * Language) metadata settings. See {@link Saml2MetadataContributor} for more
		 * details.
		 * @param saml2Metadata the callback used to apply configuration
		 */
		default void saml2Metadata(Consumer<Saml2MetadataContributor.Configurer> saml2Metadata) {
			configure(Saml2MetadataContributor.instance(), saml2Metadata);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} OAuth 2.0 (Open Authorization)
		 * metadata settings. See {@link Oauth2LoginContributor} for more details.
		 * @param oauth2Login the callback used to apply configuration
		 */
		default void oauth2Login(Consumer<Oauth2LoginContributor.Configurer> oauth2Login) {
			configure(Oauth2LoginContributor.instance(), oauth2Login);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} OICD (OpenID Connect) logout
		 * settings. See {@link OidcLogoutContributor} for more details.
		 * @param oidcLogout the callback used to apply configuration
		 */
		default void oidcLogout(Consumer<OidcLogoutContributor.Configurer> oidcLogout) {
			configure(OidcLogoutContributor.instance(), oidcLogout);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} OAuth 2.0 (Open Authorization) client
		 * settings. See {@link Oauth2ClientContributor} for more details.
		 * @param oauth2Client the callback used to apply configuration
		 */
		default void oauth2Client(Consumer<Oauth2ClientContributor.Configurer> oauth2Client) {
			configure(Oauth2ClientContributor.instance(), oauth2Client);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} OAuth 2.0 (Open Authorization)
		 * resource server settings. See {@link Oauth2ClientContributor} for more details.
		 * @param oauth2ResourceServer the callback used to apply configuration
		 */
		default void oauth2ResourceServer(Consumer<Oauth2ResourceServerContributor.Configurer> oauth2ResourceServer) {
			configure(Oauth2ResourceServerContributor.instance(), oauth2ResourceServer);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} "requires channel" settings. See
		 * {@link RequiresChannelContributor} for more details.
		 * @param requiresChannel the callback used to apply configuration
		 */
		default void requiresChannel(Consumer<RequiresChannelContributor.Configurer> requiresChannel) {
			configure(RequiresChannelContributor.instance(), requiresChannel);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} HTTP basic settings. See
		 * {@link HttpBasicContributor} for more details.
		 * @param httpBasic the callback used to apply configuration
		 */
		default void httpBasic(Consumer<HttpBasicContributor.Configurer> httpBasic) {
			configure(HttpBasicContributor.instance(), httpBasic);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} password management settings. See
		 * {@link PasswordManagementContributor} for more details.
		 * @param passwordManagement the callback used to apply configuration
		 */
		default void passwordManagement(Consumer<PasswordManagementContributor.Configurer> passwordManagement) {
			configure(PasswordManagementContributor.instance(), passwordManagement);
		}

		/**
		 * Configure {@link HttpSecurityFilterChain} settings for a given
		 * {@link SecurityFilterChainContributor}, adding it if necessary.
		 * @param <C> the type of configurer
		 * @param contributor the contributor to configure and possibly add
		 * @param cutomizer the callback used to apply configuration
		 */
		<C> void configure(SecurityFilterChainContributor<C> contributor, Consumer<C> cutomizer);

	}

}
