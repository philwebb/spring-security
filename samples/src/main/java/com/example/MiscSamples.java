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

package com.example;

import jakarta.servlet.DispatcherType;

import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.lambdaconfig.web.HttpSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;

public class MiscSamples {

	// @formatter:off
	/* https://github.com/Kehrlann/spring-security-workshop-code/blob/main/src/main/java/wf/garnier/devoxx/SecurityConfig.java
	 *
			return http.authenticationProvider(new DanielAuthenticationProvider())
						.authorizeRequests()
						.antMatchers("/").permitAll()
						.antMatchers("/error").permitAll()
						.antMatchers("/favicon.ico").permitAll()
						.anyRequest().authenticated()
					.and().httpBasic()
					.and().formLogin()
					.and().oauth2Login()
						.withObjectPostProcessor(new RateLimiteAuthenticationProviderProcessor<>(OidcAuthorizationCodeAuthenticationProvider.class))
					.and().apply(new RobotAccountConfigurer())
						.password("beep-boop")
						.password("boop-beep")
					.and()
					.build();
					*/
			// @formatter:on

	HttpSecurityFilterChain workshop() {
		return HttpSecurityFilterChain.of((chain) -> {
			// We don't yet have authentication provider
			chain.authorizationRules((authorizationRules) -> {
				authorizationRules.ifMatches("/", "/error", "favicon.ico").thenReturnPermitted();
				authorizationRules.ifAnyRequest().thenReturnChecking().isAuthenticated();

			});
			chain.httpBasic();
			chain.formLogin();
			chain.oauth2Login((oauth2Login) -> {
				// We don't have ObjectPostProcessor support yet
			});
			// chain.configure(null, null) This would be be the configurer equiv. Might
			// need to make it easy
		});
	}

	// @formatter:off
	/* Spring Boot smoke test

	 		@Bean
		SecurityFilterChain configure(HttpSecurity http) throws Exception {
			http.csrf((csrf) -> csrf.disable());
			http.authorizeHttpRequests((requests) -> {
				requests.dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll();
				requests.anyRequest().fullyAuthenticated();
			});
			http.formLogin((form) -> form.loginPage("/login").permitAll());
			return http.build();
		}

		*/
		// @formatter:on

	HttpSecurityFilterChain springBootSmokeTest() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.csrf().disable();
			chain.authorizationRules((authorizationRules) -> {
				authorizationRules.ifMatches(DispatcherType.FORWARD).thenReturnPermitted();
				authorizationRules.ifAnyRequest().thenReturnChecking().isFullyAuthenticated();
			});
			chain.formLogin((formLogin) -> {
				formLogin.page("/login");
				formLogin.permitRequests();
			});
		});
	}

	// https://github.com/rwinch/spring-security-6-next-generation/blob/main/src/main/java/example/spring/SecurityConfig.java
	// @formatter:off
	/*

	DefaultSecurityFilterChain springSecurity(HttpSecurity http, OpaAuthorizationManager opa) throws Exception {
		XorCsrfTokenRequestAttributeHandler requestHandler = new XorCsrfTokenRequestAttributeHandler();
		// set the name of the attribute the CsrfToken will be populated on
		requestHandler.setCsrfRequestAttributeName("_csrf");
		http
			.csrf(csrf -> csrf
				.csrfTokenRequestHandler(requestHandler)
			)
			.authorizeHttpRequests(requests -> requests
				.anyRequest().access(opa)
			)
			.formLogin(withDefaults())
			.httpBasic(withDefaults());
		return http.build();
	}

	*/
	// @formatter:on

	SecurityFilterChain springSecurity(AuthorizationManager<RequestAuthorizationContext> opa) {
		XorCsrfTokenRequestAttributeHandler requestHandler = new XorCsrfTokenRequestAttributeHandler();
		requestHandler.setCsrfRequestAttributeName("_csrf");
		return HttpSecurityFilterChain.of((chain) -> {
			chain.csrf().tokenRequestHandler(requestHandler);
			chain.authorizationRules().ifAnyRequest().thenReturnChecking(opa);
			chain.formLogin();
			chain.httpBasic();
		});
	}

	// https://stackoverflow.com/questions/33739359/combining-basic-authentication-and-form-login-for-the-same-rest-api
	// @formatter:off
	/*

 @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/js/**", "/css/**")
                .permitAll();

        http
                .authorizeRequests()
                .antMatchers("/api/**")
                .authenticated()
                .and()
                .httpBasic();

        http
                .authorizeRequests()
                .antMatchers("/","/index")
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/j_spring_security_check")
                .defaultSuccessUrl("/monitor")
                .failureUrl("/login?error")
                .usernameParameter("j_username")
                .passwordParameter("j_password")
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/j_spring_security_logout")
                .logoutSuccessUrl("/login?logout")
                .permitAll()
                .and()
                .csrf()
                .disable();
    }

	*/
	// @formatter:on

	SecurityFilterChain stackOverflow() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.authorizationRules((authorizationRules) -> {
				authorizationRules.ifMatches("/js/**", "/css/**").thenReturnPermitted();
				authorizationRules.ifMatches("/api/**").thenReturnChecking().isFullyAuthenticated();
				authorizationRules.ifMatches("/", "/index").thenReturnChecking().isFullyAuthenticated();
			});
			chain.httpBasic();
			chain.formLogin((formLogin) -> {
				formLogin.page("/login");
				formLogin.processingUrl("/j_spring_security_check");
				formLogin.successUrl("/monitor");
				formLogin.failureUrl("/login?error");
				formLogin.usernameParameter("j_username");
				formLogin.passwordParameter("j_password");
				formLogin.permitRequests();
			});
			chain.logout((logout) -> {
				logout.url("/j_spring_security_logout");
				logout.successUrl("/login?logout");
				logout.permitRequests();
			});
			chain.csrf().disable();
		});
	}

	// https://github.com/nebhale/mtls-sample/blob/4e17268fcb5821a8dfc502b0ff724e71a9249344/server/src/main/java/io/pivotal/mtlssample/server/ServerApplication.java#L96C22-L96C22
	// @formatter:off
	/*

 			http
                .x509()
                    .subjectPrincipalRegex("OU=app:(.*?)(?:,|$)")
                    .and()
                .authorizeRequests()
                    .mvcMatchers("/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated();

	*/
	// @formatter:on

	SecurityFilterChain nebhale() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.x509().principalExtractor("OU=app:(.*?)(?:,|$)");
			chain.authorizationRules((authorizationRules) -> {
				authorizationRules.ifMatches("/admin/**").thenReturnChecking().hasRole("ADMIN");
				authorizationRules.ifAnyRequest().thenReturnChecking().isFullyAuthenticated();
			});
		});
	}

	// Shortcuts
	SecurityFilterChain shortcuts() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.authorizationRules().ifAnyRequest().thenReturnChecking().isFullyAuthenticated();
			chain.csrf().disable();
		});
	}

	// https://github.com/spring-projects/spring-security-samples/blob/357d75f63aaea8d7c44e7903bd1c622570a9b725/servlet/spring-boot/java/saml2/saml-extension-federation/src/main/java/example/SecurityConfiguration.java#L47
	SecurityFilterChain saml() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.authorizationRules((authorizationRules) -> {
				authorizationRules.ifMatches("/error").thenReturnPermitted();
				authorizationRules.ifAnyRequest().thenReturnChecking().isFullyAuthenticated();
			});
			chain.saml2Login().processingUrl("/saml/SSO");
			chain.saml2Logout((saml2Logout) -> {
				saml2Logout.request().url("/saml/logout");
				saml2Logout.response().url("/saml/SingleLogout");
			});
			chain.saml2Metadata().url("/saml/metadata");
		});
	}

	// https://github.com/spring-projects/spring-security-samples/blob/357d75f63aaea8d7c44e7903bd1c622570a9b725/servlet/spring-boot/java/oauth2/resource-server/hello-security/src/main/java/example/OAuth2ResourceServerSecurityConfiguration.java#L22
	SecurityFilterChain oauth() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.authorizationRules((authorizationRules) -> {
				authorizationRules.ifMatches(HttpMethod.GET, "/message/**")
					.thenReturnChecking()
					.hasAuthority("SCOPE_message:read");
				authorizationRules.ifMatches(HttpMethod.POST, "/message/**")
					.thenReturnChecking()
					.hasAuthority("SCOPE_message:write");
				authorizationRules.ifAnyRequest().thenReturnChecking().isFullyAuthenticated();
			});
			chain.oauth2ResourceServer().jwt();
		});
	}

	// https://github.com/spring-projects/spring-security-samples/blob/357d75f63aaea8d7c44e7903bd1c622570a9b725/servlet/java-configuration/max-sessions/src/main/java/example/SecurityConfiguration.java#L22
	SecurityFilterChain maxSessions() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.authorizationRules().ifAnyRequest().thenReturnChecking().isFullyAuthenticated();
			chain.formLogin();
			chain.sessionManagement().concurrency((concurrency) -> {
				concurrency.maximumSessions(1);
				concurrency.expiredUrl("/login?expired");
			});
		});
	}

	// https://github.com/spring-projects/spring-security-samples/blob/357d75f63aaea8d7c44e7903bd1c622570a9b725/servlet/spring-boot/java/oauth2/resource-server/opaque/src/main/java/example/OAuth2ResourceServerSecurityConfiguration.java#L22
	SecurityFilterChain oauthOpaque() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.authorizationRules((authorizationRules) -> {
				authorizationRules.ifMatches(HttpMethod.GET, "/message/**")
					.thenReturnChecking()
					.hasAuthority("SCOPE_message:read");
				authorizationRules.ifMatches(HttpMethod.POST, "/message/**")
					.thenReturnChecking()
					.hasAuthority("SCOPE_message:write");
				authorizationRules.ifAnyRequest().thenReturnChecking().isFullyAuthenticated();
			});
			chain.oauth2ResourceServer().opaqueToken((opaqueToken) -> {
				opaqueToken.introspectionUri("foo");
				opaqueToken.introspectionClientCredentials("cid", "shh!");
			});
		});
	}

	// https://www.geeksforgeeks.org/spring-security-project-example-using-java-configuration/#
	SecurityFilterChain geeksforgeeks() {
		return HttpSecurityFilterChain.of((chain) -> {
			chain.authorizationRules((authorizationRules) -> {
				authorizationRules.ifMatches("/basic").thenReturnChecking().hasAnyRole("BASIC", "ADMIN");
				authorizationRules.ifMatches("/admin").thenReturnChecking().hasRole("ADMIN");
				authorizationRules.ifMatches("/").thenReturnPermitted();
				authorizationRules.ifAnyRequest().thenReturnChecking().isAuthenticated();
			});
			chain.formLogin((formLogin) -> {
				formLogin.permitRequests();
				formLogin.page("/login");
				formLogin.usernameParameter("username");
			});
			chain.logout((logout) -> {
				logout.apply().ifMatches("/logout");
				logout.permitRequests();
			});
		});
	}

}
