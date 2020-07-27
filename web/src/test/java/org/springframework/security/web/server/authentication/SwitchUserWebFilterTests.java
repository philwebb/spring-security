/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.web.server.authentication;

import java.security.Principal;
import java.util.Collections;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.core.context.ReactiveSecurityContextHolder.withSecurityContext;
import static org.springframework.security.web.server.authentication.SwitchUserWebFilter.ROLE_PREVIOUS_ADMINISTRATOR;

/**
 * @author Artur Otrzonsek
 */
@RunWith(MockitoJUnitRunner.class)
public class SwitchUserWebFilterTests {

	private SwitchUserWebFilter switchUserWebFilter;

	@Mock
	private ReactiveUserDetailsService userDetailsService;

	@Mock
	ServerAuthenticationSuccessHandler successHandler;

	@Mock
	private ServerAuthenticationFailureHandler failureHandler;

	@Mock
	private ServerSecurityContextRepository serverSecurityContextRepository;

	@Rule
	public ExpectedException exceptionRule = ExpectedException.none();

	@Before
	public void setUp() {
		this.switchUserWebFilter = new SwitchUserWebFilter(this.userDetailsService, this.successHandler,
				this.failureHandler);
		this.switchUserWebFilter.setSecurityContextRepository(this.serverSecurityContextRepository);
	}

	@Test
	public void switchUserWhenRequestNotMatchThenDoesNothing() {
		// given
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/not/existing"));

		WebFilterChain chain = mock(WebFilterChain.class);
		when(chain.filter(exchange)).thenReturn(Mono.empty());

		// when
		this.switchUserWebFilter.filter(exchange, chain).block();
		// then
		verifyNoInteractions(this.userDetailsService);
		verifyNoInteractions(this.successHandler);
		verifyNoInteractions(this.failureHandler);
		verifyNoInteractions(this.serverSecurityContextRepository);

		verify(chain).filter(exchange);
	}

	@Test
	public void switchUser() {
		// given
		final String targetUsername = "TEST_USERNAME";
		final UserDetails switchUserDetails = switchUserDetails(targetUsername, true);

		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate?username={targetUser}", targetUsername));

		final WebFilterChain chain = mock(WebFilterChain.class);

		final Authentication originalAuthentication = new UsernamePasswordAuthenticationToken("principal",
				"credentials");
		final SecurityContextImpl securityContext = new SecurityContextImpl(originalAuthentication);

		when(this.userDetailsService.findByUsername(targetUsername)).thenReturn(Mono.just(switchUserDetails));
		when(this.serverSecurityContextRepository.save(eq(exchange), any(SecurityContext.class)))
				.thenReturn(Mono.empty());
		when(this.successHandler.onAuthenticationSuccess(any(WebFilterExchange.class), any(Authentication.class)))
				.thenReturn(Mono.empty());

		// when
		this.switchUserWebFilter.filter(exchange, chain)
				.subscriberContext(withSecurityContext(Mono.just(securityContext))).block();

		// then
		verifyNoInteractions(chain);
		verify(this.userDetailsService).findByUsername(targetUsername);

		final ArgumentCaptor<SecurityContext> securityContextCaptor = ArgumentCaptor.forClass(SecurityContext.class);
		verify(this.serverSecurityContextRepository).save(eq(exchange), securityContextCaptor.capture());
		final SecurityContext savedSecurityContext = securityContextCaptor.getValue();

		final ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(this.successHandler).onAuthenticationSuccess(any(WebFilterExchange.class),
				authenticationCaptor.capture());

		final Authentication switchUserAuthentication = authenticationCaptor.getValue();

		assertSame(savedSecurityContext.getAuthentication(), switchUserAuthentication);

		assertEquals("username should point to the switched user", targetUsername, switchUserAuthentication.getName());
		assertTrue("switchAuthentication should contain SwitchUserGrantedAuthority", switchUserAuthentication
				.getAuthorities().stream().anyMatch(a -> a instanceof SwitchUserGrantedAuthority));
		assertTrue("new authentication should get new role ", switchUserAuthentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority).anyMatch(a -> a.equals(ROLE_PREVIOUS_ADMINISTRATOR)));
		assertEquals("SwitchUserGrantedAuthority should contain the original authentication",
				originalAuthentication.getName(),
				switchUserAuthentication.getAuthorities().stream().filter(a -> a instanceof SwitchUserGrantedAuthority)
						.map(a -> ((SwitchUserGrantedAuthority) a).getSource()).map(Principal::getName).findFirst()
						.orElse(null));
	}

	@Test
	public void switchUserWhenUserAlreadySwitchedThenExitSwitchAndSwitchAgain() {
		// given
		final Authentication originalAuthentication = new UsernamePasswordAuthenticationToken("origPrincipal",
				"origCredentials");

		final GrantedAuthority switchAuthority = new SwitchUserGrantedAuthority(ROLE_PREVIOUS_ADMINISTRATOR,
				originalAuthentication);
		final Authentication switchUserAuthentication = new UsernamePasswordAuthenticationToken("switchPrincipal",
				"switchCredentials", Collections.singleton(switchAuthority));

		final SecurityContextImpl securityContext = new SecurityContextImpl(switchUserAuthentication);

		final String targetUsername = "newSwitchPrincipal";
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate?username={targetUser}", targetUsername));

		final WebFilterChain chain = mock(WebFilterChain.class);

		when(this.serverSecurityContextRepository.save(eq(exchange), any(SecurityContext.class)))
				.thenReturn(Mono.empty());
		when(this.successHandler.onAuthenticationSuccess(any(WebFilterExchange.class), any(Authentication.class)))
				.thenReturn(Mono.empty());
		when(this.userDetailsService.findByUsername(targetUsername))
				.thenReturn(Mono.just(switchUserDetails(targetUsername, true)));

		// when
		this.switchUserWebFilter.filter(exchange, chain)
				.subscriberContext(withSecurityContext(Mono.just(securityContext))).block();

		// then
		final ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(this.successHandler).onAuthenticationSuccess(any(WebFilterExchange.class),
				authenticationCaptor.capture());

		final Authentication secondSwitchUserAuthentication = authenticationCaptor.getValue();

		assertEquals("username should point to the switched user", targetUsername,
				secondSwitchUserAuthentication.getName());
		assertEquals("SwitchUserGrantedAuthority should contain the original authentication",
				originalAuthentication.getName(),
				secondSwitchUserAuthentication.getAuthorities().stream()
						.filter(a -> a instanceof SwitchUserGrantedAuthority)
						.map(a -> ((SwitchUserGrantedAuthority) a).getSource()).map(Principal::getName).findFirst()
						.orElse(null));
	}

	@Test
	public void switchUserWhenUsernameIsMissingThenThrowException() {
		// given
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate"));

		final WebFilterChain chain = mock(WebFilterChain.class);
		final SecurityContextImpl securityContext = new SecurityContextImpl(mock(Authentication.class));

		this.exceptionRule.expect(IllegalArgumentException.class);
		this.exceptionRule.expectMessage("The userName can not be null.");

		// when
		this.switchUserWebFilter.filter(exchange, chain)
				.subscriberContext(withSecurityContext(Mono.just(securityContext))).block();
		verifyNoInteractions(chain);
	}

	@Test
	public void switchUserWhenExceptionThenCallFailureHandler() {
		final String targetUsername = "TEST_USERNAME";
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate?username={targetUser}", targetUsername));

		final WebFilterChain chain = mock(WebFilterChain.class);
		final SecurityContextImpl securityContext = new SecurityContextImpl(mock(Authentication.class));

		final UserDetails switchUserDetails = switchUserDetails(targetUsername, false);
		when(this.userDetailsService.findByUsername(any(String.class))).thenReturn(Mono.just(switchUserDetails));
		when(this.failureHandler.onAuthenticationFailure(any(WebFilterExchange.class), any(DisabledException.class)))
				.thenReturn(Mono.empty());

		// when
		this.switchUserWebFilter.filter(exchange, chain)
				.subscriberContext(withSecurityContext(Mono.just(securityContext))).block();

		verify(this.failureHandler).onAuthenticationFailure(any(WebFilterExchange.class), any(DisabledException.class));
		verifyNoInteractions(chain);
	}

	@Test
	public void switchUserWhenFailureHandlerNotDefinedThenReturnError() {
		// given
		this.switchUserWebFilter = new SwitchUserWebFilter(this.userDetailsService, this.successHandler, null);

		final String targetUsername = "TEST_USERNAME";
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate?username={targetUser}", targetUsername));

		final WebFilterChain chain = mock(WebFilterChain.class);
		final SecurityContextImpl securityContext = new SecurityContextImpl(mock(Authentication.class));

		final UserDetails switchUserDetails = switchUserDetails(targetUsername, false);
		when(this.userDetailsService.findByUsername(any(String.class))).thenReturn(Mono.just(switchUserDetails));

		this.exceptionRule.expect(DisabledException.class);

		// when then
		this.switchUserWebFilter.filter(exchange, chain)
				.subscriberContext(withSecurityContext(Mono.just(securityContext))).block();
		verifyNoInteractions(chain);
	}

	@Test
	public void exitSwitchThenReturnToOriginalAuthentication() {
		// given
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/logout/impersonate"));

		final Authentication originalAuthentication = new UsernamePasswordAuthenticationToken("origPrincipal",
				"origCredentials");

		final GrantedAuthority switchAuthority = new SwitchUserGrantedAuthority(ROLE_PREVIOUS_ADMINISTRATOR,
				originalAuthentication);
		final Authentication switchUserAuthentication = new UsernamePasswordAuthenticationToken("switchPrincipal",
				"switchCredentials", Collections.singleton(switchAuthority));

		final WebFilterChain chain = mock(WebFilterChain.class);
		final SecurityContextImpl securityContext = new SecurityContextImpl(switchUserAuthentication);

		when(this.serverSecurityContextRepository.save(eq(exchange), any(SecurityContext.class)))
				.thenReturn(Mono.empty());
		when(this.successHandler.onAuthenticationSuccess(any(WebFilterExchange.class), any(Authentication.class)))
				.thenReturn(Mono.empty());

		// when
		this.switchUserWebFilter.filter(exchange, chain)
				.subscriberContext(withSecurityContext(Mono.just(securityContext))).block();

		// then
		final ArgumentCaptor<SecurityContext> securityContextCaptor = ArgumentCaptor.forClass(SecurityContext.class);
		verify(this.serverSecurityContextRepository).save(eq(exchange), securityContextCaptor.capture());
		final SecurityContext savedSecurityContext = securityContextCaptor.getValue();

		final ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(this.successHandler).onAuthenticationSuccess(any(WebFilterExchange.class),
				authenticationCaptor.capture());

		final Authentication originalAuthenticationValue = authenticationCaptor.getValue();

		assertSame(originalAuthentication, savedSecurityContext.getAuthentication());
		assertSame(originalAuthentication, originalAuthenticationValue);
		verifyNoInteractions(chain);
	}

	@Test
	public void exitSwitchWhenUserNotSwitchedThenThrowError() {
		// given
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/logout/impersonate"));

		final Authentication originalAuthentication = new UsernamePasswordAuthenticationToken("origPrincipal",
				"origCredentials");

		final WebFilterChain chain = mock(WebFilterChain.class);
		final SecurityContextImpl securityContext = new SecurityContextImpl(originalAuthentication);

		this.exceptionRule.expect(AuthenticationCredentialsNotFoundException.class);
		this.exceptionRule.expectMessage("Could not find original Authentication object");

		// when then
		this.switchUserWebFilter.filter(exchange, chain)
				.subscriberContext(withSecurityContext(Mono.just(securityContext))).block();
		verifyNoInteractions(chain);
	}

	@Test
	public void exitSwitchWhenNoCurrentUserThenThrowError() {
		// given
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/logout/impersonate"));

		final WebFilterChain chain = mock(WebFilterChain.class);

		this.exceptionRule.expect(AuthenticationCredentialsNotFoundException.class);
		this.exceptionRule.expectMessage("No current user associated with this request");

		// when
		this.switchUserWebFilter.filter(exchange, chain).block();
		// then
		verifyNoInteractions(chain);
	}

	@Test
	public void constructorUserDetailsServiceRequired() {
		// given
		this.exceptionRule.expect(IllegalArgumentException.class);
		this.exceptionRule.expectMessage("userDetailsService must be specified");

		// when
		this.switchUserWebFilter = new SwitchUserWebFilter(null, mock(ServerAuthenticationSuccessHandler.class),
				mock(ServerAuthenticationFailureHandler.class));
	}

	@Test
	public void constructorServerAuthenticationSuccessHandlerRequired() {
		// given
		this.exceptionRule.expect(IllegalArgumentException.class);
		this.exceptionRule.expectMessage("successHandler must be specified");
		// when
		this.switchUserWebFilter = new SwitchUserWebFilter(mock(ReactiveUserDetailsService.class), null,
				mock(ServerAuthenticationFailureHandler.class));
	}

	@Test
	public void constructorSuccessTargetUrlRequired() {
		// given
		this.exceptionRule.expect(IllegalArgumentException.class);
		this.exceptionRule.expectMessage("successTargetUrl must be specified");
		// when
		this.switchUserWebFilter = new SwitchUserWebFilter(mock(ReactiveUserDetailsService.class), null,
				"failure/target/url");
	}

	@Test
	public void constructorFirstDefaultValues() {
		// when
		this.switchUserWebFilter = new SwitchUserWebFilter(mock(ReactiveUserDetailsService.class),
				mock(ServerAuthenticationSuccessHandler.class), mock(ServerAuthenticationFailureHandler.class));

		// then
		final Object securityContextRepository = ReflectionTestUtils.getField(this.switchUserWebFilter,
				"securityContextRepository");
		assertTrue(securityContextRepository instanceof WebSessionServerSecurityContextRepository);

		final Object userDetailsChecker = ReflectionTestUtils.getField(this.switchUserWebFilter, "userDetailsChecker");
		assertTrue(userDetailsChecker instanceof AccountStatusUserDetailsChecker);
	}

	@Test
	public void constructorSecondDefaultValues() {
		// when
		this.switchUserWebFilter = new SwitchUserWebFilter(mock(ReactiveUserDetailsService.class), "success/target/url",
				"failure/target/url");

		// then
		final Object successHandler = ReflectionTestUtils.getField(this.switchUserWebFilter, "successHandler");
		assertTrue(successHandler instanceof RedirectServerAuthenticationSuccessHandler);

		final Object failureHandler = ReflectionTestUtils.getField(this.switchUserWebFilter, "failureHandler");
		assertTrue(failureHandler instanceof RedirectServerAuthenticationFailureHandler);

		final Object securityContextRepository = ReflectionTestUtils.getField(this.switchUserWebFilter,
				"securityContextRepository");
		assertTrue(securityContextRepository instanceof WebSessionServerSecurityContextRepository);

		final Object userDetailsChecker = ReflectionTestUtils.getField(this.switchUserWebFilter, "userDetailsChecker");
		assertTrue(userDetailsChecker instanceof AccountStatusUserDetailsChecker);
	}

	@Test
	public void setSecurityContextRepositoryWhenNullThenThrowException() {
		// given
		this.exceptionRule.expect(IllegalArgumentException.class);
		this.exceptionRule.expectMessage("securityContextRepository cannot be null");
		// when
		this.switchUserWebFilter.setSecurityContextRepository(null);
		// then
		fail("Test should fail with exception");
	}

	@Test
	public void setSecurityContextRepositoryWhenDefinedThenChangeDefaultValue() {
		// given
		final Object oldSecurityContextRepository = ReflectionTestUtils.getField(this.switchUserWebFilter,
				"securityContextRepository");
		assertSame(this.serverSecurityContextRepository, oldSecurityContextRepository);

		final ServerSecurityContextRepository newSecurityContextRepository = mock(
				ServerSecurityContextRepository.class);
		// when
		this.switchUserWebFilter.setSecurityContextRepository(newSecurityContextRepository);
		// then
		final Object currentSecurityContextRepository = ReflectionTestUtils.getField(this.switchUserWebFilter,
				"securityContextRepository");
		assertSame(newSecurityContextRepository, currentSecurityContextRepository);
	}

	@Test
	public void setExitUserUrlWhenNullThenThrowException() {
		// given
		this.exceptionRule.expect(IllegalArgumentException.class);
		this.exceptionRule.expectMessage("exitUserUrl cannot be empty and must be a valid redirect URL");
		// when
		this.switchUserWebFilter.setExitUserUrl(null);
		// then
		fail("Test should fail with exception");
	}

	@Test
	public void setExitUserUrlWhenInvalidUrlThenThrowException() {
		// given
		this.exceptionRule.expect(IllegalArgumentException.class);
		this.exceptionRule.expectMessage("exitUserUrl cannot be empty and must be a valid redirect URL");
		// when
		this.switchUserWebFilter.setExitUserUrl("wrongUrl");
		// then
		fail("Test should fail with exception");
	}

	@Test
	public void setExitUserUrlWhenDefinedThenChangeDefaultValue() {
		// given
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/logout/impersonate"));

		final ServerWebExchangeMatcher oldExitUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "exitUserMatcher");

		assertThat(oldExitUserMatcher.matches(exchange).block().isMatch()).isTrue();

		// when
		this.switchUserWebFilter.setExitUserUrl("/exit-url");

		// then
		final MockServerWebExchange newExchange = MockServerWebExchange.from(MockServerHttpRequest.post("/exit-url"));

		final ServerWebExchangeMatcher newExitUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "exitUserMatcher");

		assertThat(newExitUserMatcher.matches(newExchange).block().isMatch()).isTrue();
	}

	@Test
	public void setExitUserMatcherWhenNullThenThrowException() {
		// given
		this.exceptionRule.expect(IllegalArgumentException.class);
		this.exceptionRule.expectMessage("exitUserMatcher cannot be null");
		// when
		this.switchUserWebFilter.setExitUserMatcher(null);
		// then
		fail("Test should fail with exception");
	}

	@Test
	public void setExitUserMatcherWhenDefinedThenChangeDefaultValue() {
		// given
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/logout/impersonate"));

		final ServerWebExchangeMatcher oldExitUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "exitUserMatcher");

		assertThat(oldExitUserMatcher.matches(exchange).block().isMatch()).isTrue();

		final ServerWebExchangeMatcher newExitUserMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST,
				"/exit-url");

		// when
		this.switchUserWebFilter.setExitUserMatcher(newExitUserMatcher);

		// then

		final ServerWebExchangeMatcher currentExitUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "exitUserMatcher");

		assertSame(newExitUserMatcher, currentExitUserMatcher);
	}

	@Test
	public void setSwitchUserUrlWhenNullThenThrowException() {
		// given
		this.exceptionRule.expect(IllegalArgumentException.class);
		this.exceptionRule.expectMessage("switchUserUrl cannot be empty and must be a valid redirect URL");
		// when
		this.switchUserWebFilter.setSwitchUserUrl(null);
		// then
		fail("Test should fail with exception");
	}

	@Test
	public void setSwitchUserUrlWhenInvalidThenThrowException() {
		// given
		this.exceptionRule.expect(IllegalArgumentException.class);
		this.exceptionRule.expectMessage("switchUserUrl cannot be empty and must be a valid redirect URL");
		// when
		this.switchUserWebFilter.setSwitchUserUrl("wrongUrl");
		// then
		fail("Test should fail with exception");
	}

	@Test
	public void setSwitchUserUrlWhenDefinedThenChangeDefaultValue() {
		// given
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate"));

		final ServerWebExchangeMatcher oldSwitchUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "switchUserMatcher");

		assertThat(oldSwitchUserMatcher.matches(exchange).block().isMatch()).isTrue();

		// when
		this.switchUserWebFilter.setSwitchUserUrl("/switch-url");

		// then
		final MockServerWebExchange newExchange = MockServerWebExchange.from(MockServerHttpRequest.post("/switch-url"));

		final ServerWebExchangeMatcher newSwitchUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "switchUserMatcher");

		assertThat(newSwitchUserMatcher.matches(newExchange).block().isMatch()).isTrue();
	}

	@Test
	public void setSwitchUserMatcherWhenNullThenThrowException() {
		// given
		this.exceptionRule.expect(IllegalArgumentException.class);
		this.exceptionRule.expectMessage("switchUserMatcher cannot be null");
		// when
		this.switchUserWebFilter.setSwitchUserMatcher(null);
		// then
		fail("Test should fail with exception");
	}

	@Test
	public void setSwitchUserMatcherWhenDefinedThenChangeDefaultValue() {
		// given
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate"));

		final ServerWebExchangeMatcher oldSwitchUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "switchUserMatcher");

		assertThat(oldSwitchUserMatcher.matches(exchange).block().isMatch()).isTrue();

		final ServerWebExchangeMatcher newSwitchUserMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST,
				"/switch-url");

		// when
		this.switchUserWebFilter.setSwitchUserMatcher(newSwitchUserMatcher);

		// then

		final ServerWebExchangeMatcher currentExitUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "switchUserMatcher");

		assertSame(newSwitchUserMatcher, currentExitUserMatcher);
	}

	private UserDetails switchUserDetails(String username, boolean enabled) {
		final SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_SWITCH_TEST");
		return new User(username, "NA", enabled, true, true, true, Collections.singleton(authority));
	}

}