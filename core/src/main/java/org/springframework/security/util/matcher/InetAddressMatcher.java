/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.util.matcher;

import java.net.InetAddress;
import java.util.Collection;

import org.jspecify.annotations.Nullable;

import org.springframework.util.Assert;

/**
 * Matches an {@link InetAddress}.
 *
 * @author Rossen Stoyanchev
 * @author Rob Winch
 * @author Phillip Webb
 * @since 7.1
 */
@FunctionalInterface
public interface InetAddressMatcher {

	/**
	 * Whether the given address matches.
	 * @param address the {@link InetAddress} to check (may be {@code null})
	 * @return {@code true} if the address matches, {@code false} otherwise
	 */
	boolean matches(@Nullable InetAddress address);

	/**
	 * Whether the given address string matches.
	 * @param address the IP address string to check (may be {@code null})
	 * @return {@code true} if the address matches, {@code false} otherwise
	 */
	default boolean matches(@Nullable String address) {
		return (address != null) ? matches(InetAddressParser.parseAddress(address)) : false;
	}

	/**
	 * Returns a new matcher that represents the logical negation of this matcher.
	 * @return the negated matcher
	 */
	default InetAddressMatcher negate() {
		return new NegatedInetAddressMatcher(this);
	}

	/**
	 * Return an {@link IncludeExcludeInetAddressMatcher} configured to include all
	 * addresses.
	 * @return an {@link IncludeExcludeInetAddressMatcher} configured to include the given
	 * matchers
	 */
	static IncludeExcludeInetAddressMatcher all() {
		return of((address) -> true);
	}

	/**
	 * Return an {@link IncludeExcludeInetAddressMatcher} configured to match external
	 * (non-private) IP addresses.
	 * @return an {@link IncludeExcludeInetAddressMatcher} configured to match internal
	 * addresses
	 * @see #ofInternalAddresses()
	 */
	static IncludeExcludeInetAddressMatcher ofExternalAddresses() {
		return of(ExternalInetAddressMatcher.instance);
	}

	/**
	 * Return an {@link IncludeExcludeInetAddressMatcher} configured to match internal
	 * (private) IP addresses.
	 * <p>
	 * Internal addresses include loopback addresses ({@code 127.0.0.0/8} for IPv4,
	 * {@code ::1} for IPv6), private IPv4 address ranges ({@code 10.0.0.0/8},
	 * {@code 172.16.0.0/12}, {@code 192.168.0.0/16}), and IPv6 Unique Local Addresses
	 * ({@code fc00::/7}).
	 * @return an {@link IncludeExcludeInetAddressMatcher} configured to match internal
	 * addresses
	 * @see #ofExternalAddresses()
	 */
	static IncludeExcludeInetAddressMatcher ofInternalAddresses() {
		return of(InternalInetAddressMatcher.instance);
	}

	/**
	 * Return an {@link IncludeExcludeInetAddressMatcher} configured to match the given IP
	 * addresses.
	 * @param addresses the IP addresses to match. Each element mat be a specific IP
	 * address, or a subnet specified using CIDR notation (e.g., {@code 192.168.1.0/24})
	 * @return an {@link IncludeExcludeInetAddressMatcher} configured to match the given
	 * addresses
	 */
	static IncludeExcludeInetAddressMatcher of(String... addresses) {
		return of().including(addresses);
	}

	/**
	 * Return an {@link IncludeExcludeInetAddressMatcher} configured to include the given
	 * matchers.
	 * @param matchers the matchers to include
	 * @return an {@link IncludeExcludeInetAddressMatcher} configured to include the given
	 * matchers
	 */
	static IncludeExcludeInetAddressMatcher of(InetAddressMatcher... matchers) {
		return of().including(matchers);
	}

	/**
	 * Return an {@link IncludeExcludeInetAddressMatcher} configured to include the given
	 * matchers.
	 * @param matchers the matchers to include
	 * @return an {@link IncludeExcludeInetAddressMatcher} configured to include the given
	 * matchers
	 */
	static IncludeExcludeInetAddressMatcher of(Collection<? extends InetAddressMatcher> matchers) {
		return of().including(matchers);
	}

	/**
	 * Return an {@link IncludeExcludeInetAddressMatcher} configured to include the given
	 * matchers.
	 * @param matchers the matchers to include
	 * @return an {@link IncludeExcludeInetAddressMatcher} configured to include the given
	 * matchers
	 */
	static IncludeExcludeInetAddressMatcher of() {
		return IncludeExcludeInetAddressMatcher.instance;
	}

	/**
	 * Returns a matcher that is the negation of the supplied matcher.
	 * @param matcher the matcher to negate
	 * @return the negated matcher
	 * @see #negate()
	 */
	static InetAddressMatcher not(InetAddressMatcher matcher) {
		Assert.notNull(matcher, "'matcher' must not ne null");
		return matcher.negate();
	}

}
