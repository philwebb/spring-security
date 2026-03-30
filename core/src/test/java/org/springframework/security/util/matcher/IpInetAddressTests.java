/*
 * Copyright 2026 the original author or authors.
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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link IpInetAddress}.
 *
 * @author Rob Winch
 * @author Phillip Webb
 */
class IpInetAddressTests {

	@Test
	void createWhenNullAddressThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new IpInetAddress(null, 0))
			.withMessage("'address' must not be null");
	}

	// FIXME more create

	@Test
	void ofWhenAddressIsNullThrowsException() {
	}

	@Test
	void ofWhenAddressIsEmptyThrowsException() {

	}

	@Test
	void ofWithMaskWhenAddressIsEmptyThrowsException() {

	}

	@Test
	void ofWithHostnameThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> IpInetAddress.of("example.com"))
			.withMessageContaining("doesn't look like an IP Address");
	}

	@Test
	void matchesWhenIpv4ExactMatchReturnsTrue() throws Exception {
		IpInetAddress ipAddress = IpInetAddress.of("192.168.1.1");
		assertThat(ipAddress.matches(InetAddress.getByName("192.168.1.1"))).isTrue();
	}

	@Test
	void matchesWhenIpv4NoMatchReturnsTrue() throws Exception {
		IpInetAddress ipAddress = IpInetAddress.of("192.168.1.1");
		assertThat(ipAddress.matches(InetAddress.getByName("192.168.1.2"))).isFalse();
	}

	@Test
	void matchesWhenIpv6ExactMatchReturnsTrue() throws Exception {
		IpInetAddress ipAddress = IpInetAddress.of("fe80::21f:5bff:fe33:bd68");
		assertThat(ipAddress.matches(InetAddress.getByName("fe80::21f:5bff:fe33:bd68"))).isTrue();
	}

	@Test
	void matchesWhenIpv6NoMatchReturnsFalse() throws Exception {
		IpInetAddress ipAddress = IpInetAddress.of("fe80::21f:5bff:fe33:bd68");
		assertThat(ipAddress.matches(InetAddress.getByName("fe80::21f:5bff:fe33:bd69"))).isFalse();
	}

	@Test
	void matchesWhenIpv4WithCidrMatchesSubnetReturnsTrue() throws Exception {
		IpInetAddress ipAddress = IpInetAddress.of("192.168.1.0/24");
		assertThat(ipAddress.matches(InetAddress.getByName("192.168.1.1"))).isTrue();
		assertThat(ipAddress.matches(InetAddress.getByName("192.168.1.255"))).isTrue();
	}

	@Test
	void matchesWhenIpv4WithCidrOutsideSubnetReturnsFalse() throws Exception {
		IpInetAddress ipAddress = IpInetAddress.of("192.168.1.0/24");
		assertThat(ipAddress.matches(InetAddress.getByName("192.168.2.1"))).isFalse();
		assertThat(ipAddress.matches(InetAddress.getByName("192.168.0.255"))).isFalse();
	}

	@Test
	void matchesWhenIpv6WithCidrMatchesSubnetReturnsTrue() throws Exception {
		IpInetAddress ipAddress = IpInetAddress.of("2001:db8::/48");
		assertThat(ipAddress.matches(InetAddress.getByName("2001:db8:0:0:0:0:0:0"))).isTrue();
		assertThat(ipAddress.matches(InetAddress.getByName("2001:db8:0:ffff:ffff:ffff:ffff:ffff"))).isTrue();
	}

	@Test
	void matchesWhenIpv6WithCidrOutsideSubnetReturnsFalse() throws Exception {
		IpInetAddress ipAddress = IpInetAddress.of("2001:db8::/48");
		assertThat(ipAddress.matches(InetAddress.getByName("2001:db8:1:0:0:0:0:0"))).isFalse();
	}

	@Test
	void matchesWhenWithOutsideOfByteBoundary() throws Exception {
		IpInetAddress ipAddress = IpInetAddress.of("192.168.1.0/30");
		assertThat(ipAddress.matches(InetAddress.getByName("192.168.1.0"))).isTrue();
		assertThat(ipAddress.matches(InetAddress.getByName("192.168.1.1"))).isTrue();
		assertThat(ipAddress.matches(InetAddress.getByName("192.168.1.2"))).isTrue();
		assertThat(ipAddress.matches(InetAddress.getByName("192.168.1.3"))).isTrue();
		assertThat(ipAddress.matches(InetAddress.getByName("192.168.1.4"))).isFalse();
	}

	@Test
	void matchesWhenIpv4AndIpv6AddressReturnsFalse() throws Exception {
		IpInetAddress ipAddress = IpInetAddress.of("192.168.1.1");
		assertThat(ipAddress.matches(InetAddress.getByName("fe80::21f:5bff:fe33:bd68"))).isFalse();
	}

	@Test
	void matchesWhenIpv6AndIpv4AddressReturnsFalse() throws Exception {
		IpInetAddress ipAddress = IpInetAddress.of("fe80::21f:5bff:fe33:bd68");
		assertThat(ipAddress.matches(InetAddress.getByName("192.168.1.1"))).isFalse();
	}

	@Test
	void matchesWhenInetAddressNullThenFalse() {
		IpInetAddress ipAddress = IpInetAddress.of("192.168.1.1");
		assertThat(ipAddress.matches((InetAddress) null)).isFalse();
	}

	@Test
	void asMatcherMatchesWhenStringIpv4MatchReturnsTrue() {
		IpInetAddress ipAddress = IpInetAddress.of("192.168.1.1");
		assertThat(ipAddress.matcher().matches("192.168.1.1")).isTrue();
	}

	@Test
	void asMatcherMatchesWhenStringIpv4NoMatchReturnsFalse() {
		IpInetAddress ipAddress = IpInetAddress.of("192.168.1.1");
		assertThat(ipAddress.matcher().matches("192.168.1.2")).isFalse();
	}

	@Test
	void asMatcherMatchesWhenStringNullThenFalse() {
		IpInetAddress ipAddress = IpInetAddress.of("192.168.1.1");
		assertThat(ipAddress.matcher().matches((String) null)).isFalse();
	}

}
