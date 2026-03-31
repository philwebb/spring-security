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

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link InetAddressMatcher}.
 *
 * @author Rob Winch
 * @author Phillip Webb
 */
class InetAddressMatcherTests {

	private static InetAddressMatcherAssert assertThat(InetAddressMatcher matcher) {
		return new InetAddressMatcherAssert(matcher);
	}

	@Nested
	class MatchString {

		@Test
		void whenIpv4() {
			InetAddressMatcher matcher = (address) -> address.getHostAddress().equals("192.168.1.1");
			assertThat(matcher).matchesString("192.168.1.1");
			assertThat(matcher).doesNotMatchString("192.168.1.2");
		}

		@Test
		void whenIpv6() {
			InetAddressMatcher matcher = (address) -> address.getHostAddress().equals("fe80:0:0:0:21f:5bff:fe33:bd68");
			assertThat(matcher).matchesString("fe80::21f:5bff:fe33:bd68");
			assertThat(matcher).doesNotMatchString("fe90::21f:5bff:fe33:bd68");
		}

		@Test
		void whenNull() {
			InetAddressMatcher matcher = (address) -> address != null;
			assertThat(matcher).doesNotMatchString(null);
		}

		@Test
		void whenNotAndIpAddress() {
			InetAddressMatcher matcher = InetAddressMatcher.all();
			assertThat(matcher).matches("192.168.1.1");
			assertThatIllegalArgumentException().isThrownBy(() -> matcher.matches("not.an.ip.address"));
		}

		@Test
		void whenLambda() {
			InetAddressMatcher matcher = (address) -> address.getHostAddress().startsWith("192.168");
			assertThat(matcher).matches("192.168.1.1");
			assertThat(matcher).matches("192.168.100.200");
			assertThat(matcher).doesNotMatch("10.0.0.1");
		}

	}

	@Nested
	class And {

		@Test
		void stringsWhenEmpty() {

		}

		@Test
		void stringsWhenSingle() {

		}

		@Test
		void stringsWhenMultiple() {

		}

		@Test
		void matchers() {

		}

		@Test
		void collection() {

		}

		@Test
		void matchAllWhenMultipleMatchersThenAppliesAndLogic() {
			InetAddressMatcher startsWithTen = (address) -> address.getHostAddress().startsWith("10.");
			InetAddressMatcher endsWithOne = (address) -> address.getHostAddress().endsWith(".1");
			InetAddressMatcher matcher = startsWithTen.and(endsWithOne);
			assertThat(matcher).matches("10.0.0.1");
			assertThat(matcher).doesNotMatch("10.0.0.2");
			assertThat(matcher).doesNotMatch("192.168.1.1");
		}

	}

	@Nested
	class AndNot {

		@Test
		void stringsWhenEmpty() {

		}

		@Test
		void stringsWhenSingle() {

		}

		@Test
		void stringsWhenMultiple() {

		}

		@Test
		void matcher() {

		}

		@Test
		void collection() {

		}

	}

	@Nested
	class Or {

		@Test
		void stringsWhenEmpty() {

		}

		@Test
		void stringsWhenSingle() {

		}

		@Test
		void stringsWhenMultiple() {

		}

		@Test
		void matcher() {

		}

		@Test
		void collection() {

		}

	}

	@Nested
	class Negate {

	}

	@Nested
	class ExternalAddresses {

		@Test
		void nullInetAddressDoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.externalAddresses();
			assertThat(matcher).doesNotMatch((InetAddress) null);
		}

		@Test
		void ipv4PublicMatches() {
			InetAddressMatcher matcher = InetAddressMatcher.externalAddresses();
			assertThat(matcher).matches("8.8.8.8");
			assertThat(matcher).matches("1.1.1.1");
		}

		@Test
		void ipv6PublicMatches() {
			InetAddressMatcher matcher = InetAddressMatcher.externalAddresses();
			assertThat(matcher).matches("2001:4860:4860::8888");
		}

		@Test
		void ipv4PrivateDoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.externalAddresses();
			assertThat(matcher).doesNotMatch("192.168.1.1");
			assertThat(matcher).doesNotMatch("10.0.0.1");
			assertThat(matcher).doesNotMatch("172.16.0.1");
		}

		@Test
		void ipv4LoopbackDoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.externalAddresses();
			assertThat(matcher).doesNotMatch("127.0.0.1");
		}

		@Test
		void ipv4LinkLocalDoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.externalAddresses();
			assertThat(matcher).doesNotMatch("169.254.0.0");
			assertThat(matcher).doesNotMatch("169.254.169.254");
			assertThat(matcher).doesNotMatch("169.254.255.255");
		}

		@Test
		void ipv6LoopbackDoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.externalAddresses();
			assertThat(matcher).doesNotMatch("::1");
		}

		@Test
		void ipv6UniqueLocalDoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.externalAddresses();
			assertThat(matcher).doesNotMatch("fc00::1");
			assertThat(matcher).doesNotMatch("fd00::1");
		}

	}

	@Nested
	class InternalAddresses {

		@Test
		void nullInetAddressDoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).doesNotMatch((InetAddress) null);
		}

		@Test
		void ipv4LoopbackMatches() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).matches("127.0.0.1");
			assertThat(matcher).matches("127.0.0.255");
		}

		@Test
		void ipv6LoopbackMatches() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).matches("::1");
		}

		@Test
		void ipv4PrivateClass10Matches() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).matches("10.0.0.1");
			assertThat(matcher).matches("10.255.255.255");
		}

		@Test
		void ipv4PrivateClass192Matches() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).matches("192.168.0.1");
			assertThat(matcher).matches("192.168.255.255");
		}

		@Test
		void ipv4LinkLocalMatches() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).matches("169.254.0.0");
			assertThat(matcher).matches("169.254.169.254");
			assertThat(matcher).matches("169.254.255.255");
		}

		@Test
		void ipv4PrivateClass172Matches() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).matches("172.16.0.1");
			assertThat(matcher).matches("172.16.255.255");
			assertThat(matcher).matches("172.17.1.1");
			assertThat(matcher).matches("172.31.255.255");
		}

		@Test
		void ipv4MappedIpv6InternalMatches() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).matches("::ffff:192.168.1.1");
			assertThat(matcher).matches("::ffff:169.254.169.254");
			assertThat(matcher).matches("::ffff:10.0.0.1");
		}

		@Test
		void ipv6UniqueLocalMatches() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).matches("fc00::1");
			assertThat(matcher).matches("fd00::1");
		}

		@Test
		void ipv6TranslationWithInternalIpv4Matches() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).matches("64:ff9b::10.0.0.1");
			assertThat(matcher).matches("64:ff9b::127.0.0.1");
			assertThat(matcher).matches("64:ff9b::192.168.1.1");
			assertThat(matcher).matches("64:ff9b::172.16.0.1");
		}

		@Test
		void ipv6TranslationWithIpv4StartsWith192ButNot168Matches() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).doesNotMatch("64:ff9b::192.0.2.1");
			assertThat(matcher).doesNotMatch("64:ff9b::192.167.1.1");
		}

		@Test
		void ipv6TranslationWithIpv4StartsWith172And16Matches() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).matches("64:ff9b::172.16.0.1");
			assertThat(matcher).matches("64:ff9b::172.16.255.255");
		}

		@Test
		@ValueSource(strings = {})
		void ipv6TranslationWithExternalIpv4DoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).doesNotMatch("64:ff9b::8.8.8.8");
			assertThat(matcher).doesNotMatch("64:ff9b::1.1.1.1");
		}

		@Test
		void ppv6NonTranslationPrefixByte0DoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).doesNotMatch("65:ff9b::10.0.0.1");
		}

		@Test
		void ipv6NonTranslationPrefixByte1DoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).doesNotMatch("64:fe9b::10.0.0.1");
		}

		@Test
		void ipv6NonTranslationPrefixByte2DoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).doesNotMatch("64:ff9a::10.0.0.1");
		}

		@Test
		void ipv6NonTranslationPrefixByte3DoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).doesNotMatch("64:ff9c::10.0.0.1");
		}

		@Test
		void ipv4PublicDoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).doesNotMatch("8.8.8.8");
			assertThat(matcher).doesNotMatch("1.1.1.1");
		}

		@Test
		void ipv4StartsWith192ButNot168DoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).doesNotMatch("192.0.2.1");
			assertThat(matcher).doesNotMatch("192.167.1.1");
			assertThat(matcher).doesNotMatch("192.169.1.1");
		}

		@Test
		void ipv4StartsWith172ButNotPrivate16To31DoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).doesNotMatch("172.15.1.1");
			assertThat(matcher).doesNotMatch("172.32.1.1");
		}

		@Test
		void ipv6PublicDoesNotMatch() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses();
			assertThat(matcher).doesNotMatch("2001:4860:4860::8888");
		}

	}

	@Nested
	class Not {

		@Test
		void excludeAddressesWhenSingleAddressThenBlocksOnlyThatAddress() {
			InetAddressMatcher matcher = InetAddressMatcher.not("192.168.1.1");
			assertThat(matcher).matches("192.168.1.2");
			assertThat(matcher).doesNotMatch("192.168.1.1");
		}

		@Test
		void excludeAddressesWhenMultipleAddressesThenBlocksAll() {
			InetAddressMatcher matcher = InetAddressMatcher.not("192.168.1.1", "10.0.0.1");
			assertThat(matcher).doesNotMatch("192.168.1.1");
			assertThat(matcher).doesNotMatch("10.0.0.1");
			assertThat(matcher).matches("8.8.8.8");
		}

		@Test
		void excludeAddressesWhenCidrNotationThenBlocksSubnet() {
			InetAddressMatcher matcher = InetAddressMatcher.not("192.168.1.0/24");
			assertThat(matcher).matches("192.168.2.1");
			assertThat(matcher).doesNotMatch("192.168.1.1");
			assertThat(matcher).doesNotMatch("192.168.1.255");
		}

	}

	@Nested
	class Of {

		@Test
		void includeAddressesWhenSingleAddressThenMatchesOnlyThatAddress() {
			InetAddressMatcher matcher = InetAddressMatcher.of("192.168.1.1");
			assertThat(matcher).matches("192.168.1.1");
			assertThat(matcher).doesNotMatch("192.168.1.2");
		}

		@Test
		void includeAddressesWhenMultipleAddressesThenMatchesAny() {
			InetAddressMatcher matcher = InetAddressMatcher.of("192.168.1.1", "10.0.0.1");
			assertThat(matcher).matches("192.168.1.1");
			assertThat(matcher).matches("10.0.0.1");
			assertThat(matcher).doesNotMatch("8.8.8.8");
		}

		@Test
		void includeAddressesWhenCidrNotationThenMatchesSubnet() {
			InetAddressMatcher matcher = InetAddressMatcher.of("192.168.1.0/24");
			assertThat(matcher).matches("192.168.1.1");
			assertThat(matcher).matches("192.168.1.255");
			assertThat(matcher).doesNotMatch("192.168.2.1");
		}

		@Test
		void matchAllWhenVarargsThenAddsMatchersToChain() {
			InetAddressMatcher customMatcher = (address) -> address.getHostAddress().startsWith("10.");
			InetAddressMatcher matcher = InetAddressMatcher.of(customMatcher);
			assertThat(matcher).matches("10.0.0.1");
			assertThat(matcher).doesNotMatch("192.168.1.1");
		}

	}

	@Nested
	class Composite {

		@Test
		void buildWhenMultipleMatchersThenAppliesAndLogic() {
			InetAddressMatcher matcher = InetAddressMatcher.of("192.168.1.0/24").andNot("192.168.1.100");
			assertThat(matcher).matches("192.168.1.1");
			assertThat(matcher).doesNotMatch("192.168.1.100");
			assertThat(matcher).doesNotMatch("192.168.2.1");
		}

		@Test
		void buildWhenMultipleIncludes() {
			InetAddressMatcher matcher = InetAddressMatcher.of("192.168.1.100").or("192.168.1.101");
			assertThat(matcher).matches("192.168.1.100");
			assertThat(matcher).matches("192.168.1.101");
			assertThat(matcher).doesNotMatch("192.168.1.102");
		}

		@Test
		void matchesWhenAllMatchersTrueThenReturnsTrue() {
			InetAddressMatcher matcher = InetAddressMatcher.of("192.168.1.0/24")
				.and((address) -> address.getHostAddress().endsWith(".1"));
			assertThat(matcher).matches("192.168.1.1");
			assertThat(matcher).doesNotMatch("192.168.1.2");
		}

		@Test
		void testName() {
			InetAddressMatcher matcher = InetAddressMatcher.internalAddresses()
				.and("8.8.8.8", "8.8.4.4")
				.andNot("192.168.2.0/24");
			assertThat(matcher).matches("192.168.1.1");
			assertThat(matcher).matches("8.8.8.8");
			assertThat(matcher).matches("8.8.4.4");
			assertThat(matcher).doesNotMatch("192.168.2.1");
		}

	}

	@Nested
	class All {

	}

	@Nested
	class None {

	}

}
