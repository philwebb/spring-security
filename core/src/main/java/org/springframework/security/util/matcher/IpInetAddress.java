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
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.regex.Pattern;

import org.jspecify.annotations.Nullable;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An IP address with support of CIDR notation.
 *
 * @author Luke Taylor
 * @author Steve Riesenberg
 * @author Andrey Litvitski
 * @author Rob Winch
 * @author Phillip Webb
 * @param address the address
 * @param subnetMaskSize the subnet mask size (the number of bits)
 * @since 7.1
 */
record IpInetAddress(InetAddress address, int subnetMaskSize) {

	private static Pattern IPV4 = Pattern.compile("^\\d{1,3}(?:\\.\\d{1,3}){0,3}(?:/\\d{1,2})?$");

	IpInetAddress {
		Assert.notNull(address, "'address' must not be null");
		Assert.isTrue(subnetMaskSize >= 0, "'subnetMaskSize' must be positive");
		int rawAddressSize = address.getAddress().length * 8;
		Assert.isTrue(rawAddressSize >= subnetMaskSize,
				() -> String.format("'address' [%s] is too short for bitmask of length %d", address, subnetMaskSize));
	}

	InetAddressMatcher matcher() {
		return (address) -> {
			if (address == null) {
				return false;
			}
			return (this.subnetMaskSize == 0) ? address.equals(this.address)
					: Arrays.equals(maskedRawAddress(this.address), maskedRawAddress(address));
		};
	}

	private byte[] maskedRawAddress(@Nullable InetAddress address) {
		byte[] rawAddress = address.getAddress();
		int start = (this.subnetMaskSize / 8);
		byte firstMask = (byte) (0xFF << (8 - (this.subnetMaskSize % 8)));
		for (int i = start; i < rawAddress.length; i++) {
			byte mask = (i == start) ? firstMask : (byte) 0x00;
			rawAddress[i] = (byte) (rawAddress[i] & mask);
		}
		return rawAddress;
	}

	@Override
	public String toString() {
		String hostAddress = this.address.getHostAddress();
		String suffix = (this.subnetMaskSize > 0) ? "/" + this.subnetMaskSize : "";
		return "IpAddress [" + hostAddress + suffix + "]";
	}

	static IpInetAddress of(String address) {
		Assert.hasText(address, "'address' must not be empty");
		int slash = address.indexOf('/');
		if (slash == -1) {
			return of(address, 0);
		}
		String ip = address.substring(0, slash);
		String subnetMaskSize = address.substring(slash + 1);
		return of(ip, parseSubnetMaskSize(subnetMaskSize));
	}

	private static int parseSubnetMaskSize(String subnetMaskSize) {
		try {
			return Integer.parseInt(subnetMaskSize);
		}
		catch (NumberFormatException ex) {
			throw new IllegalArgumentException("'address' subnet mask must be a number", ex);
		}
	}

	private static IpInetAddress of(String ip, int subnetMaskSize) {
		Assert.hasText(ip, "'ip' must not be empty");
		return new IpInetAddress(parseIpAddress(ip), subnetMaskSize);
	}

	/**
	 * Parses the given address string into an {@link InetAddress}.
	 * @param address the IP address string to parse
	 * @return the parsed {@link InetAddress}
	 * @throws IllegalArgumentException if the address cannot be parsed or appears to be a
	 * hostname
	 */
	static @Nullable InetAddress parseIpAddress(@Nullable String address) {
		if (address == null) {
			return null;
		}
		Assert.isTrue(isLikelyIpAddress(address),
				() -> "'address' [%s] must be an IP address and not a host name".formatted(address));
		try {
			return InetAddress.getByName(address);
		}
		catch (UnknownHostException ex) {
			throw new IllegalArgumentException("'address' [%s] must be parsable to an InetAddress".formatted(address),
					ex);
		}
	}

	private static boolean isLikelyIpAddress(String address) {
		return StringUtils.hasText(address) && (IPV4.matcher(address).matches() || isLikelyIpv6Address(address));
	}

	private static boolean isLikelyIpv6Address(String address) {
		char firstChar = address.charAt(0);
		return (firstChar == '[' || firstChar == ':') || (isHexDigit(firstChar) && address.contains(":"));
	}

	private static boolean isHexDigit(char ch) {
		return Character.digit(ch, 16) != -1;
	}

}
