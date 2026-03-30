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
		Assert.hasText(address, "'address' cannot be empty");
		int slash = address.indexOf('/');
		if (slash == -1) {
			return of(address, 0);
		}
		String ip = address.substring(0, slash);
		String subnetMaskSize = address.substring(slash + 1);
		return of(ip, Integer.parseInt(subnetMaskSize));
	}

	private static IpInetAddress of(String ip, int subnetMaskSize) {
		return new IpInetAddress(IpInetAddressParser.parse(ip), subnetMaskSize);
	}

	static @Nullable InetAddress parseIpAddress(@Nullable String address) {
		return IpInetAddressParser.parse(address);
	}

	private static Pattern IPV4 = Pattern.compile("^\\d{1,3}(?:\\.\\d{1,3}){0,3}(?:/\\d{1,2})?$");

	/**
	 * Parses the given address string into an {@link InetAddress}.
	 * @param address the IP address string to parse
	 * @return the parsed {@link InetAddress}
	 * @throws IllegalArgumentException if the address cannot be parsed or appears to be a
	 * hostname
	 */
	static InetAddress parse(String address) {
		assertNotHostName(address);
		try {
			return InetAddress.getByName(address);
		}
		catch (UnknownHostException ex) {
			throw new IllegalArgumentException("Failed to parse address '" + address + "'", ex);
		}
	}

	static void assertNotHostName(String ipAddress) {
		Assert.isTrue(isIpAddress(ipAddress),
				() -> String.format("ipAddress %s doesn't look like an IP Address. Is it a host name?", ipAddress));
	}

	private static boolean isIpAddress(String ipAddress) {
		if (!org.springframework.util.StringUtils.hasText(ipAddress)) {
			return false;
		}
		// @formatter:off
		return IPV4.matcher(ipAddress).matches()
			|| ipAddress.charAt(0) == '['
			|| ipAddress.charAt(0) == ':'
			|| Character.digit(ipAddress.charAt(0), 16) != -1
			&& ipAddress.indexOf(':') > 0;
		// @formatter:on
	}

}
