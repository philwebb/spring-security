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

import org.jspecify.annotations.Nullable;

/**
 * An {@link InetAddressMatcher} that matches internal (private) addresses.
 * <p>
 * Internal addresses include loopback addresses (127.0.0.0/8 for IPv4, ::1 for IPv6),
 * private IPv4 address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and IPv6
 * Unique Local Addresses (fc00::/7).
 *
 * @author Gábor Vaspöri
 * @author Kian Jamali
 * @author Rossen Stoyanchev
 * @author Rob Winch
 */
final class InternalInetAddressMatcher implements InetAddressMatcher {

	static final InternalInetAddressMatcher instance = new InternalInetAddressMatcher();

	private InternalInetAddressMatcher() {
	}

	@Override
	public boolean matches(@Nullable InetAddress address) {
		if (address == null) {
			return false;
		}
		if (address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress()) {
			return true;
		}
		return matchesRaw(address.getAddress());
	}

	private boolean matchesRaw(byte[] rawAddress) {
		if (rawAddress.length == 16) {
			// Convert signed bytes to unsigned ints for easier matching logic
			int[] iAddr = toUnsignedInts(rawAddress);

			/*
			 * IPv6, check for Unique Local Addresses. We cannot rely on
			 * Inet6Address.isSiteLocalAddress() here because the JVM implementation
			 * dictates that fec0::/10 is the only site-local IPv6 address space, based on
			 * the outdated RFC 2373. That RFC was deprecated by the IETF in 2004 in favor
			 * of fc00::/7 (RFC 4193). To keep our private network checking accurate to
			 * modern subnets, we maintain manual parsing.
			 */
			if (iAddr[0] == 0xfc || iAddr[0] == 0xfd) {
				return true;
			}

			// IPv4/IPv6 translation, 64:ff9b
			if (iAddr[0] == 0x00 && iAddr[1] == 0x64 && iAddr[2] == 0xff && iAddr[3] == 0x9b) {
				try {
					InetAddress ipv4Part = InetAddress
						.getByAddress(new byte[] { rawAddress[12], rawAddress[13], rawAddress[14], rawAddress[15] });

					if (ipv4Part.isLoopbackAddress() || ipv4Part.isLinkLocalAddress()
							|| ipv4Part.isSiteLocalAddress()) {
						return true;
					}
				}
				catch (java.net.UnknownHostException ex) {
					// Should not happen for 4-byte array
				}
			}
		}

		return false;
	}

	private int[] toUnsignedInts(byte[] bytes) {
		int[] ints = new int[bytes.length];
		for (int i = 0; i < bytes.length; i++) {
			ints[i] = Byte.toUnsignedInt(bytes[i]);
		}
		return ints;
	}

	@Override
	public String toString() {
		return "InternalInetAddressMatcher";
	}

}