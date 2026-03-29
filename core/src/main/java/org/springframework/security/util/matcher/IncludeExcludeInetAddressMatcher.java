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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.jspecify.annotations.Nullable;

import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ObjectUtils;

/**
 * @author Rob Winch
 * @author Phillip Webb
 */
public final class IncludeExcludeInetAddressMatcher implements InetAddressMatcher {

	static IncludeExcludeInetAddressMatcher instance = new IncludeExcludeInetAddressMatcher(Collections.emptyList(),
			Collections.emptyList());

	private final List<InetAddressMatcher> includes;

	private final List<InetAddressMatcher> excludes;

	private IncludeExcludeInetAddressMatcher(List<InetAddressMatcher> includes, List<InetAddressMatcher> excludes) {
		this.includes = includes;
		this.excludes = excludes;
	}

	public IncludeExcludeInetAddressMatcher including(String... addresses) {
		Assert.notNull(addresses, "'addresses' must not be null");
		Assert.noNullElements(addresses, "'addresses' must not contain null elements");
		if (ObjectUtils.isEmpty(addresses)) {
			return this;
		}
		return including(Arrays.stream(addresses).map(IpInetAddressMatcher::new));
	}

	public IncludeExcludeInetAddressMatcher including(InetAddressMatcher... matchers) {
		Assert.notNull(matchers, "'matchers' must not be null");
		Assert.noNullElements(matchers, "'matchers' must not contain null elements");
		if (ObjectUtils.isEmpty(matchers)) {
			return this;
		}
		return including(Arrays.stream(matchers));
	}

	public IncludeExcludeInetAddressMatcher including(Collection<? extends InetAddressMatcher> matchers) {
		Assert.notNull(matchers, "'matchers' must not be null");
		Assert.noNullElements(matchers, "'matchers' must not contain null elements");
		if (CollectionUtils.isEmpty(matchers)) {
			return this;
		}
		return including(matchers.stream());
	}

	private IncludeExcludeInetAddressMatcher including(Stream<? extends InetAddressMatcher> matchers) {
		return new IncludeExcludeInetAddressMatcher(append(this.includes, matchers), this.excludes);
	}

	public IncludeExcludeInetAddressMatcher excluding(String... addresses) {
		Assert.notNull(addresses, "'addresses' must not be null");
		Assert.noNullElements(addresses, "'addresses' must not contain null elements");
		if (ObjectUtils.isEmpty(addresses)) {
			return this;
		}
		return excluding(Arrays.stream(addresses).map(IpInetAddressMatcher::new));
	}

	public IncludeExcludeInetAddressMatcher excluding(InetAddressMatcher... matchers) {
		Assert.notNull(matchers, "'matchers' must not be null");
		Assert.noNullElements(matchers, "'matchers' must not contain null elements");
		if (ObjectUtils.isEmpty(matchers)) {
			return this;
		}
		return excluding(Arrays.stream(matchers));
	}

	public IncludeExcludeInetAddressMatcher excluding(Collection<? extends InetAddressMatcher> matchers) {
		Assert.notNull(matchers, "'matchers' must not be null");
		Assert.noNullElements(matchers, "'matchers' must not contain null elements");
		if (CollectionUtils.isEmpty(matchers)) {
			return this;
		}
		return excluding(matchers.stream());
	}

	private IncludeExcludeInetAddressMatcher excluding(Stream<? extends InetAddressMatcher> matchers) {
		return new IncludeExcludeInetAddressMatcher(this.includes, append(this.excludes, matchers));
	}

	private <T> List<T> append(@Nullable List<T> list, Stream<? extends T> stream) {
		ArrayList<T> result = new ArrayList<>(list);
		stream.forEach(result::add);
		return List.copyOf(result);
	}

	@Override
	public boolean matches(@Nullable InetAddress address) {
		return isIncluded(address) && !isExcluded(address);
	}

	private boolean isIncluded(@Nullable InetAddress address) {
		return this.includes.stream().anyMatch((matcher) -> matcher.matches(address));
	}

	private boolean isExcluded(@Nullable InetAddress address) {
		return this.excludes.stream().anyMatch((matcher) -> matcher.matches(address));
	}

	@Override
	public String toString() {
		return ""; // FIXME
	}

}
