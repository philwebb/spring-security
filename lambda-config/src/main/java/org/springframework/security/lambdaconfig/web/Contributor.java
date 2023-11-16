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

/**
 * An object that contributes security configuration.
 *
 * @param <C> the type of configurer used by the contributor
 * @param <R> the type that the resulting contribution supports
 * @author Phillip Webb
 */
public interface Contributor<C, R> {

	Contribution<R> contribute(ContributionContext context, Consumer<C> customizer);

}
