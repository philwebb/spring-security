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

package org.springframework.security.oauth2.client.jackson2;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.StdConverter;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.Builder;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * A {@code JsonDeserializer} for {@link ClientRegistration}.
 *
 * @author Joe Grandja
 * @since 5.3
 * @see ClientRegistration
 * @see ClientRegistrationMixin
 */
final class ClientRegistrationDeserializer extends JsonDeserializer<ClientRegistration> {

	private static final StdConverter<JsonNode, ClientAuthenticationMethod> CLIENT_AUTHENTICATION_METHOD_CONVERTER = new StdConverters.ClientAuthenticationMethodConverter();

	private static final StdConverter<JsonNode, AuthorizationGrantType> AUTHORIZATION_GRANT_TYPE_CONVERTER = new StdConverters.AuthorizationGrantTypeConverter();

	private static final StdConverter<JsonNode, AuthenticationMethod> AUTHENTICATION_METHOD_CONVERTER = new StdConverters.AuthenticationMethodConverter();

	@Override
	public ClientRegistration deserialize(JsonParser parser, DeserializationContext context) throws IOException {
		ObjectMapper mapper = (ObjectMapper) parser.getCodec();
		JsonNode root = mapper.readTree(parser);
		return deserialize(mapper, root);
	}

	private ClientRegistration deserialize(ObjectMapper mapper, JsonNode root) {
		Builder builder = ClientRegistration.withRegistrationId(JsonNodeUtils.findStringValue(root, "registrationId"));
		builder.clientId(JsonNodeUtils.findStringValue(root, "clientId"));
		builder.clientSecret(JsonNodeUtils.findStringValue(root, "clientSecret"));
		builder.clientAuthenticationMethod(CLIENT_AUTHENTICATION_METHOD_CONVERTER
				.convert(JsonNodeUtils.findObjectNode(root, "clientAuthenticationMethod")));
		builder.authorizationGrantType(AUTHORIZATION_GRANT_TYPE_CONVERTER
				.convert(JsonNodeUtils.findObjectNode(root, "authorizationGrantType")));
		builder.redirectUriTemplate(JsonNodeUtils.findStringValue(root, "redirectUriTemplate"));
		builder.scope(JsonNodeUtils.findValue(root, "scopes", JsonNodeUtils.STRING_SET, mapper));
		builder.clientName(JsonNodeUtils.findStringValue(root, "clientName"));
		deserializeProviderDetails(builder, mapper, JsonNodeUtils.findObjectNode(root, "providerDetails"));
		deserializeUserInfoEndpoint(builder, JsonNodeUtils
				.findObjectNode(JsonNodeUtils.findObjectNode(root, "providerDetails"), "userInfoEndpoint"));
		return builder.build();
	}

	private void deserializeUserInfoEndpoint(Builder builder, JsonNode node) {
		builder.userInfoUri(JsonNodeUtils.findStringValue(node, "uri"));
		builder.userInfoAuthenticationMethod(
				AUTHENTICATION_METHOD_CONVERTER.convert(JsonNodeUtils.findObjectNode(node, "authenticationMethod")));
		builder.userNameAttributeName(JsonNodeUtils.findStringValue(node, "userNameAttributeName"));
	}

	private void deserializeProviderDetails(Builder builder, ObjectMapper mapper, JsonNode node) {
		builder.jwkSetUri(JsonNodeUtils.findStringValue(node, "jwkSetUri"));
		builder.authorizationUri(JsonNodeUtils.findStringValue(node, "authorizationUri"));
		builder.tokenUri(JsonNodeUtils.findStringValue(node, "tokenUri"));
		builder.issuerUri(JsonNodeUtils.findStringValue(node, "issuerUri"));
		builder.providerConfigurationMetadata(
				JsonNodeUtils.findValue(node, "configurationMetadata", JsonNodeUtils.STRING_OBJECT_MAP, mapper));
	}

}
