package com.smart.authorization.utils;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.smart.authorization.domain.User;
import com.smart.authorization.domain.value.Role;
import com.smart.authorization.domain.value.UserStatus;
import com.smart.authorization.dto.LoggedUser;


import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class UserPrincipalDeserializer extends JsonDeserializer<LoggedUser> {

    @Override
    public LoggedUser deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {

        ObjectMapper mapper = (ObjectMapper) jp.getCodec();
        JsonNode jsonNode = mapper.readTree(jp);
        final JsonNode authoritiesNode = readJsonNode(jsonNode, "roles");
        Set<Role> userAuthorities = getUserAuthorities(mapper, authoritiesNode);

        Long id = readJsonNode(jsonNode, "id").asLong();
        String firstName = readJsonNode(jsonNode, "firstName").asText();
        String username = readJsonNode(jsonNode, "username").asText();
        String timezone = readJsonNode(jsonNode, "timezone").asText();

        JsonNode passwordNode = readJsonNode(jsonNode, "password");
        String password = passwordNode.asText("");
        User currentUser = new User(id, firstName, username, password, userAuthorities);

        return new LoggedUser(currentUser);

    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }

    private Set<Role> getUserAuthorities(final ObjectMapper mapper, final JsonNode authoritiesNode) throws JsonParseException, JsonMappingException, IOException {

        Set<Role> userAuthorities = new HashSet<>();
        if (authoritiesNode != null) {
            if (authoritiesNode.isArray()) {
                for (final JsonNode objNode : authoritiesNode) {
                    if (objNode.isArray()) {
                        ArrayNode arrayNode = (ArrayNode) objNode;
                        for (JsonNode elementNode : arrayNode) {
                            Role userAuthority = Role.fromString(mapper.readValue(elementNode.traverse(mapper), String.class));
                            userAuthorities.add(userAuthority);
                        }
                    }
                }
            }
        }
        return userAuthorities;
    }

}
