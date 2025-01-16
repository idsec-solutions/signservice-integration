/*
 * Copyright 2019-2025 IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.idsec.signservice.state.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.jupiter.api.Test;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.authentication.AuthnRequirements;
import se.idsec.signservice.integration.certificate.SigningCertificateRequirements;
import se.idsec.signservice.integration.core.Extension;
import se.idsec.signservice.integration.signmessage.SignMessageParameters;
import se.idsec.signservice.integration.state.SignatureSessionState;
import se.idsec.signservice.integration.state.impl.DefaultSignatureState;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DefaultSignatureStateTest {

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  public void testJsonSerializesAndDeserializes() throws Exception {

    final DefaultSignatureState signatureState = this.defaultSignatureState();
    final String jsonString = this.objectMapper.writeValueAsString(signatureState);

    final DefaultSignatureState deserializedSignatureState = this.objectMapper.readValue(jsonString,
        DefaultSignatureState.class);
    assertEquals(signatureState.getId(), deserializedSignatureState.getId());

    // Why no an simple assertEquals - all objects in the SignatureSessionState graph
    // would then have to implement equals, hashcode, and currently, they don't
    // so, we just use reflection to pick most of them.
    // If improving further in the future, that would be that would be the way to go imho,
    // (not expanding on this reflection test, but aim to remove any such need)
    final Field[] allFields = FieldUtils.getAllFields(SignatureSessionState.class);
    Arrays.stream(allFields).forEach(field -> {
          field.setAccessible(true);
          switch (field.getName()) {
          case "correlationId":
            break;
          case "policy":
            this.assertField(field, deserializedSignatureState, signatureState);
            break;
          case "expectedReturnUrl":
            this.assertField(field, deserializedSignatureState, signatureState);
            break;
          case "tbsDocuments":
            this.assertField(field, deserializedSignatureState, signatureState);
            break;
          case "signRequest":
            this.assertField(field, deserializedSignatureState, signatureState);
            break;
          case "encodedSignRequest":
            this.assertField(field, deserializedSignatureState, signatureState);
            break;
          default:
            System.out.println("unknown");
          }
        }

    );
  }

  private void assertField(final Field field, final DefaultSignatureState deserializedSignatureState,
      final DefaultSignatureState signatureState) {
    try {
      assertEquals(field.get(deserializedSignatureState.getState()), field.get(signatureState.getState()));
    }
    catch (IllegalArgumentException | IllegalAccessException e) {
      e.printStackTrace();
    }
  }

  // TODO: this test object setup could certainly improve with a better object setup
  // Currently we are only testing the general serialize/deseralize mechanism,
  // and are not putting much effort into the field values themselves.
  // So good enough for that.
  private DefaultSignatureState defaultSignatureState() {

    final SignRequestInput requestInput = SignRequestInput.builder().build();
    requestInput.setCorrelationId("correlationId");
    requestInput.setAuthnRequirements(AuthnRequirements.builder().build());
    requestInput.setCertificateRequirements(SigningCertificateRequirements.builder().build());
    requestInput.setDestinationUrl("http://desturl.test");
    requestInput.setExtension(Extension.builder().build());
    requestInput.setPolicy("policy");
    requestInput.setReturnUrl("http://returnurl.test");
    requestInput.setSignMessageParameters(SignMessageParameters.builder().signMessage("signMessage").build());
    requestInput.setSignRequesterID("signRequesterId");
    requestInput.setSignatureAlgorithm("signatureAlg");
    requestInput.setTbsDocuments(List.of());

    final SignatureSessionState sessionState = SignatureSessionState.builder()
        .ownerId("owner")
        .correlationId(requestInput.getCorrelationId())
        .policy(requestInput.getPolicy())
        .expectedReturnUrl(requestInput.getReturnUrl())
        .tbsDocuments(requestInput.getTbsDocuments())
        .signMessage(requestInput.getSignMessageParameters())
        .encodedSignRequest("encodedSignRequest")
        .build();

    return DefaultSignatureState.builder().id("id").state(sessionState).build();
  }
}
