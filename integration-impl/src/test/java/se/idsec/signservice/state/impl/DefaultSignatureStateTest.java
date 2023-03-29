package se.idsec.signservice.state.impl;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.SignServiceIntegrationService;
import se.idsec.signservice.integration.authentication.AuthnRequirements;
import se.idsec.signservice.integration.certificate.SigningCertificateRequirements;
import se.idsec.signservice.integration.core.Extension;
import se.idsec.signservice.integration.signmessage.SignMessageParameters;
import se.idsec.signservice.integration.state.SignatureSessionState;
import se.idsec.signservice.integration.state.impl.DefaultSignatureState;

public class DefaultSignatureStateTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void testJsonSerializesAndDeserializes() throws Exception {

        DefaultSignatureState signatureState = defaultSignatureState();
        String jsonString = objectMapper.writeValueAsString(signatureState);

        DefaultSignatureState deserializedSignatureState = objectMapper.readValue(jsonString,
                DefaultSignatureState.class);
        assertEquals(signatureState.getId(), deserializedSignatureState.getId());
        assertEquals(signatureState.getOwnerId(), deserializedSignatureState.getOwnerId());

        //Why no an simple assertEquals - all objects in the SignatureSessionState graph
        // would then have to implement equals, hashcode, and currently, they don't
        //so, we just use reflection to pick most of them.
        // If improving further in the future, that would be that would be the way to go imho,
        // (not expanding on this reflection test, but aim to remove any such need)
        Field[] allFields = FieldUtils.getAllFields(SignatureSessionState.class);
        Arrays.stream(allFields).forEach(field -> {
            System.out.println(field.getName());
            field.setAccessible(true);
            switch (field.getName()) {
                case "correlationId":
                    break;
                case "policy":
                    assertField(field, deserializedSignatureState, signatureState);
                    break;
                case "expectedReturnUrl":
                    assertField(field, deserializedSignatureState, signatureState);
                    break;
                case "tbsDocuments":
                    assertField(field, deserializedSignatureState, signatureState);
                    break;
                case "signRequest":
                    assertField(field, deserializedSignatureState, signatureState);
                    break;
                case "encodedSignRequest":
                    assertField(field, deserializedSignatureState, signatureState);
                    break;
                default:
                    System.out.println("unknown");

            }
        }

        );
    }

    private void assertField(Field field, DefaultSignatureState deserializedSignatureState,
            DefaultSignatureState signatureState) {
        try {
            assertEquals(field.get(deserializedSignatureState.getState()), field.get(signatureState.getState()));
        } catch (IllegalArgumentException | IllegalAccessException e) {
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
                .ownerId(requestInput.getExtensionValue(SignServiceIntegrationService.OWNER_ID_EXTENSION_KEY))
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
