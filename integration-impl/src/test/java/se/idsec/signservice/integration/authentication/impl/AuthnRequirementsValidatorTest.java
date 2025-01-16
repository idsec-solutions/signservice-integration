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
package se.idsec.signservice.integration.authentication.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.idsec.signservice.integration.authentication.AuthnRequirements;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.impl.DefaultIntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.testbase.TestBase;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;

/**
 * Test cases for {@code AuthnRequirementsValidator}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AuthnRequirementsValidatorTest extends TestBase {

  private IntegrationServiceConfiguration defaultConfig;

  public AuthnRequirementsValidatorTest() {
    this.defaultConfig = DefaultIntegrationServiceConfiguration.builder()
        .defaultAuthnServiceID("http://authn-service-id.com")
        .defaultAuthnContextRef("loa3")
        .build();
  }

  @Test
  public void testNullAndValidDefaults() throws Exception {
    AuthnRequirementsValidator validator = new AuthnRequirementsValidator();
    ValidationResult result = validator.validate(null, "a", this.defaultConfig);
    Assertions.assertFalse(result.hasErrors());
  }

  @Test
  public void testNullAndNoDefaults() throws Exception {
    AuthnRequirementsValidator validator = new AuthnRequirementsValidator();
    ValidationResult result = validator.validate(null, "a", new DefaultIntegrationServiceConfiguration());
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertTrue(result.getFieldErrors().size() == 2);
    Assertions.assertNotNull(result.getFieldErrors().get("a.authnServiceID"));
    Assertions.assertNotNull(result.getFieldErrors().get("a.authnContextClassRefs"));
  }

  @Test
  public void testUnsetAndNoDefaults() throws Exception {
    AuthnRequirementsValidator validator = new AuthnRequirementsValidator();

    AuthnRequirements ar = new AuthnRequirements();

    ValidationResult result = validator.validate(ar, "a", new DefaultIntegrationServiceConfiguration());
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertTrue(result.getFieldErrors().size() == 2);
    Assertions.assertNotNull(result.getFieldErrors().get("a.authnServiceID"));
    Assertions.assertNotNull(result.getFieldErrors().get("a.authnContextClassRefs"));
  }

  @Test
  public void testValidRequestedSignerAttributes() throws Exception {
    AuthnRequirementsValidator validator = new AuthnRequirementsValidator();

    AuthnRequirements ar = AuthnRequirements.builder()
        .authnContextClassRef("loa3")
        .authnServiceID("http://xyz")
        .requestedSignerAttribute(
          SignerIdentityAttributeValue.builder()
            .name(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
            .value("197001011234")
            .type(SignerIdentityAttributeValue.SAML_TYPE)
            .build())
        .requestedSignerAttribute(
          SignerIdentityAttributeValue.builder()
          .name(AttributeConstants.ATTRIBUTE_NAME_BIRTH_NAME)
          .value("Kalle")
          .build())
        .build();
    ValidationResult result = validator.validate(ar, "a", new DefaultIntegrationServiceConfiguration());
    Assertions.assertFalse(result.hasErrors());
  }

  @Test
  public void testInvalidRequestedSignerAttributes() throws Exception {
    AuthnRequirementsValidator validator = new AuthnRequirementsValidator();

    AuthnRequirements ar = AuthnRequirements.builder()
        .authnContextClassRef("loa3")
        .authnServiceID("http://xyz")
        .requestedSignerAttribute(
          SignerIdentityAttributeValue.builder()
            .name("personalId")
            .value("197001011234")
            .type("oidc")
            .build())
        .requestedSignerAttribute(
          SignerIdentityAttributeValue.builder()
          .name(AttributeConstants.ATTRIBUTE_NAME_BIRTH_NAME)
          .build())
        .requestedSignerAttribute(
          SignerIdentityAttributeValue.builder()
          .value("Kalle")
          .build())
        .build();
    ValidationResult result = validator.validate(ar, "a", new DefaultIntegrationServiceConfiguration());
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertTrue(result.getFieldErrors().size() == 3);
    Assertions.assertNotNull(result.getFieldErrors().get("a.requestedSignerAttributes[0].type"));
    Assertions.assertNotNull(result.getFieldErrors().get("a.requestedSignerAttributes[1].value"));
    Assertions.assertNotNull(result.getFieldErrors().get("a.requestedSignerAttributes[2].name"));
  }

}
