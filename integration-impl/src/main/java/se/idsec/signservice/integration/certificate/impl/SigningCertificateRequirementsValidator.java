/*
 * Copyright 2019-2023 IDsec Solutions AB
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
package se.idsec.signservice.integration.certificate.impl;

import jakarta.annotation.Nullable;
import org.apache.commons.lang3.StringUtils;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.certificate.CertificateAttributeMapping;
import se.idsec.signservice.integration.certificate.RequestedCertificateAttributeType;
import se.idsec.signservice.integration.certificate.SigningCertificateRequirements;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.validation.AbstractInputValidator;
import se.idsec.signservice.integration.core.validation.ValidationResult;

/**
 * Validator for {@link SigningCertificateRequirements} objects.
 * <p>
 * The validator is used both when checking input (hint is set) and when checking the configuration (hint is null).
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SigningCertificateRequirementsValidator extends
    AbstractInputValidator<SigningCertificateRequirements, IntegrationServiceConfiguration> {

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(final SigningCertificateRequirements object, @Nullable final String objectName,
      final IntegrationServiceConfiguration hint) {

    final ValidationResult result = new ValidationResult(objectName);

    if (object == null) {
      if (hint != null) {
        // Null is OK - the default will be used.
        return result;
      }
      else {
        result.reject("Missing SigningCertificateRequirements");
        return result;
      }
    }

    if (object.getCertificateType() == null) {
      if (hint == null) {
        result.rejectValue("certificateType", "Missing certificate type");
      }
    }

    if (object.getAttributeMappings() == null || object.getAttributeMappings().isEmpty()) {
      if (hint == null) {
        result.rejectValue("attributeMappings", "No attribute mappings provided");
      }
    }

    int pos = 0;
    for (final CertificateAttributeMapping mapping : object.getAttributeMappings()) {
      if (mapping.getDestination() == null) {
        result.rejectValue("attributeMappings[" + pos + "].destination", "Missing destination for mapping");
      }
      else {
        if (StringUtils.isBlank(mapping.getDestination().getType())) {
          result.rejectValue("attributeMappings[" + pos + "].destination.type",
              "Missing type for destination attribute");
        }
        else {
          try {
            RequestedCertificateAttributeType.fromType(mapping.getDestination().getType());
          }
          catch (final IllegalArgumentException e) {
            result.rejectValue("attributeMappings[" + pos + "].destination.type", e.getMessage());
          }
        }
        if (StringUtils.isBlank(mapping.getDestination().getName())) {
          result.rejectValue("attributeMappings[" + pos + "].destination.name",
              "Missing name for destination attribute");
        }
      }

      if (mapping.getSources() == null || mapping.getSources().isEmpty()) {
        if (mapping.getDestination() != null && Boolean.TRUE.equals(mapping.getDestination().getRequired())
            && mapping.getDestination().getDefaultValue() == null) {
          result.rejectValue("attributeMappings[" + pos + "]",
              "Attribute mapping has no sources and destination has no default value - illegal");
        }
      }
      else {
        int spos = 0;
        for (final SignerIdentityAttribute source : mapping.getSources()) {
          if (source.getType() != null && !SignerIdentityAttribute.SAML_TYPE.equalsIgnoreCase(source.getType())) {
            result.rejectValue("attributeMappings[" + pos + "].sources[" + spos + "].type",
                String.format("Unsupported attribute type - %s", source.getType()));
          }
          if (StringUtils.isBlank(source.getName())) {
            result.rejectValue("attributeMappings[" + pos + "].sources[" + spos + "].name", "Missing attribute name");
          }
          spos++;
        }
      }
      pos++;
    }

    return result;
  }

}
