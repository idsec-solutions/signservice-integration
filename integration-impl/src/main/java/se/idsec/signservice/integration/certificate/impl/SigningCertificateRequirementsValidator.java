/*
 * Copyright 2019 IDsec Solutions AB
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

import org.springframework.util.StringUtils;

import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.certificate.CertificateAttributeMapping;
import se.idsec.signservice.integration.certificate.RequestedCertificateAttributeType;
import se.idsec.signservice.integration.certificate.SigningCertificateRequirements;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.validation.AbstractInputValidator;
import se.idsec.signservice.integration.core.validation.ValidationResult;

/**
 * Validator for {@link SigningCertificateRequirements} objects.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SigningCertificateRequirementsValidator extends
    AbstractInputValidator<SigningCertificateRequirements, IntegrationServiceConfiguration> {

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(SigningCertificateRequirements object, String objectName, 
      IntegrationServiceConfiguration hint) {
    
    ValidationResult result = new ValidationResult(objectName);
    
    if (object == null) {
      // Null is OK - the default will be used.
      return result;
    }
    
    if (object.getCertificateType() == null) {
      result.rejectValue("certificateType", "Missing certificate type");
    }
    if (object.getAttributeMappings() == null || object.getAttributeMappings().isEmpty()) {
      result.rejectValue("attributeMappings", "No attribute mappings provided");
    }
    
    int pos = 0;
    for (CertificateAttributeMapping mapping : object.getAttributeMappings()) {
      if (mapping.getDestination() == null) {
        result.rejectValue("attributeMappings[" + pos + "].destination", "Missing destination for mapping");
      }
      else {
        if (!StringUtils.hasText(mapping.getDestination().getType())) {
          result.rejectValue("attributeMappings[" + pos + "].destination.type", "Missing type for destination attribute");
        }
        else {
          try {
            RequestedCertificateAttributeType.fromType(mapping.getDestination().getType());            
          }
          catch (IllegalArgumentException e) {
            result.rejectValue("attributeMappings[" + pos + "].destination.type", e.getMessage());
          }
        }
        if (!StringUtils.hasText(mapping.getDestination().getName())) {
          result.rejectValue("attributeMappings[" + pos + "].destination.name", "Missing name for destination attribute");
        }
      }
      
      if (mapping.getSources() == null || mapping.getSources().isEmpty()) {
        if (mapping.getDestination() != null && Boolean.TRUE.equals(mapping.getDestination().getRequired())
            && mapping.getDestination().getDefaultValue() == null) {
          result.rejectValue("attributeMappings[" + pos + "]", "Attribute mapping has no sources and destination has no default value - illegal");
        }
      }
      else {
        int spos = 0;
        for (SignerIdentityAttribute source : mapping.getSources()) {
          if (source.getType() != null && !SignerIdentityAttribute.SAML_TYPE.equalsIgnoreCase(source.getType())) {
            result.rejectValue("attributeMappings[" + pos + "].sources[" + spos + "].type",
              String.format("Unsupported attribute type - %s", source.getType()));
          }
          if (!StringUtils.hasText(source.getName())) {
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
