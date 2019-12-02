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

import se.idsec.signservice.integration.certificate.CertificateAttributeMapping;
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
      IntegrationServiceConfiguration hint, final String correlationID) {
    
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
      else if (mapping.getSources() == null || mapping.getSources().isEmpty()) {
        if (Boolean.TRUE.equals(mapping.getDestination().getRequired())
            && mapping.getDestination().getDefaultValue() == null) {
          result.rejectValue("attributeMappings[" + pos + "]", "Attribute mapping has no sources and destination has no default value - illegal");
        }
      }
      pos++;
    }
    
    return result;
  }

}
