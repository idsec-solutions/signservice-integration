/*
 * Copyright 2019-2020 IDsec Solutions AB
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

import org.apache.commons.lang.StringUtils;

import se.idsec.signservice.integration.authentication.AuthnRequirements;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.validation.AbstractInputValidator;
import se.idsec.signservice.integration.core.validation.ValidationResult;

/**
 * Validator for {@link AuthnRequirements} objects.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AuthnRequirementsValidator extends AbstractInputValidator<AuthnRequirements, IntegrationServiceConfiguration> {

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(final AuthnRequirements object, final String objectName, 
      final IntegrationServiceConfiguration hint) {
    
    final ValidationResult result = new ValidationResult(objectName);

    if ((object == null || StringUtils.isBlank(object.getAuthnServiceID()))
        && StringUtils.isBlank(hint.getDefaultAuthnServiceID())) {
      result.rejectValue("authnServiceID", String.format(
        "Request does not contain an authnServiceID and policy '%s' has no default value", hint.getPolicy()));
    }
    if ((object == null || StringUtils.isBlank(object.getAuthnContextRef()))
        && StringUtils.isBlank(hint.getDefaultAuthnContextRef())) {
      result.rejectValue("authnContextRef", String.format(
        "Request does not contain an authnContextRef and policy '%s' has no default value", hint.getPolicy()));
    }
    if (object != null && object.getRequestedSignerAttributes() != null) {
      int pos = 0;
      for (SignerIdentityAttributeValue a : object.getRequestedSignerAttributes()) {
        if (a.getType() != null && !SignerIdentityAttribute.SAML_TYPE.equalsIgnoreCase(a.getType())) {
          result.rejectValue("requestedSignerAttributes[" + pos + "].type", "The only supported attribute type is 'saml'");
        }
        if (StringUtils.isBlank(a.getName())) {
          result.rejectValue("requestedSignerAttributes[" + pos + "].name", "Missing attribute name");          
        }
        if (StringUtils.isBlank(a.getValue())) {
          result.rejectValue("requestedSignerAttributes[" + pos + "].value", "Missing attribute value");
        }
        pos++;
      }
    }

    return result;
  }

}
