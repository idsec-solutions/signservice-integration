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
package se.idsec.signservice.integration.process.impl;

import org.apache.commons.lang.StringUtils;

import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.authentication.impl.AuthnRequirementsValidator;
import se.idsec.signservice.integration.certificate.impl.SigningCertificateRequirementsValidator;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.validation.AbstractInputValidator;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.signmessage.impl.SignMessageParametersValidator;

/**
 * Validator for {@link SignRequestInput} objects.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SignRequestInputValidator extends AbstractInputValidator<SignRequestInput, IntegrationServiceConfiguration> {

  /** Validator for AuthnRequirements. */
  private final AuthnRequirementsValidator authnRequirementsValidator = new AuthnRequirementsValidator();

  /** Validator for SigningCertificateRequirements. */
  private final SigningCertificateRequirementsValidator signingCertificateRequirementsValidator = new SigningCertificateRequirementsValidator();
  
  /** Validator for SignMessageParametersValidator. */
  private final SignMessageParametersValidator signMessageParametersValidator = new SignMessageParametersValidator();

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(
      final SignRequestInput object, final String objectName, final IntegrationServiceConfiguration hint) {

    final ValidationResult result = new ValidationResult("signRequestInput");
    if (object == null) {
      result.reject("Missing signRequestInput");
      return result;
    }
    
    // SignRequesterID
    if (StringUtils.isBlank(object.getSignRequesterID()) && StringUtils.isBlank(hint.getDefaultSignRequesterID())) {
      result.rejectValue("signRequesterID", "No signRequesterID given and configuration does not contain a default value");
    }
    
    // ReturnUrl
    if (StringUtils.isBlank(object.getReturnUrl()) && StringUtils.isBlank(hint.getDefaultReturnUrl())) {
      result.rejectValue("returnUrl", "No returnUrl given and configuration does not contain a default value");
    }
    
    // AuthnRequirements
    result.setFieldErrors(this.authnRequirementsValidator.validate(
      object.getAuthnRequirements(), "authnRequirements", hint));

    // SigningCertificateRequirements
    result.setFieldErrors(this.signingCertificateRequirementsValidator.validate(
      object.getCertificateRequirements(), "certificateRequirements", hint));

    // SignMessageParametersValidator
    result.setFieldErrors(this.signMessageParametersValidator.validate(
      object.getSignMessageParameters(), "signMessageParameters", null));
    
    // TbsDocuments
    if (object.getTbsDocuments() == null || object.getTbsDocuments().isEmpty()) {
      result.rejectValue("tbsDocuments", "Missing document(s) to sign");
    }
    
    return result;
  }

}
