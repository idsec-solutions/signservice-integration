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
package se.idsec.signservice.integration.document.impl;

import java.util.Base64;

import org.springframework.util.StringUtils;

import se.idsec.signservice.integration.core.validation.AbstractInputValidator;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.TbsDocument.EtsiAdesFormatRequirement;

/**
 * Validator for {@link TbsDocument} objects.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class TbsDocumentValidator extends AbstractInputValidator<TbsDocument, Void> {
  
  /** Validator for AdES reqs. */
  private final EtsiAdesFormatRequirementValidator adesFormatRequirementValidator = new EtsiAdesFormatRequirementValidator();
  
  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(final TbsDocument object, final String objectName, final Void hint) {
    ValidationResult result = new ValidationResult(objectName);
    if (object == null) {
      return result;
    }
    if (!StringUtils.hasText(object.getContent())) {
      result.rejectValue("content", "No document content set in TbsDocument");
    }
    if (!StringUtils.hasText(object.getMimeType())) {
      result.rejectValue("mimeType", "No mimeType set in TbsDocument");
    }
    result.setFieldErrors(
      this.adesFormatRequirementValidator.validate(object.getAdesRequirement(), "adesRequirement", null));
    
    return result;
  }


  /**
   * Validator for {@link EtsiAdesFormatRequirement} objects.
   */
  public static class EtsiAdesFormatRequirementValidator extends AbstractInputValidator<EtsiAdesFormatRequirement, Void> {

    /** {@inheritDoc} */
    @Override
    public ValidationResult validate(EtsiAdesFormatRequirement object, String objectName, Void hint) {
      ValidationResult result = new ValidationResult(objectName);
      if (object == null) {
        return result;
      }
      if (TbsDocument.AdesType.EPES.equals(object.getAdesFormat()) && !StringUtils.hasText(object.getSignaturePolicy())) {
        result.rejectValue("signaturePolicy", 
          "AdES requirement states Extended Policy Electronic Signature but no signature policy has been given");
      }
      if (object.getAdesObject() != null) {
        try {
          Base64.getDecoder().decode(object.getAdesObject());
        }
        catch (Exception e) {
          result.rejectValue("adesObject", "Invalid Base64 encoding for adesObject");
        }
      }
      return result;
    }

  }

}
