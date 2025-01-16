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
package se.idsec.signservice.integration.document.impl;

import jakarta.annotation.Nullable;
import org.apache.commons.lang3.StringUtils;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.validation.AbstractInputValidator;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.TbsDocument;

/**
 * Validator for {@link TbsDocument} objects.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class TbsDocumentValidator extends AbstractInputValidator<TbsDocument, IntegrationServiceConfiguration> {

  /** Validator for AdES reqs. */
  private final EtsiAdesRequirementValidator adesRequirementValidator;

  /**
   * Constructor.
   *
   * @param adesRequirementValidator validatorfor AdES requirements
   */
  public TbsDocumentValidator(final EtsiAdesRequirementValidator adesRequirementValidator) {
    if (adesRequirementValidator == null) {
      throw new IllegalArgumentException("adesRequirementValidator must not be null");
    }
    this.adesRequirementValidator = adesRequirementValidator;
  }

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(final TbsDocument object, @Nullable final String objectName,
      final IntegrationServiceConfiguration hint) {
    final ValidationResult result = new ValidationResult(objectName);
    if (object == null) {
      return result;
    }
    if (StringUtils.isBlank(object.getContent()) && StringUtils.isBlank(object.getContentReference())) {
      result.rejectValue("content", "No document content set in TbsDocument");
    }
    if (StringUtils.isNotBlank(object.getContentReference()) && hint.isStateless()) {
      result.rejectValue("contentReference", "Can not pass contentReference for stateless profile policy");
    }
    if (StringUtils.isNotBlank(object.getContent()) && StringUtils.isNotBlank(object.getContentReference())
        && !hint.isStateless()) {
      result.reject("Both content and contentReference are set - not allowed");
    }
    if (StringUtils.isBlank(object.getMimeType())) {
      result.rejectValue("mimeType", "No mimeType set in TbsDocument");
    }
    result.setFieldErrors(
        this.adesRequirementValidator.validate(object.getAdesRequirement(), "adesRequirement", null));

    return result;
  }

}
