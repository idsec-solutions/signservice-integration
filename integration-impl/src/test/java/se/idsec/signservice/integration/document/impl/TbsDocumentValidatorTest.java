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
package se.idsec.signservice.integration.document.impl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.testbase.TestEtsiAdesRequirementValidator;

/**
 * Test cases for {@code TbsDocumentValidator}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class TbsDocumentValidatorTest {

  @Test
  public void testBadInit() throws Exception {
    try {
      new TbsDocumentValidator(null);
      Assertions.fail("Expected IllegalArgumentException");
    }
    catch (IllegalArgumentException e) {
    }
  }

  @Test
  public void testNull() throws Exception {
    TbsDocumentValidator validator = new TbsDocumentValidator(new TestEtsiAdesRequirementValidator());
    ValidationResult result = validator.validate(null, "tbs", null);
    Assertions.assertFalse(result.hasErrors());
  }

  @Test
  public void missingContent() throws Exception {
    TbsDocumentValidator validator = new TbsDocumentValidator(new TestEtsiAdesRequirementValidator());
    TbsDocument tbs = TbsDocument.builder()
        .id("ID")
        .content(null)
        .mimeType(DocumentType.XML)
        .build();
    ValidationResult result = validator.validate(tbs, "tbs", null);
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertNull(result.getGlobalError());
    Assertions.assertTrue(result.getFieldErrors().size() == 1);
    Assertions.assertNotNull(result.getFieldErrors().get("tbs.content"));

    // The same with an empty string ...
    tbs = TbsDocument.builder()
        .id("ID")
        .content("    ")
        .mimeType(DocumentType.XML)
        .build();
    result = validator.validate(tbs, "tbs", null);
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertTrue(result.getFieldErrors().size() == 1);
    Assertions.assertNotNull(result.getFieldErrors().get("tbs.content"));
  }

  @Test
  public void missingMimeType() throws Exception {
    TbsDocumentValidator validator = new TbsDocumentValidator(new TestEtsiAdesRequirementValidator());
    TbsDocument tbs = TbsDocument.builder()
        .id("ID")
        .content("Hello")
        .mimeType((DocumentType) null)
        .build();
    ValidationResult result = validator.validate(tbs, "tbs", null);
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertNull(result.getGlobalError());
    Assertions.assertTrue(result.getFieldErrors().size() == 1);
    Assertions.assertNotNull(result.getFieldErrors().get("tbs.mimeType"));

    // The same with an empty string ...
    tbs = TbsDocument.builder()
        .id("ID")
        .content("Hello")
        .mimeType("   ")
        .build();
    result = validator.validate(tbs, "tbs", null);
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertTrue(result.getFieldErrors().size() == 1);
    Assertions.assertNotNull(result.getFieldErrors().get("tbs.mimeType"));
  }

  @Test
  public void missingContentAndMimeType() throws Exception {
    TbsDocumentValidator validator = new TbsDocumentValidator(new TestEtsiAdesRequirementValidator());
    TbsDocument tbs = TbsDocument.builder()
        .id("ID")
        .content(null)
        .mimeType((DocumentType) null)
        .build();
    ValidationResult result = validator.validate(tbs, "tbs", null);
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertNull(result.getGlobalError());
    Assertions.assertTrue(result.getFieldErrors().size() == 2);
    Assertions.assertNotNull(result.getFieldErrors().get("tbs.content"));
    Assertions.assertNotNull(result.getFieldErrors().get("tbs.mimeType"));

    // The same with an empty string ...
    tbs = TbsDocument.builder()
        .id("ID")
        .content("   ")
        .mimeType("   ")
        .build();
    result = validator.validate(tbs, "tbs", null);
    Assertions.assertTrue(result.hasErrors());
    Assertions.assertTrue(result.getFieldErrors().size() == 2);
    Assertions.assertNotNull(result.getFieldErrors().get("tbs.content"));
    Assertions.assertNotNull(result.getFieldErrors().get("tbs.mimeType"));
  }

}
