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
package se.idsec.signservice.integration.document.pdf.signpage.impl;

import java.util.Base64;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;

import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.impl.PdfSignaturePageValidator;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePage.PdfSignatureImagePlacementConfiguration;
import se.idsec.signservice.integration.document.pdf.utils.PDDocumentUtils;

/**
 * An extension to {@link PdfSignaturePageValidator} that also validates that the PDF document is valid and may be loaded.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedPdfSignaturePageValidator extends PdfSignaturePageValidator {

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(
      final PdfSignaturePage object, final String objectName, final List<? extends PdfSignatureImageTemplate> hint) {
    final ValidationResult result = super.validate(object, objectName, hint);
    
    if (object.getPdfDocument() != null) {
      final String contents = object.getPdfDocument().getContents();
      // If contents is null, the base implementation has already reported an error ...
      //
      PDDocument document = null;
      if (contents != null) {
        try {
          byte[] bytes = Base64.getDecoder().decode(contents);
          document = PDDocumentUtils.load(bytes);
          
          // Check the placement configuration ...
          if (object.getImagePlacementConfiguration() != null) {
            final PdfSignatureImagePlacementConfiguration config = object.getImagePlacementConfiguration();
            if (config.getPage() != null) {
              if (config.getPage().intValue() > document.getNumberOfPages()) {
                result.rejectValue("imagePlacementConfiguration.page", String.format(
                  "Invalid page number. Document has %d page(s), but page is %d", document.getNumberOfPages(), config.getPage())); 
              }
            }
          }
        }
        catch (Exception e) {
          result.rejectValue("pdfDocument", "Invalid PDF document - can not be loaded");
        }
        finally {
          PDDocumentUtils.close(document);
        }
      }
    }
    
    return result;
  }

  

}
