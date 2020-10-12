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
package se.idsec.signservice.integration.config.impl;

import lombok.ToString;
import se.idsec.signservice.integration.core.FileResource;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;

/**
 * An extension to {@link PdfSignatureImageTemplate} that lets us assign the resource of the SVG image file.
 * 
 * @deprecated since 1.1.0, the {@link PdfSignatureImageTemplate} has a
 *             {@link PdfSignatureImageTemplate#setSvgImageFile(se.idsec.signservice.integration.core.FileResource)}
 *             method that should be used
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Deprecated
@ToString(callSuper = true)
public class PdfSignatureImageTemplateExt extends PdfSignatureImageTemplate {

  /**
   * Default constructor.
   */
  public PdfSignatureImageTemplateExt() {
    super();
  }

  /**
   * Assigns the resource holding the SVG image.
   * 
   * @param resource
   *          the SVG resource
   * @throws IllegalArgumentException
   *           if the resource can not be read
   * @deprecated Use
   *             {@link PdfSignatureImageTemplate#setSvgImageFile(se.idsec.signservice.integration.core.FileResource)} instead
   */
  @Deprecated
  public void setResource(final String resource) throws IllegalArgumentException {
    if (resource != null) {
      try {
        FileResource fileResource = FileResource.builder()
          .resource(resource).eagerlyLoadContents(true).build();
        fileResource.afterPropertiesSet();
        this.setSvgImageFile(fileResource);
      }
      catch (Exception e) {
        throw new IllegalArgumentException("Failed to read resource", e);
      }
    }
  }

}
