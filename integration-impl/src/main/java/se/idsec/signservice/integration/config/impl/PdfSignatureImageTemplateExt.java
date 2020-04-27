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

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.springframework.core.io.Resource;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import se.idsec.signservice.integration.core.Extension;
import se.idsec.signservice.integration.core.ObjectBuilder;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;

/**
 * An extension to {@link PdfSignatureImageTemplate} that lets us assign the resource of the SVG image file.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@ToString(callSuper = true)
public class PdfSignatureImageTemplateExt extends PdfSignatureImageTemplate {

  /**
   * The resource of the SVG image.
   * 
   * @return the resource of the SVG image
   */
  @Getter
  @JsonIgnore
  private Resource resource;

  /**
   * Default constructor.
   */
  public PdfSignatureImageTemplateExt() {
    super();
  }

  /**
   * Copy constructor.
   * 
   * @param template
   *          the template to assign
   */
  public PdfSignatureImageTemplateExt(final PdfSignatureImageTemplate template) {
    super(template.getReference(), template.getImage(), template.getWidth(), template.getHeight(), template.isIncludeSignerName(),
      template.isIncludeSigningTime(), template.getFields(), template.getExtension());
  }

  @Builder(builderMethodName = "createBuilder")
  public PdfSignatureImageTemplateExt(final String reference, final String image, final Resource resource, final Integer width,
      final Integer height, final boolean includeSignerName, final boolean includeSigningTime, final Map<String, String> fields, 
      final Extension extension) {
    super(reference, image, width, height, includeSignerName, includeSigningTime, fields, extension);
    this.setResource(resource);
  }

  /**
   * Assigns the resource holding the SVG image. The method also assigns the {@code image} property by getting the
   * contents of the resource and assigning it using {@link #setImage(String)}.
   * 
   * @param resource
   *          the SVG resource
   * @throws IllegalArgumentException
   *           if the resource can not be read
   */
  public void setResource(final Resource resource) throws IllegalArgumentException {
    this.resource = resource;
    if (this.resource != null) {
      try {
        this.setImage(IOUtils.toString(this.resource.getInputStream(), StandardCharsets.UTF_8));
      }
      catch (Exception e) {
        throw new IllegalArgumentException("Failed to read resource", e);
      }
    }
  }

  /**
   * Builder for {@code PdfSignatureImageTemplateExt} objects.
   */
  public static class PdfSignatureImageTemplateExtBuilder implements ObjectBuilder<PdfSignatureImageTemplateExt> {
    // Since the base class has the Singular annotation on the fields property, we
    // want that as well, so we'll have to do some ugly fixes here ...
    //

    public PdfSignatureImageTemplateExtBuilder field(final String fieldKey, final String fieldValue) {
      if (this.fields == null) {
        this.fields = new HashMap<>();
      }
      this.fields.put(fieldKey, fieldValue);
      return this;
    }

    public PdfSignatureImageTemplateExtBuilder fields(final java.util.Map<? extends String, ? extends String> fields) {
      if (fields != null) {
        for (final java.util.Map.Entry<? extends String, ? extends String> e : fields.entrySet()) {
          this.field(e.getKey(), e.getValue());
        }
      }
      return this;
    }

    public PdfSignatureImageTemplateExtBuilder clearFields() {
      if (this.fields != null) {
        this.fields.clear();
      }
      return this;
    }

  }

}
