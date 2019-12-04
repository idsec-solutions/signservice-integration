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
package se.idsec.signservice.integration.document.xml;

import java.io.ByteArrayInputStream;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.w3c.dom.Document;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.impl.AbstractTbsDocumentProcessor;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;

/**
 * Implementation of the XML TBS document processor.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XmlTbsDocumentProcessor extends AbstractTbsDocumentProcessor<Document> {

  /**
   * Constructor.
   */
  public XmlTbsDocumentProcessor() {
  }

  /** {@inheritDoc} */
  @Override
  public boolean supports(final TbsDocument document) {
    try {
      return DocumentType.fromMimeType(document.getMimeType()) == DocumentType.XML;
    }
    catch (IllegalArgumentException e) {
      return false;
    }
  }

  /** {@inheritDoc} */
  @Override
  public SignTaskData process(final TbsDocument document, final IntegrationServiceConfiguration config)
      throws SignServiceIntegrationException {
    return null;
  }

  /** {@inheritDoc} */
  @Override
  protected Document validateDocumentContent(final byte[] content, final TbsDocument document,
      final IntegrationServiceConfiguration config, final String fieldName) throws InputValidationException {

    try {
      Document xmlDocument = XMLObjectProviderRegistrySupport.getParserPool().parse(new ByteArrayInputStream(content));
      log.debug("{}: Successfully validated XML document (doc-id: {})", CorrelationID.id(), document.getId());
      return xmlDocument;
    }
    catch (XMLParserException e) {
      final String msg = String.format("Failed to load XML content for document '%s' - %s", document.getId(), e.getMessage());
      log.error("{}: {}", CorrelationID.id(), msg, e);
      throw new InputValidationException(fieldName + ".content", msg, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  protected Class<Document> getDocumentContentType() {
    return Document.class;
  }

}
