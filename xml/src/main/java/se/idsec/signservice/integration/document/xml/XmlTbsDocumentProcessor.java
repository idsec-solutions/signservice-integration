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

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
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

  /** The document factory. */
  private DocumentBuilderFactory documentFactory;
  
  /**
   * Constructor.
   */
  public XmlTbsDocumentProcessor() {
    this.documentFactory = DocumentBuilderFactory.newInstance();
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
  public SignTaskData process(final TbsDocument document, final IntegrationServiceConfiguration config) throws SignServiceIntegrationException {
    return null;
  }

  /** {@inheritDoc} */
  @Override
  protected Document validateDocumentContent(final TbsDocument document, final IntegrationServiceConfiguration config, final String fieldName)
      throws InputValidationException {
    
//    DocumentBuilder builder = this.documentFactory.newDocumentBuilder();
    
    // TODO
    
    return null;
  }

  /** {@inheritDoc} */
  @Override
  protected Class<Document> getDocumentContentType() {
    return Document.class;
  }

}
