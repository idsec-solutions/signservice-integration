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
package se.idsec.signservice.integration.dss;

import java.io.Serial;
import java.io.Serializable;

import org.w3c.dom.Element;

import jakarta.xml.bind.JAXBException;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.core.error.impl.SignServiceProtocolException;
import se.swedenconnect.schemas.csig.dssext_1_1.SignRequestExtension;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTasks;
import se.swedenconnect.schemas.dss_1_0.AnyType;
import se.swedenconnect.schemas.dss_1_0.InputDocuments;
import se.swedenconnect.schemas.dss_1_0.SignRequest;
import se.swedenconnect.xml.jaxb.JAXBMarshaller;
import se.swedenconnect.xml.jaxb.JAXBSerializable;
import se.swedenconnect.xml.jaxb.JAXBUnmarshaller;

/**
 * A wrapper for easier access to the DSS extensions.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class SignRequestWrapper extends SignRequest implements Serializable {

  /** For serialization. */
  @Serial
  private static final long serialVersionUID = 8934202280623051779L;

  /** Object factory for DSS objects. */
  private static final se.swedenconnect.schemas.dss_1_0.ObjectFactory dssObjectFactory =
      new se.swedenconnect.schemas.dss_1_0.ObjectFactory();

  /** The wrapped SignRequest. */
  private final JAXBSerializable<SignRequest> signRequest;

  /** The SignRequest extension (stored in OptionalInputs). */
  private transient SignRequestExtension signRequestExtension;

  /** The SignTasks element (stored in InputDocuments). */
  private transient SignTasks signTasks;

  /**
   * Constructor setting up an empty {@code SignRequest}.
   */
  public SignRequestWrapper() {
    this.signRequest = new JAXBSerializable<>(dssObjectFactory.createSignRequest(), SignRequest.class);
  }

  /**
   * Constructor.
   *
   * @param signRequest the request to wrap.
   */
  public SignRequestWrapper(final SignRequest signRequest) {
    this.signRequest = new JAXBSerializable<>(signRequest, SignRequest.class);
  }

  /**
   * Gets the wrapped SignRequest object.
   *
   * @return the wrapped SignRequest object
   */
  public SignRequest getWrappedSignRequest() {
    return this.signRequest.get();
  }

  /**
   * Utility method that obtains the SignRequestExtension (from the OptionalInputs).
   *
   * @return the SignRequestExtension
   * @throws SignServiceProtocolException for unmarshalling errors
   */
  public SignRequestExtension getSignRequestExtension() throws SignServiceProtocolException {
    if (this.signRequestExtension != null) {
      return this.signRequestExtension;
    }
    if (!this.getWrappedSignRequest().isSetOptionalInputs()) {
      return null;
    }
    final Element signRequestExtensionElement = this.getWrappedSignRequest().getOptionalInputs()
        .getAnies()
        .stream()
        .filter(e -> "SignRequestExtension".equals(e.getLocalName()))
        .filter(e -> DssUtils.DSS_EXT_NAMESPACE.equals(e.getNamespaceURI()))
        .findFirst()
        .orElse(null);
    if (signRequestExtensionElement != null) {
      try {
        this.signRequestExtension =
            JAXBUnmarshaller.unmarshall(signRequestExtensionElement, SignRequestExtension.class);
      }
      catch (final JAXBException e) {
        log.error("Failed to unmarshall SignRequestExtension - {}", e.getMessage(), e);
        throw new SignServiceProtocolException("Failed to decode SignRequestExtension", e);
      }
    }
    return this.signRequestExtension;
  }

  /**
   * Assigns the SignRequestExtension by adding it to OptionalInputs.
   * <p>
   * Note: If the OptionalInputs already contains data it is overwritten.
   * </p>
   *
   * @param signRequestExtension the extension to add
   * @throws SignServiceProtocolException for JAXB errors
   */
  public void setSignRequestExtension(final SignRequestExtension signRequestExtension)
      throws SignServiceProtocolException {
    if (signRequestExtension == null) {
      this.getWrappedSignRequest().setOptionalInputs(null);
      this.signRequestExtension = null;
      return;
    }

    try {
      final AnyType optionalInputs = dssObjectFactory.createAnyType();
      optionalInputs.getAnies().add(JAXBMarshaller.marshall(signRequestExtension).getDocumentElement());
      this.getWrappedSignRequest().setOptionalInputs(optionalInputs);
      this.signRequestExtension = signRequestExtension;
    }
    catch (final JAXBException e) {
      log.error("Failed to marshall SignRequestExtension - {}", e.getMessage(), e);
      throw new SignServiceProtocolException("Failed to marshall SignRequestExtension", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public AnyType getOptionalInputs() {
    return this.getWrappedSignRequest().getOptionalInputs();
  }

  /** {@inheritDoc} */
  @Override
  public void setOptionalInputs(final AnyType value) {
    // Reset the signRequestExtension. It may be set as an AnyType.
    this.signRequestExtension = null;
    this.getWrappedSignRequest().setOptionalInputs(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetOptionalInputs() {
    return this.getWrappedSignRequest().isSetOptionalInputs();
  }

  /** {@inheritDoc} */
  @Override
  public InputDocuments getInputDocuments() {
    return this.getWrappedSignRequest().getInputDocuments();
  }

  /** {@inheritDoc} */
  @Override
  public void setInputDocuments(final InputDocuments value) {
    // Reset the signTasks variable. It may be set as an any type in the supplied value.
    this.signTasks = null;
    this.getWrappedSignRequest().setInputDocuments(value);
  }

  /**
   * Utility method that obtains the SignTasks element from the InputDocuments.
   *
   * @return the SignTasks element or null
   * @throws SignServiceProtocolException for unmarshalling errors
   */
  public SignTasks getSignTasks() throws SignServiceProtocolException {
    if (this.signTasks != null) {
      return this.signTasks;
    }
    if (this.getWrappedSignRequest().getInputDocuments() == null
        || !this.getWrappedSignRequest().getInputDocuments().isSetDocumentsAndTransformedDatasAndDocumentHashes()) {
      return null;
    }
    for (final Object o : this.getWrappedSignRequest().getInputDocuments()
        .getDocumentsAndTransformedDatasAndDocumentHashes()) {
      if (o instanceof AnyType) {
        final Element signTasksElement = ((AnyType) o).getAnies()
            .stream()
            .filter(e -> "SignTasks".equals(e.getLocalName()))
            .filter(e -> DssUtils.DSS_EXT_NAMESPACE.equals(e.getNamespaceURI()))
            .findFirst()
            .orElse(null);
        if (signTasksElement != null) {
          try {
            this.signTasks = JAXBUnmarshaller.unmarshall(signTasksElement, SignTasks.class);
            return this.signTasks;
          }
          catch (final JAXBException e) {
            log.error("Failed to unmarshall SignTasks - {}", e.getMessage(), e);
            throw new SignServiceProtocolException("Failed to decode SignTasks", e);
          }
        }
      }
    }
    return null;
  }

  /**
   * Utility method that add a SignTasks object to the InputDocuments.
   *
   * @param signTasks the object to add
   * @throws SignServiceProtocolException for marshalling errors
   */
  public void setSignTasks(final SignTasks signTasks) throws SignServiceProtocolException {
    this.signTasks = signTasks;
    if (this.getWrappedSignRequest().getInputDocuments() == null) {
      if (this.signTasks == null) {
        return;
      }
      this.getWrappedSignRequest().setInputDocuments(dssObjectFactory.createInputDocuments());
    }
    final Element signTasksElement;
    try {
      signTasksElement = JAXBMarshaller.marshall(this.signTasks).getDocumentElement();
    }
    catch (final JAXBException e) {
      log.error("Failed to marshall SignTasks - {}", e.getMessage(), e);
      throw new SignServiceProtocolException("Failed to marshall SignTasks", e);
    }

    for (final Object o : this.getWrappedSignRequest().getInputDocuments()
        .getDocumentsAndTransformedDatasAndDocumentHashes()) {
      if (o instanceof final AnyType other) {
        // Replace the entire object.
        other.unsetAnies();
        other.getAnies().add(signTasksElement);
        return;
      }
    }
    final AnyType other = dssObjectFactory.createAnyType();
    other.getAnies().add(signTasksElement);
    this.getWrappedSignRequest().getInputDocuments().getDocumentsAndTransformedDatasAndDocumentHashes().add(other);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetInputDocuments() {
    return this.getWrappedSignRequest().isSetInputDocuments();
  }

  /** {@inheritDoc} */
  @Override
  public String getRequestID() {
    return this.getWrappedSignRequest().getRequestID();
  }

  /** {@inheritDoc} */
  @Override
  public void setRequestID(final String value) {
    this.getWrappedSignRequest().setRequestID(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetRequestID() {
    return this.getWrappedSignRequest().isSetRequestID();
  }

  /** {@inheritDoc} */
  @Override
  public String getProfile() {
    return this.getWrappedSignRequest().getProfile();
  }

  /** {@inheritDoc} */
  @Override
  public void setProfile(final String value) {
    this.getWrappedSignRequest().setProfile(value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSetProfile() {
    return this.getWrappedSignRequest().isSetProfile();
  }

}
