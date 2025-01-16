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
package se.idsec.signservice.integration.state;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.Singular;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.core.ObjectBuilder;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.integration.signmessage.SignMessageParameters;
import se.idsec.signservice.integration.state.impl.DefaultSignatureState;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.schemas.dss_1_0.SignRequest;
import se.swedenconnect.xml.jaxb.JAXBMarshaller;
import se.swedenconnect.xml.jaxb.JAXBUnmarshaller;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;

/**
 * Representation of the signature session state. See {@link DefaultSignatureState}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@JsonInclude(Include.NON_NULL)
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = { "signRequest" })
@Slf4j
public class SignatureSessionState implements Serializable {

  /** For serialization. */
  @Serial
  private static final long serialVersionUID = 6334324655251433759L;

  /**
   * The owner identity of this operaration. This is set in the cases when the SignService Integration Service is
   * running in stateful mode. It is primary useful when the SignService Integration Service is running as a stand-alone
   * service.
   */
  @JsonIgnore
  @Getter
  @Setter
  private String ownerId;

  /**
   * The correlation ID for this session/process.
   */
  @Getter
  @Setter
  private String correlationId;

  /**
   * The policy under which the operation is executing.
   */
  @Setter
  @Getter
  private String policy;

  /**
   * The URL to which the user agent along with the sign response message should be directed after a signature
   * operation.
   */
  @Setter
  @Getter
  private String expectedReturnUrl;

  /**
   * The document(s) to be signed along with a per-document signing requirements and parameters.
   */
  @Setter
  @Getter
  @Singular
  private List<TbsDocument> tbsDocuments;

  /**
   * The sign message that was ordered by the initiator.
   */
  @Setter
  @Getter
  private SignMessageParameters signMessage;

  /**
   * The SignRequest that was passed to the signature service.
   */
  @Setter
  @JsonIgnore
  private SignRequestWrapper signRequest;

  /**
   * The Base64-encoded SignRequest. Used in cases when the state is passed back to the caller (via REST).
   */
  @Setter
  private String encodedSignRequest;

  /**
   * Gets the encoded SignRequest.
   */
  public String getEncodedSignRequest() {
    if (this.encodedSignRequest != null) {
      return this.encodedSignRequest;
    }
    if (this.signRequest != null) {
      try {
        this.encodedSignRequest =
            DOMUtils.nodeToBase64(JAXBMarshaller.marshall(this.signRequest.getWrappedSignRequest()));
      }
      catch (final Exception e) {
        log.error("Failed to marshall SignRequest", e);
      }
    }
    return this.encodedSignRequest;
  }

  /**
   * Gets the SignRequest that was passed to the signature service.
   */
  public SignRequestWrapper getSignRequest() {
    if (this.signRequest != null) {
      return this.signRequest;
    }
    if (this.encodedSignRequest != null) {
      try {
        this.signRequest = new SignRequestWrapper(
            JAXBUnmarshaller.unmarshall(DOMUtils.base64ToDocument(this.encodedSignRequest), SignRequest.class));
      }
      catch (final Exception e) {
        log.error("Failed to unmarshall encoded SignRequest", e);
      }
    }
    return this.signRequest;
  }

  /**
   * Builder for {@code SignatureSessionState}.
   */
  public static class SignatureSessionStateBuilder implements ObjectBuilder<SignatureSessionState> {
    // Lombok
  }

}
