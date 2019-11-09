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
package se.idsec.signservice.integration;

/**
 * An interface that is the return type of the {@link SignServiceIntegrationService#createSignRequest(SignRequestInput)}
 * and represents the information needed to send a {@code dss:SignRequest} to a signature service.
 * 
 * <p>
 * Chapter 3 of <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/ELN-0607_-_Implementation_Profile_for_using_DSS_in_Central_Signing_Services.html#http-post-binding">Implementation
 * Profile for using OASIS DSS in Central Signing Services</a> describes how a sign request is transfered to the
 * signature service. Below is an example of an XHTML form:
 * 
 * <pre>
 * {@code
 * <?xml version='1.0' encoding='UTF-8'?>
 * <!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.1//EN' 'http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd'>
 * <html xmlns='http://www.w3.org/1999/xhtml' xml:lang='en'>
 * <body onload='document.forms[0].submit()'>
 *   <noscript>
 *     <p><strong>Note:</strong> Since your browser does not support JavaScript,
 *     you must press the Continue button once to proceed.</p>
 *   </noscript>
 *   <form action='https://sig.example.com/signrequest' method='post'>
 *     <input type='hidden' name='Binding' value='POST/XML/1.0'/>
 *     <input type='hidden' name='RelayState' value='56345145a482995d'/>
 *     <input type='hidden' name='EidSignRequest' value='PD94bWC...WVzdD4='/>
 *     <noscript>
 *       <input type='submit' value='Continue'/>
 *     </noscript>
 *   </form>
 * </body>}
 * </pre>
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignRequestData {

  /**
   * Returns the signature state for this operation.
   * 
   * <p>
   * When the signature requester receives the {@code dss:SignResponse} message from the signature service it completes
   * the signature operation by invoking
   * {@link SignServiceIntegrationService#processSignResponse(String, SignatureState, SignResponseProcessingParameters)}
   * The signature state must be supplied to this method.
   * </p>
   * 
   * @return the signature state for this operation
   */
  SignatureState getSignatureState();

  /**
   * Returns the Base64-encoded {@code dss:SignRequest} message that is to be posted to the signature service.
   * 
   * <p>
   * This value should be posted to the signature service in a form where the parameter has the name
   * {@code EidSignRequest}. See example above.
   * 
   * @return the encoded {@code dss:SignRequest} message
   */
  String getSignRequest();

  /**
   * Returns the relay state. This is the same value as the {@code RequestID} attribute of the {@code dss:SignRequest}
   * <b>and</b> {@link SignatureState#getId()}.
   * 
   * <p>
   * This value should be posted to the signature service in a form where the parameter has the name {@code RelayState}.
   * See example above.
   * </p>
   * 
   * <p>
   * <b>Note:</b> The RelayState used in communication with the signature service has the same name as the parameter
   * used in SAML authentication requests, <b>but</b> in SAML the value is opaque and does not bind to any value in the
   * request as is the case for signature service communication. An unlucky re-use of the term RelayState.
   * </p>
   * 
   * @return the relay state value
   */
  String getRelayState();

  /**
   * Returns an identifier for the binding of the message that is to be sent.
   * 
   * <p>
   * This value should be posted to the signature service in a form where the parameter has the name {@code Binding}.
   * See example above.
   * </p>
   * 
   * <p>
   * Currently, the only supported value is "POST/XML/1.0".
   * </p>
   * 
   * @return the binding identifier
   */
  String getBinding();

  /**
   * Returns the signature service URL to which the {@code dss:SignRequest} should be posted.
   * 
   * @return signature service destination URL
   */
  String getDestinationUrl();

}
