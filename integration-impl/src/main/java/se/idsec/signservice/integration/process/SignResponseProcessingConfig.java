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
package se.idsec.signservice.integration.process;

import java.util.HashMap;
import java.util.Map;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.litsec.swedisheid.opensaml.saml2.authentication.LevelofAssuranceAuthenticationContextURI;

/**
 * Configuration for processing a {@code SignResponse} message. This class represents the "static" configuration
 * settings. Also see the {@link SignResponseProcessingParameters} class that is parameters supplied by the caller.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@ToString
@Slf4j
public class SignResponseProcessingConfig {

  /** The default for the maximum allowed age for a response given in milliseconds. 3 minutes. */
  public final static long DEFAULT_MAXIMUM_ALLOWED_RESPONSE_AGE = 180000L;

  /**
   * The default for the allowed number of milliseconds that we allow our clock to differ from the SignService clock. 1
   * minute.
   */
  public static final long DEFAULT_ALLOWED_CLOCK_SKEW = 60000L;

  /** The default time we allow for processing at the server side. Default is 10 minutes. */
  public static final long DEFAULT_MAXIMUM_ALLOWED_PROCESSING_TIME = 600000L;

  /**
   * Flag that tells whether the processing and validation steps should be "extra" strict and look for every little
   * thing that deviates from the specifications. The default is {@code false}. Turning on this setting is mainly
   * intended for testing of a SignService, and should not be active in a production setup.
   * 
   * @param strictProcessing
   *          whether to use strict processing or not
   * @return whether to use strict processing or not
   */
  @Getter
  @Setter
  private boolean strictProcessing = false;

  /**
   * The maximum allowed age for a response given in milliseconds. The default is
   * {@value #DEFAULT_MAXIMUM_ALLOWED_RESPONSE_AGE}.
   * 
   * @param maximumAllowedResponseAge
   *          maximum allowed age for a response
   * @return maximum allowed age for a response
   */
  @Getter
  @Setter
  private long maximumAllowedResponseAge = DEFAULT_MAXIMUM_ALLOWED_RESPONSE_AGE;

  /**
   * The allowed number of milliseconds that we allow our clock to differ from the SignService clock. The default is
   * {@value #DEFAULT_ALLOWED_CLOCK_SKEW}.
   * 
   * @param allowedClockSkew
   *          maximum allowed clock skew
   * @return maximum allowed clock skew
   */
  @Getter
  @Setter
  private long allowedClockSkew = DEFAULT_ALLOWED_CLOCK_SKEW;

  /**
   * The allowed number of milliseconds that we allow processing at the server side to go on, that is, the time from
   * when we sent the request until we received the response.
   * 
   * @param maximumAllowedProcessingTime
   *          maximum allowed server processing time
   * @return maximum allowed server processing time
   */
  @Getter
  @Setter
  private long maximumAllowedProcessingTime = DEFAULT_MAXIMUM_ALLOWED_PROCESSING_TIME;

  /**
   * Tells whether the deprecated <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/03_-_Registry_for_Identifiers.html#sign-message-authentication-context-uris">Sign
   * Message Authentication Context URIs be allowed</a>. The default is {@code true}.
   * 
   * @param allowSigMessageUris
   *          whether Sign Message Authentication Context URIs are allowed or not
   * @return whether Sign Message Authentication Context URIs are allowed or not
   */
  @Getter
  @Setter
  private boolean allowSigMessageUris = true;

  /**
   * The mapping between Authentication Context URIs and their corresponding Sign Message Authentication Context URIs.
   * Only relevant if {@code allowSigMessageUris} is set. If not assigned, the defaults given in
   * <a href="https://docs.swedenconnect.se/technical-framework/latest/03_-_Registry_for_Identifiers.html">Swedish eID
   * Framework - Registry for identifiers</a> will be used.
   * 
   * @param sigMessageUriMap
   *          authentication context URI mapping
   */
  @Setter
  private Map<String, String> sigMessageUriMap;

  /**
   * Flag telling whether we require the assertion from where the user authenticated for signature to be present in the
   * sign response. The default is {@code false}.
   * 
   * @param requireAssertion
   *          whether user assertion is required in the sign response
   * @return whether user assertion is required in the sign response
   */
  @Getter
  @Setter
  private boolean requireAssertion = false;

  /**
   * A {@code SignResponseProcessingConfig} with default settings.
   * 
   * @return default config settings
   */
  public static SignResponseProcessingConfig defaultSignResponseProcessingConfig() {
    SignResponseProcessingConfig config = new SignResponseProcessingConfig();
    config.setSigMessageUriMap(getDefaultAuthnContextMappings());
    return config;
  }

  /**
   * Gets the mapping between Authentication Context URIs and their corresponding Sign Message Authentication Context
   * URIs. Only relevant if {@code allowSigMessageUris} is set. If not assigned, the defaults given in
   * <a href="https://docs.swedenconnect.se/technical-framework/latest/03_-_Registry_for_Identifiers.html">Swedish eID
   * Framework - Registry for identifiers</a> will be used.
   * 
   * @return authentication context URI mapping
   */
  public Map<String, String> getSigMessageUriMap() {
    if (this.allowSigMessageUris && this.sigMessageUriMap == null) {
      this.sigMessageUriMap = getDefaultAuthnContextMappings();
      log.info("No AuthnContext URI mapping assigned. Using sigMessageUriMap: {}", this.sigMessageUriMap);      
    }
    return this.sigMessageUriMap;
  }

  /**
   * Gets the defaults given in
   * <a href="https://docs.swedenconnect.se/technical-framework/latest/03_-_Registry_for_Identifiers.html">Swedish eID
   * Framework - Registry for identifiers</a>.
   * 
   * @return authentication context URI mapping
   */
  private static Map<String, String> getDefaultAuthnContextMappings() {
    Map<String, String> map = new HashMap<>();
    for (LevelofAssuranceAuthenticationContextURI.LoaEnum e : LevelofAssuranceAuthenticationContextURI.LoaEnum.values()) {
      if (!e.isSignatureMessageUri()) {
        LevelofAssuranceAuthenticationContextURI.LoaEnum s = LevelofAssuranceAuthenticationContextURI.LoaEnum.plusSigMessage(e);
        if (s != null) {
          map.put(e.getUri(), s.getUri());
        }
      }
    }
    return map;
  }

}
