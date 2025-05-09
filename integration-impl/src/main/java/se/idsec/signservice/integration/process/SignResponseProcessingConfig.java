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
package se.idsec.signservice.integration.process;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import se.idsec.signservice.integration.SignResponseProcessingParameters;

import java.time.Duration;
import java.util.Optional;

/**
 * Configuration for processing a {@code SignResponse} message. This class represents the "static" configuration
 * settings. Also see the {@link SignResponseProcessingParameters} class that is parameters supplied by the caller.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@ToString
public class SignResponseProcessingConfig {

  /** The default for the maximum allowed age for a response. 3 minutes. */
  public final static Duration DEFAULT_MAXIMUM_ALLOWED_RESPONSE_AGE_DURATION = Duration.ofMinutes(3);

  /**
   * The default for the maximum allowed age for a response given in milliseconds.
   *
   * @deprecated Use {@link #DEFAULT_MAXIMUM_ALLOWED_RESPONSE_AGE_DURATION} instead
   */
  @Deprecated(since = "3.4.0", forRemoval = true)
  public final static long DEFAULT_MAXIMUM_ALLOWED_RESPONSE_AGE =
      DEFAULT_MAXIMUM_ALLOWED_RESPONSE_AGE_DURATION.toMillis();

  /**
   * The default for the maximum time that we allow our clock to differ from the SignService clock. 1 minute.
   */
  public static final Duration DEFAULT_ALLOWED_CLOCK_SKEW_DURATION = Duration.ofMinutes(1);

  /**
   * The default for the allowed number of milliseconds that we allow our clock to differ from the SignService clock.
   *
   * @deprecated Use {@link #DEFAULT_ALLOWED_CLOCK_SKEW_DURATION} instead
   */
  @Deprecated(since = "3.4.0", forRemoval = true)
  public static final long DEFAULT_ALLOWED_CLOCK_SKEW = 60000L;

  /** The default time we allow for processing at the server side. Default is 10 minutes. */
  public static final Duration DEFAULT_MAXIMUM_ALLOWED_PROCESSING_TIME_DURATION = Duration.ofMinutes(10);

  /**
   * The default time we allow for processing at the server side. Default is 10 minutes.
   *
   * @deprecated Use {@link #DEFAULT_MAXIMUM_ALLOWED_PROCESSING_TIME_DURATION} instead
   */
  @Deprecated(since = "3.4.0", forRemoval = true)
  public static final long DEFAULT_MAXIMUM_ALLOWED_PROCESSING_TIME = 600000L;

  /**
   * Flag that tells whether the processing and validation steps should be "extra" strict and look for every little
   * thing that deviates from the specifications. The default is {@code false}. Turning on this setting is mainly
   * intended for testing of a SignService, and should not be active in a production setup.
   */
  @Getter
  @Setter
  private boolean strictProcessing = false;

  /**
   * The maximum allowed age for a response. The default is {@link #DEFAULT_MAXIMUM_ALLOWED_RESPONSE_AGE_DURATION}.
   */
  @Getter
  @Setter
  private Duration maximumAllowedResponseAgeDuration = DEFAULT_MAXIMUM_ALLOWED_RESPONSE_AGE_DURATION;

  /**
   * The allowed duration that we allow our clock to differ from the SignService clock. The default is
   * {@link #DEFAULT_ALLOWED_CLOCK_SKEW_DURATION}.
   */
  @Getter
  @Setter
  private Duration allowedClockSkewDuration = DEFAULT_ALLOWED_CLOCK_SKEW_DURATION;

  /**
   * The allowed duration that we allow processing at the server side to go on, that is, the time from when we sent the
   * request until we received the response.
   */
  @Getter
  @Setter
  private Duration maximumAllowedProcessingTimeDuration = DEFAULT_MAXIMUM_ALLOWED_PROCESSING_TIME_DURATION;

  /**
   * Flag telling whether we require the assertion from where the user authenticated for signature to be present in the
   * sign response. The default is {@code false}.
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
    return new SignResponseProcessingConfig();
  }

  /**
   * The maximum allowed age for a response given in milliseconds.
   *
   * @return maximum allowed age for a response given in milliseconds
   * @deprecated Use {@link #getMaximumAllowedResponseAgeDuration()} instead
   */
  @Deprecated(since = "3.4.0", forRemoval = true)
  public long getMaximumAllowedResponseAge() {
    return Optional.ofNullable(this.maximumAllowedResponseAgeDuration)
        .map(Duration::toMillis)
        .orElse(DEFAULT_MAXIMUM_ALLOWED_RESPONSE_AGE_DURATION.toMillis());
  }

  /**
   * The maximum allowed age for a response given in milliseconds.
   *
   * @param maximumAllowedResponseAge maximum allowed age for a response given in milliseconds
   * @deprecated Use {@link #setMaximumAllowedResponseAgeDuration(Duration)} instead
   */
  @Deprecated(since = "3.4.0", forRemoval = true)
  public void setMaximumAllowedResponseAge(final long maximumAllowedResponseAge) {
    this.setMaximumAllowedResponseAgeDuration(Duration.ofMillis(maximumAllowedResponseAge));
  }

  /**
   * The allowed number of milliseconds that we allow our clock to differ from the SignService clock.
   *
   * @return allowed number of milliseconds that we allow our clock to differ from the SignService clock
   * @deprecated Use {@link #getAllowedClockSkewDuration()} instead
   */
  @Deprecated(since = "3.4.0", forRemoval = true)
  public long getAllowedClockSkew() {
    return Optional.ofNullable(this.allowedClockSkewDuration)
        .map(Duration::toMillis)
        .orElseGet(DEFAULT_ALLOWED_CLOCK_SKEW_DURATION::toMillis);
  }

  /**
   * The allowed number of milliseconds that we allow our clock to differ from the SignService clock.
   *
   * @param allowedClockSkew allowed number of milliseconds that we allow our clock to differ from the SignService
   *     clock
   * @deprecated Use {@link #setAllowedClockSkewDuration(Duration)} instead
   */
  @Deprecated(since = "3.4.0", forRemoval = true)
  public void setAllowedClockSkew(final long allowedClockSkew) {
    this.setAllowedClockSkewDuration(Duration.ofMillis(allowedClockSkew));
  }

  /**
   * The allowed number of milliseconds that we allow processing at the server side to go on, that is, the time from
   * when we sent the request until we received the response.
   *
   * @return maximum processing time in millis
   * @deprecated Use {@link #getMaximumAllowedProcessingTimeDuration()} instead
   */
  @Deprecated(since = "3.4.0", forRemoval = true)
  public long getMaximumAllowedProcessingTime() {
    return Optional.ofNullable(this.maximumAllowedProcessingTimeDuration)
        .map(Duration::toMillis)
        .orElse(DEFAULT_MAXIMUM_ALLOWED_PROCESSING_TIME_DURATION.toMillis());
  }

  /**
   * The allowed number of milliseconds that we allow processing at the server side to go on, that is, the time from
   * when we sent the request until we received the response.
   *
   * @param maximumAllowedProcessingTime maximum processing time in millis
   * @deprecated Use {@link #setMaximumAllowedProcessingTimeDuration(Duration)} instead
   */
  @Deprecated(since = "3.4.0", forRemoval = true)
  public void setMaximumAllowedProcessingTime(final long maximumAllowedProcessingTime) {
    this.setMaximumAllowedProcessingTimeDuration(Duration.ofMillis(maximumAllowedProcessingTime));
  }

  @PostConstruct
  public void init() {
    if (this.maximumAllowedResponseAgeDuration == null) {
      this.maximumAllowedResponseAgeDuration = DEFAULT_MAXIMUM_ALLOWED_RESPONSE_AGE_DURATION;
    }
    if (this.maximumAllowedResponseAgeDuration.isNegative()) {
      throw new IllegalArgumentException("Maximum allowed response age duration cannot be negative");
    }
    if (this.allowedClockSkewDuration == null) {
      this.allowedClockSkewDuration = DEFAULT_ALLOWED_CLOCK_SKEW_DURATION;
    }
    if (this.allowedClockSkewDuration.isNegative()) {
      throw new IllegalArgumentException("Allowed clock skew duration cannot be negative");
    }
    if (this.maximumAllowedProcessingTimeDuration == null) {
      this.maximumAllowedProcessingTimeDuration = DEFAULT_MAXIMUM_ALLOWED_PROCESSING_TIME_DURATION;
    }
    if (this.maximumAllowedProcessingTimeDuration.isNegative()) {
      throw new IllegalArgumentException("Maximum allowed processing time duration cannot be negative");
    }
  }

}
