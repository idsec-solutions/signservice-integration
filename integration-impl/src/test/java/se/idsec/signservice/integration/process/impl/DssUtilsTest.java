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
package se.idsec.signservice.integration.process.impl;

import org.joda.time.DateTime;
import org.junit.Assert;
import org.junit.Test;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Conditions;

import se.idsec.signservice.integration.dss.DssUtils;
import se.idsec.signservice.integration.testbase.TestBase;

/**
 * Test cases for DssUtils.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DssUtilsTest extends TestBase {

  @Test
  public void testToJAXB() throws Exception {
    
    Conditions conditions = (Conditions) XMLObjectSupport.buildXMLObject(Conditions.DEFAULT_ELEMENT_NAME);
    final DateTime currentTime = new DateTime();
    conditions.setNotBefore(currentTime.minusMinutes(1));
    conditions.setNotOnOrAfter(currentTime.plusMinutes(5));

    AudienceRestriction audienceRestriction = (AudienceRestriction) XMLObjectSupport.buildXMLObject(
      AudienceRestriction.DEFAULT_ELEMENT_NAME);
    Audience audience = (Audience) XMLObjectSupport.buildXMLObject(Audience.DEFAULT_ELEMENT_NAME);
    audience.setAudienceURI("http://www.example.com/test");
    audienceRestriction.getAudiences().add(audience);

    conditions.getAudienceRestrictions().add(audienceRestriction);

    se.swedenconnect.schemas.saml_2_0.assertion.Conditions jaxb = 
        DssUtils.toJAXB(conditions, se.swedenconnect.schemas.saml_2_0.assertion.Conditions.class);
    
    Assert.assertEquals(conditions.getNotBefore().getMillis(), jaxb.getNotBefore().toGregorianCalendar().getTimeInMillis());
    
  }
  
  
}
