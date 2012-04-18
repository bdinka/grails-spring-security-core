/* Copyright 2006-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.codehaus.groovy.grails.plugins.springsecurity

import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource
import org.springframework.security.web.util.RequestMatcher
import org.springframework.security.web.util.AntPathRequestMatcher
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.mock.web.MockHttpServletRequest

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class ChannelFilterInvocationSecurityMetadataSourceFactoryBeanTests extends GroovyTestCase {

	private _factory = new ChannelFilterInvocationSecurityMetadataSourceFactoryBean()

    private static final int entrySetSize = 3
    private static final int configAttributeIndex = 0

	void testGetObjectType() {
		assertSame DefaultFilterInvocationSecurityMetadataSource, _factory.objectType
	}

	void testIsSingleton() {
		assertTrue _factory.singleton
	}

	void testAfterPropertiesSet() {
		shouldFail(IllegalArgumentException) {
			_factory.afterPropertiesSet()
		}

		_factory.urlMatcher = new AntPathRequestMatcher("/**")
		shouldFail(IllegalArgumentException) {
			_factory.afterPropertiesSet()
		}

		_factory.definition = ["/foo1/**" : "secure_only:"]
        
		shouldFail(IllegalArgumentException) {
			_factory.afterPropertiesSet()
		}

		_factory.definition = ["/foo1/**": "REQUIRES_SECURE_CHANNEL"]
		_factory.afterPropertiesSet()
	}

	void testGetObject() {
        String patternFoo1 = "/foo1/**"
        String patternFoo2 = "/foo2/**"
        String patternFoo3 = "/foo3/**"

		_factory.urlMatcher = new AntPathRequestMatcher("/**")
		_factory.definition = ["/foo1/**": 'REQUIRES_SECURE_CHANNEL',
                               "/foo2/**": 'REQUIRES_INSECURE_CHANNEL',
                               "/foo3/**": 'ANY_CHANNEL']
		_factory.afterPropertiesSet()

		def object = _factory.object

        System.out.println("The object is: " + object)

		assertTrue object instanceof DefaultFilterInvocationSecurityMetadataSource
		def map = object.@requestMap
        
        System.out.println("The contents of the mpa are: " + map)

        assertTrue !map.isEmpty()
        assertNotNull map.entrySet()
        assertEquals map.entrySet().size(), entrySetSize

        boolean isFoundMatch = false;

        def mockHttpServletRequestFoo1 = new MockHttpServletRequest();
        mockHttpServletRequestFoo1.setServletPath(patternFoo1)
        mockHttpServletRequestFoo1.setPathInfo(null)
        mockHttpServletRequestFoo1.setQueryString(null)


        def mockHttpServletRequestFoo2 = new MockHttpServletRequest();
        mockHttpServletRequestFoo2.setServletPath(patternFoo2)
        mockHttpServletRequestFoo2.setPathInfo(null)
        mockHttpServletRequestFoo2.setQueryString(null)

        def mockHttpServletRequestFoo3 = new MockHttpServletRequest();
        mockHttpServletRequestFoo3.setServletPath(patternFoo3)
        mockHttpServletRequestFoo3.setPathInfo(null)
        mockHttpServletRequestFoo3.setQueryString(null)

        for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : map.entrySet()) {
            RequestMatcher rp = entry.getKey()
            Collection<ConfigAttribute> value = map.get(rp)

            assertNotNull value

            List<ConfigAttribute> valueList = (List<ConfigAttribute>) value;
            ConfigAttribute configAttribute = valueList.get(configAttributeIndex)

            String attribute = configAttribute.getAttribute()

            if(rp.matches(mockHttpServletRequestFoo1))  {
               assertEquals 'REQUIRES_SECURE_CHANNEL',  attribute

               isFoundMatch = true
            }  else if (rp.matches(mockHttpServletRequestFoo2)) {
                assertEquals 'REQUIRES_INSECURE_CHANNEL', attribute

                isFoundMatch = true
            }  else if (rp.matches(mockHttpServletRequestFoo3)) {
                assertEquals 'ANY_CHANNEL', attribute

                isFoundMatch = true
            }

            assertTrue isFoundMatch

            isFoundMatch = false;
        }
	}
}
