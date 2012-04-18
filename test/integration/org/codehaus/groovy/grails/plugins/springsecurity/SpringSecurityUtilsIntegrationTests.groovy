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

import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse

import org.springframework.beans.factory.NoSuchBeanDefinitionException
import org.springframework.beans.factory.support.AbstractBeanDefinition
import org.springframework.beans.factory.support.GenericBeanDefinition
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.security.web.util.RequestMatcher
import org.springframework.web.filter.GenericFilterBean

import test.TestRole
import test.TestUser
import test.TestUserRole

/**
 * Integration tests for <code>SpringSecurityUtils</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SpringSecurityUtilsIntegrationTests extends GroovyTestCase {

	def grailsApplication
	def springSecurityFilterChain
	def springSecurityService

	private String username = 'username'
	private TestUser testUser

	@Override
	protected void setUp() {
		super.setUp()
		def user = new TestUser(loginName: username, enabld: true,
			passwrrd: springSecurityService.encodePassword('password')).save(failOnError: true)
		testUser = user
		def role = new TestRole(auth: 'ROLE_ADMIN', description: 'admin').save(failOnError: true)
		TestUserRole.create user, role, true

		user = new TestUser(loginName: 'other', enabld: true,
			passwrrd: springSecurityService.encodePassword('password')).save(failOnError: true)
		TestUserRole.create user, role, true
	}

	@Override
	protected void tearDown() {
		super.tearDown()
		SecurityContextHolder.clearContext() // logout
	}

	void testClientRegisterFilter() {

		def map = SpringSecurityUtils.getConfiguredOrderedFilters()
		assertEquals 8, map.size()
		assertTrue map[300] instanceof SecurityContextPersistenceFilter
		assertTrue map[400] instanceof LogoutFilter
		assertTrue map[800] instanceof RequestHolderAuthenticationFilter
		assertTrue map[1400] instanceof SecurityContextHolderAwareRequestFilter
		assertTrue map[1500] instanceof RememberMeAuthenticationFilter
		assertTrue map[1600] instanceof AnonymousAuthenticationFilter
		assertTrue map[1800] instanceof ExceptionTranslationFilter
		assertTrue map[1900] instanceof FilterSecurityInterceptor

		shouldFail(IllegalArgumentException) {
			SpringSecurityUtils.clientRegisterFilter 'foo',
					SecurityFilterPosition.LOGOUT_FILTER
		}

		shouldFail(NoSuchBeanDefinitionException) {
			SpringSecurityUtils.clientRegisterFilter 'foo',
					SecurityFilterPosition.LOGOUT_FILTER.order + 10
		}

		shouldFail(ClassCastException) {
			SpringSecurityUtils.clientRegisterFilter 'passwordEncoder',
					SecurityFilterPosition.LOGOUT_FILTER.order + 10
		}

//		grailsApplication.mainContext.registerBeanDefinition 'dummyFilter',
//			new GenericBeanDefinition(beanClass: DummyFilter,
//					scope: AbstractBeanDefinition.SCOPE_PROTOTYPE,
//					autowireMode:AbstractBeanDefinition.AUTOWIRE_BY_NAME)
//
//		SpringSecurityUtils.clientRegisterFilter 'dummyFilter',
//				SecurityFilterPosition.LOGOUT_FILTER.order + 10

//		assertEquals 9, map.size()
//		assertTrue map[410] instanceof DummyFilter

        Set<Map.Entry<RequestMatcher,List<javax.servlet.Filter>>> entrySet =
                    springSecurityFilterChain.filterChainMap.entrySet()

        int index = 0;

        for (Map.Entry<RequestMatcher,List<javax.servlet.Filter>> entry : entrySet) {
            def filters = entry.value


    	    assertTrue filters[index++] instanceof SecurityContextPersistenceFilter
    		assertTrue filters[index++] instanceof LogoutFilter
//    		assertTrue filters[index++] instanceof DummyFilter
    		assertTrue filters[index++] instanceof RequestHolderAuthenticationFilter
    		assertTrue filters[index++] instanceof SecurityContextHolderAwareRequestFilter
    		assertTrue filters[index++] instanceof RememberMeAuthenticationFilter
    		assertTrue filters[index++] instanceof AnonymousAuthenticationFilter
    		assertTrue filters[index++] instanceof ExceptionTranslationFilter
    		assertTrue filters[index] instanceof FilterSecurityInterceptor

            index = 0;
        }

	}

	void testReauthenticate() {

		assertFalse springSecurityService.loggedIn

		SpringSecurityUtils.reauthenticate username, null

		assertTrue springSecurityService.loggedIn
		def principal = springSecurityService.principal
		assertTrue principal instanceof GrailsUser
		assertEquals(['ROLE_ADMIN'], principal.authorities.authority)
		assertEquals username, principal.username
	}

	void testDoWithAuth_CurrentAuth() {

		assertFalse springSecurityService.loggedIn
		SpringSecurityUtils.reauthenticate username, null
		assertTrue springSecurityService.loggedIn

		Thread.start {

			assertFalse "shouldn't appear authenticated in a new thread", springSecurityService.loggedIn

			SpringSecurityUtils.doWithAuth {
				assertTrue springSecurityService.loggedIn
				assertEquals username, springSecurityService.principal.username
			}

			assertFalse "should have reset auth", springSecurityService.loggedIn
		}.join()

		assertTrue "should still be authenticated in main thread", springSecurityService.loggedIn
	}

	void testDoWithAuth_NewAuth() {

		assertFalse springSecurityService.loggedIn

		Thread.start {

			assertFalse "shouldn't appear authenticated in a new thread", springSecurityService.loggedIn

			SpringSecurityUtils.doWithAuth username, {
				assertTrue springSecurityService.loggedIn
				assertEquals username, springSecurityService.principal.username
			}

			assertFalse "should have reset auth", springSecurityService.loggedIn
		}.join()

		assertFalse "should still be unauthenticated in main thread", springSecurityService.loggedIn
	}

	void testDoWithAuth_NewAuth_WithExisting() {

		assertFalse springSecurityService.loggedIn
		SpringSecurityUtils.reauthenticate username, null
		assertTrue springSecurityService.loggedIn

		Thread.start {

			assertFalse "shouldn't appear authenticated in a new thread", springSecurityService.loggedIn

			SpringSecurityUtils.doWithAuth 'other', {
				assertTrue springSecurityService.loggedIn
				assertEquals 'other', springSecurityService.principal.username
			}

			assertTrue 'should still be authenticated', springSecurityService.loggedIn
			assertEquals 'should have reset auth to previous', username, springSecurityService.principal.username
		}.join()

		assertTrue 'should still be authenticated', springSecurityService.loggedIn
		assertEquals 'should still be unauthenticated in main thread', username, springSecurityService.principal.username
	}

	void testGetCurrentUser_NotLoggedIn() {
		assertFalse springSecurityService.loggedIn
		assertNull springSecurityService.currentUser
	}

	void testGetCurrentUser_LoggedIn() {
		SpringSecurityUtils.reauthenticate username, null
		assertTrue springSecurityService.loggedIn

		def currentUser = springSecurityService.currentUser
		assertNotNull currentUser
		assertEquals currentUser.id, testUser.id
	}
}

class DummyFilter extends GenericFilterBean {
	void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {}
}
