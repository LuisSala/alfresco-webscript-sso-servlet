INSTALLATION
============

The Web Script SSO Authenticator is a drop-in replacement for the default Basic Authentication support.

It works by looking for a REMOTE_USER server variable. If present, then that User ID will be used to
authenticate the request.

0. These instructions assume you're in the `{ALFRESCO_HOME}` directory.

1. To apply the AMP, copy `alfresco-webscript-sso.amp` to `{ALFRESCO_HOME}/amps`.

2. Run `./bin/apply_amps.sh`.

3. After applying the AMP, start Alfresco to force deployment of the updated WAR archive:
	eg. `alfresco.sh start`

4. Once Alfresco has been started, you must shut it back down again:
	eg. `alfresco.sh stop`
	
5. Edit `{ALFRESCO_HOME}/tomcat/webapps/alfresco/WEB-INF/web.xml` and make the following changes:

	=============
	Replace this:
	=============
	
	   <servlet>
	      <servlet-name>apiServlet</servlet-name>
	      <servlet-class>org.springframework.extensions.webscripts.servlet.WebScriptServlet</servlet-class>
	      <init-param>
	         <param-name>authenticator</param-name>
	         <param-value>webscripts.authenticator.basic</param-value>
	      </init-param>
	   </servlet>
	   
	==========
	With this:
	==========
	
	   <servlet>
	      <servlet-name>apiServlet</servlet-name>
	      <servlet-class>org.springframework.extensions.webscripts.servlet.WebScriptServlet</servlet-class>
	      <init-param>
	         <param-name>authenticator</param-name>
	         <param-value>webscripts.authenticator.servicesso</param-value>
	      </init-param>
	   </servlet>
	   
6. After saving `web.xml`, you may launch Alfresco again.

Special Note: For development and testing purposes it is OK for these manual changes to be applied to
the "unpacked" `web.xml` file. This means that you will need to repeat steps 3-6 if new AMPs are ever
deployed.

Production installations should incorporate these changes directly into `alfresco.war` by unpacking the
war file into a temporary directory:
	eg.	`jar xf alfresco.war -C ~/tmp_war/`

After applying the changes to `WEB-INF/web.xml` you may re-pack the war using:
	eg.	`jar cvf alfresco.war .`
	
	
USING WITH HTTP HEADERS
=======================

NOTE: For testing and debugging purposes only

This AMP support the use of a `REMOTE_USER` HTTP header. This feature is disabled by default but may be
enabled by creating a new context file and overriding the authenticator JavaBean with new properties.

1. Create and edit a new file called:
	`{ALFRESCO_HOME}/tomcat/shared/classes/alfresco/extension/custom-webscript-sso-context.xml`

2. Paste in the following:	
	<?xml version='1.0' encoding='UTF-8'?>
	<!DOCTYPE beans PUBLIC '-//SPRING//DTD BEAN//EN' 'http://www.springframework.org/dtd/spring-beans.dtd'>
	<beans>
	
	  <!-- Custom Web Script authenticator used to provide a custom authentication scheme in front of CMIS -->
	  <bean id="webscripts.authenticator.servicesso" class="org.alfresco.module.webscripts.sso.SSOAuthenticatorFactory">
	    <property name="authenticationService"   ref="AuthenticationService" />
		<property name="personService"   ref="PersonService" />
		<property name="useHeader"	value="false" />
	  </bean>
	  
	</beans>

Note the `useHeader` property defaults to "false", change the value to "true" in order to enable support
for the REMOTE_USER HTTP header.

3. Save the file and restart Alfresco.

LICENSE
=======
Copyright (C) 2005-2012 Alfresco Software Limited.

Alfresco is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Alfresco is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with Alfresco. If not, see <http://www.gnu.org/licenses/>.

