/*
 * Copyright (C) 2005-2012 Alfresco Software Limited.
 *
 * This file is part of Alfresco
 *
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 */

package org.alfresco.module.webscripts.sso;

import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.webscripts.Authenticator;
import org.springframework.extensions.webscripts.Description.RequiredAuthentication;
import org.springframework.extensions.webscripts.servlet.WebScriptServletRequest;
import org.springframework.extensions.webscripts.servlet.WebScriptServletResponse;

import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.security.AuthenticationService;
import org.alfresco.service.cmr.security.PersonService;

import org.alfresco.repo.web.scripts.servlet.BasicHttpAuthenticatorFactory;


/**
 * SSO Authentication for Web Scripts (CMIS, specifically).
 * 
 * @author Luis Sala (luis.sala@alfresco.com)
 * @version $Id: SSOAuthenticatorFactory.java 28112 2011-05-30 05:46:41Z lsala $
 */
public class SSOAuthenticatorFactory
    extends BasicHttpAuthenticatorFactory
{
    // Logger
    private final static Log log = LogFactory.getLog(SSOAuthenticatorFactory.class);
    
    private final static String HTTP_HEADER_NAME_USER_ID = "REMOTE_USER";
    

    // Component dependencies
    private AuthenticationService   authenticationService;
    private PersonService   personService;
    private boolean useHeader;

    
    /**
     * @param authenticationService
     */
    @Override
    public void setAuthenticationService(final AuthenticationService authenticationService)
    {
        super.setAuthenticationService(authenticationService);
        this.authenticationService = authenticationService;
    }
    
    public void setPersonService(final PersonService personService)
    {
        this.personService = personService;
    }
    
    public void setUseHeader(final boolean useHeader)
    {
    	this.useHeader = useHeader;
    }


    /* (non-Javadoc)
     * @see org.alfresco.web.scripts.servlet.ServletAuthenticatorFactory#create(org.alfresco.web.scripts.servlet.WebScriptServletRequest, org.alfresco.web.scripts.servlet.WebScriptServletResponse)
     */
    public Authenticator create(final WebScriptServletRequest req, final WebScriptServletResponse res)
    {
        return new SSOAuthenticator(req, res);
    }
    
    
    /**
     * SSO Authentication - Masquerades as the user passed via the REMOTE_USER HTTP header.
     * 
     * @author Luis Sala (luis.sala@alfresco.com)
     */
    public class SSOAuthenticator
        extends BasicHttpAuthenticatorFactory.BasicHttpAuthenticator
    {
        // dependencies
        private WebScriptServletRequest  servletReq;
        private WebScriptServletResponse servletRes;
        
        
        /**
         * Construct
         * 
         * @param req
         * @param res
         */
        public SSOAuthenticator (final WebScriptServletRequest req, final WebScriptServletResponse res)
        {
            super(req, res);
            
            this.servletReq = req;
            this.servletRes = res;
        }
        
    
        /* (non-Javadoc)
         * @see org.alfresco.web.scripts.Authenticator#authenticate(org.alfresco.web.scripts.Description.RequiredAuthentication, boolean)
         */
        @Override
        public boolean authenticate(final RequiredAuthentication required, final boolean isGuest)
        {
            boolean             result = false;
            HttpServletRequest  req    = servletReq.getHttpServletRequest();
            HttpServletResponse res    = servletRes.getHttpServletResponse();
            String agent = req.getHeader("User-Agent");
            
            String userId = req.getRemoteUser();
            
            
            
            if ((userId == null || userId.equals("")) && useHeader)
            	userId = req.getHeader(HTTP_HEADER_NAME_USER_ID);            
            
            if (log.isDebugEnabled()) {
                log.debug("Received request: " + requestToString(req));
                log.debug("UserId Header: "+req.getHeader(HTTP_HEADER_NAME_USER_ID));
                log.debug("UserId CGI Var: "+req.getRemoteUser());
            }
            
            if (!(userId == null || userId.equals("")))
            {
            	if (log.isDebugEnabled())
                    log.debug("Looking for SSO User:" + userId);
            	
            	// Force the authenticated user to be the one provided by SSO rather than the one in the HTTP Basic Auth credentials
                try {
                	
                	// Authenticate as System User to locate account.
                	AuthenticationUtil.setFullyAuthenticatedUser(AuthenticationUtil.getSystemUserName());
                	
                	if (personService.personExists(userId)) {
                		if (log.isDebugEnabled())
                            log.debug("User Found:" + userId);
                		AuthenticationUtil.setFullyAuthenticatedUser(userId);
                		result = true;
                		
                		// iOS Devices get redirected to the Alfresco mobile app if a Session Cookie
                		// such as "SMSESSION" is present.
                        if (agent.contains("iPhone") || agent.contains("iPad") || agent.contains("iPod"))
                        {
                        	if (log.isDebugEnabled())
                                log.debug("Mobile device detected");
                        	
                        	String hostname = req.getHeader("Host");
                        	String sessionId = this.getCookieValue(req.getCookies(), "SMSESSION", null);
                        	
                        	// Cookies should have the proper domain set. Use the hostname to turn something
                        	// like www.example.com to example.com
                        	String domain = hostname;
                        	
                        	// When testing on localhost, there won't be a '.' in the hostname.
                        	if (hostname.indexOf(".") > 0)
                        		domain = domain.substring(hostname.indexOf("."));
                        	
                        	// Remove any port numbers. eg. 'www.example.com:8080' to 'example.com'
                        	if (domain.indexOf(":") > 0)
                        		domain = domain.substring(0,domain.indexOf(":"));                       	
                        	
                        	if (sessionId != null) {
                        		String cookie = "SMSESSION="+sessionId+"; Domain="+domain+"; Path=/";
                        		res.sendRedirect("alfrescoifc://auth-cookie?url=http://"+hostname+"&cookie="+cookie);
                        	}
                        }
                		
                	} else {
                		if (log.isDebugEnabled())
                            log.debug("User " + userId + " Not Found. Switching to Guest Privileges");
                		AuthenticationUtil.setFullyAuthenticatedUser(AuthenticationUtil.getGuestUserName());
                	}
                } catch (Exception e) {
                	if (log.isDebugEnabled())
                        log.debug("SSO Authentication Error: "+e.toString());
                	AuthenticationUtil.setFullyAuthenticatedUser(AuthenticationUtil.getGuestUserName());
                }
            }
            else // The user id sent from SSO isn't known to Alfresco
            {
                if (log.isDebugEnabled())
                    log.debug(HTTP_HEADER_NAME_USER_ID+" " + userId + " not found. Switching to Basic Auth");

                result = super.authenticate(required, isGuest);
            }
            
            return result; 
        }
    
        private String getCookieValue(Cookie[] cookies, String cookieName, String defaultValue) {
        	for(int i=0; i<cookies.length; i++) {
        		Cookie cookie = cookies[i];
        		if (cookieName.equals(cookie.getName()))
        			return(cookie.getValue());
        	}
        	return(defaultValue);
        }
    
	    /**
	     * Debugging method for obtaining the state of a request as a String.
	     * 
	     * @param request The request to retrieve the state from <i>(may be null)</i>.
	     * @return The request state as a human-readable string value <i>(will not be null)</i>.
	     */
	    private String requestToString(final HttpServletRequest request)
	    {
	        StringBuffer result = new StringBuffer(128);
	        
	        if (request != null)
	        {
	            result.append("\n\tMethod: ");
	            result.append(request.getMethod());
	            result.append("\n\tURL: ");
	            result.append(String.valueOf(request.getRequestURI()));
	            result.append("\n\tHeaders: ");
	            
	            Enumeration<String> headerNames = request.getHeaderNames();
	            
	            while (headerNames.hasMoreElements())
	            {
	                String headerName  = headerNames.nextElement();
	                String headerValue = request.getHeader(headerName);
	
	                result.append("\n\t\t");
	                result.append(headerName);
	                result.append(" : ");
	                result.append(headerValue);
	            }
	        }
	        else
	        {
	            result.append("(null)");
	        }
	        
	        return(result.toString());
	    }
	    
	}

}