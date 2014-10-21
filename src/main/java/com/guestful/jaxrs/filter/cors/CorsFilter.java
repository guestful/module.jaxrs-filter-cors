/**
 * Copyright (C) 2013 Guestful (info@guestful.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.guestful.jaxrs.filter.cors;

import javax.ws.rs.ForbiddenException;
import javax.ws.rs.container.*;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Handles CORS requests both preflight and simple CORS requests.
 * You must bind this as a singleton and set up allowedOrigins and other settings to use.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@PreMatching
public class CorsFilter implements ContainerRequestFilter, ContainerResponseFilter {

    protected boolean allowCredentials = true;
    protected String allowedMethods;
    protected String allowedHeaders;
    protected String exposedHeaders;
    protected int corsMaxAge = -1;
    protected final Set<String> allowedOrigins = new HashSet<>();

    public CorsFilter(Collection<String> allowedOrigins, Collection<String> allowedHeaders, Collection<String> allowedMethods) {
        this.allowedOrigins.addAll(allowedOrigins);
        this.allowedHeaders = String.join(",", allowedHeaders);
        this.allowedMethods = String.join(",", allowedMethods);
    }

    public CorsFilter() {
    }

    public CorsFilter setAllowedOrigins(String allowedOrigins) {
        this.allowedOrigins.addAll(Arrays.asList(allowedOrigins.split(",")));
        return this;
    }

    /**
     * Put "*" if you want to accept all origins
     */
    public Set<String> getAllowedOrigins() {
        return allowedOrigins;
    }

    /**
     * Defaults to true
     */
    public boolean isAllowCredentials() {
        return allowCredentials;
    }

    public CorsFilter setAllowCredentials(boolean allowCredentials) {
        this.allowCredentials = allowCredentials;
        return this;
    }

    /**
     * Will allow all by default
     */
    public String getAllowedMethods() {
        return allowedMethods;
    }

    /**
     * Will allow all by default
     * comma delimited string for Access-Control-Allow-Methods
     */
    public CorsFilter setAllowedMethods(String allowedMethods) {
        this.allowedMethods = allowedMethods;
        return this;
    }

    public String getAllowedHeaders() {
        return allowedHeaders;
    }

    /**
     * Will allow all by default
     * comma delimited string for Access-Control-Allow-Headers
     */
    public CorsFilter setAllowedHeaders(String allowedHeaders) {
        this.allowedHeaders = allowedHeaders;
        return this;
    }

    public int getCorsMaxAge() {
        return corsMaxAge;
    }

    public CorsFilter setCorsMaxAge(int corsMaxAge) {
        this.corsMaxAge = corsMaxAge;
        return this;
    }

    public String getExposedHeaders() {
        return exposedHeaders;
    }

    /**
     * comma delimited list
     */
    public CorsFilter setExposedHeaders(String exposedHeaders) {
        this.exposedHeaders = exposedHeaders;
        return this;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String origin = requestContext.getHeaderString(CorsHeaders.ORIGIN);
        if (origin == null) {
            return;
        }
        if (requestContext.getMethod().equalsIgnoreCase("OPTIONS")) {
            preflight(origin, requestContext);
        } else {
            checkOrigin(requestContext, origin);
        }
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
        String origin = requestContext.getHeaderString(CorsHeaders.ORIGIN);
        if (origin == null || requestContext.getMethod().equalsIgnoreCase("OPTIONS") || requestContext.getProperty("cors.failure") != null) {
            // don't do anything if origin is null, its an OPTIONS request, or cors.failure is set
            return;
        }
        responseContext.getHeaders().putSingle(CorsHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        if (allowCredentials) responseContext.getHeaders().putSingle(CorsHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");

        if (exposedHeaders != null) {
            responseContext.getHeaders().putSingle(CorsHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, exposedHeaders);
        }
    }


    protected void preflight(String origin, ContainerRequestContext requestContext) throws IOException {
        checkOrigin(requestContext, origin);

        Response.ResponseBuilder builder = Response.ok();
        builder.header(CorsHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        if (allowCredentials) builder.header(CorsHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        String requestMethods = requestContext.getHeaderString(CorsHeaders.ACCESS_CONTROL_REQUEST_METHOD);
        if (requestMethods != null) {
            if (allowedMethods != null) {
                requestMethods = this.allowedMethods;
            }
            builder.header(CorsHeaders.ACCESS_CONTROL_ALLOW_METHODS, requestMethods);
        }
        String allowHeaders = requestContext.getHeaderString(CorsHeaders.ACCESS_CONTROL_REQUEST_HEADERS);
        if (allowHeaders != null) {
            if (allowedHeaders != null) {
                allowHeaders = this.allowedHeaders;
            }
            builder.header(CorsHeaders.ACCESS_CONTROL_ALLOW_HEADERS, allowHeaders);
        }
        if (corsMaxAge > -1) {
            builder.header(CorsHeaders.ACCESS_CONTROL_MAX_AGE, corsMaxAge);
        }
        requestContext.abortWith(builder.build());

    }

    protected void checkOrigin(ContainerRequestContext requestContext, String origin) {
        if (!allowedOrigins.contains("*") && !allowedOrigins.contains(origin)) {
            requestContext.setProperty("cors.failure", true);
            throw new ForbiddenException("Origin not allowed: " + origin);
        }
    }
}
