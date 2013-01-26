/*
 * The MIT License
 * 
 * Copyright (c) 2012-2013 IKEDA Yasuyuki
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package jp.ikedam.jenkins.plugins.ldap_sasl;

import hudson.Extension;
import hudson.model.Descriptor;

import java.io.Serializable;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

import org.kohsuke.stapler.DataBoundConstructor;

import jp.ikedam.ldap.LdapWhoamiRequest;
import jp.ikedam.ldap.LdapWhoamiResponse;

/**
 * Resolve the user DN using LDAP Who Am I.
 */
public class LdapWhoamiUserDnResolver extends UserDnResolver implements Serializable
{
    private static final long serialVersionUID = 2059337024545589801L;
    
    private Logger getLogger()
    {
        return Logger.getLogger(getClass().getName());
    }
    
    /**
     * The internal class to work with views.
     * 
     * The following files are used (put in main/resource directory in the source tree).
     * <dl>
     *     <dt>config.jelly</dt>
     *         <dd>
     *             Shown as a part of a system configuration page when this Resolver is selected.
     *             Provides additional configuration fields of a LdapSaslSecurityRealm.
     *         </dd>
     * </dl>
     */
    @Extension(ordinal=50)
    public static class DescriptorImpl extends Descriptor<UserDnResolver>
    {
        /**
         * the display name shown in the radio list of LdapSaslSecurityRealm.
         * 
         * @return display name
         * @see hudson.model.Descriptor#getDisplayName()
         */
        @Override
        public String getDisplayName()
        {
            return Messages.LdapWhoamiUserDnResolver_DisplayName();
        }
    }
    
    /**
     * Constructor instantiating with parameters in the configuration page.
     * 
     * No parameter is provided.
     */
    @DataBoundConstructor
    public LdapWhoamiUserDnResolver()
    {
    }
    
    /**
     * Resolve the user DN using LDAP Who Am I.
     * 
     * @param ctx LDAP context, already authenticated.
     * @param username the username the user authenticated with.
     * 
     * @return the DN of the user.
     * @see jp.ikedam.jenkins.plugins.ldap_sasl.UserDnResolver#getUserDn(javax.naming.ldap.LdapContext, java.lang.String)
     */
    @Override
    public String getUserDn(LdapContext ctx, String username)
    {
        LdapWhoamiResponse response;
        try
        {
            response = (LdapWhoamiResponse)ctx.extendedOperation(new LdapWhoamiRequest());
        }
        catch (NamingException e)
        {
            getLogger().log(Level.WARNING, "Failed to resolve user DN", e);
            return null;
        }
        
        if(response.getAuthzIdType() != LdapWhoamiResponse.AuthzIdType.DN_AUTHZ_ID)
        {
            getLogger().warning(String.format("Failed to resolve user DN: LDAP server does not returned DN for whoami to ldap whoami: Server returned %s", response.getAuthzId()));
            return null;
        }
        
        return response.getDn();
    }
    
}
