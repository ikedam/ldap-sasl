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
import hudson.util.FormValidation;

import java.io.Serializable;
import java.text.MessageFormat;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

/**
 * Resolve the user DN by querying LDAP directory.
 */
public class SearchUserDnResolver extends UserDnResolver implements Serializable
{
    private static final long serialVersionUID = -5727907170563521060L;
    
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
     *             Shown as a part of a system configuration page when this resolver is selected.
     *             Provides additional configuration fields of a LdapSaslSecurityRealm.
     *         </dd>
     * </dl>
     */
    @Extension(ordinal=10)
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
            return Messages.SearchUserDnResolver_DisplayName();
        }
        
        /**
         * Validate the input user search base.
         * 
         * @param searchBase
         * @return
         */
        public FormValidation doCheckSearchBase(@QueryParameter String searchBase)
        {
            if(StringUtils.isBlank(searchBase))
            {
                return FormValidation.ok();
            }
            
            try
            {
                new LdapName(StringUtils.trim(searchBase));
            }
            catch(InvalidNameException e)
            {
                return FormValidation.error(Messages.SearchUserDnResolver_SearchBase_invalid(e.getMessage()));
            }
            
            return FormValidation.ok();
        }
        
        /**
         * Validate the input search query template.
         * 
         * @param searchQueryTemplate
         * @return
         */
        public FormValidation doCheckSearchQueryTemplate(@QueryParameter String searchQueryTemplate)
        {
            if(StringUtils.isBlank(searchQueryTemplate))
            {
                return FormValidation.error(Messages.SearchUserDnResolver_SearchQueryTemplate_empty());
            }
            
            String testString;
            try
            {
                testString = MessageFormat.format(searchQueryTemplate, "Dummy");
            }
            catch(IllegalArgumentException e)
            {
                // Failed to parse the format...
                return FormValidation.error(Messages.SearchUserDnResolver_SearchQueryTemplate_invalid(e.getMessage()));
            }
            if(testString.equals(searchQueryTemplate))
            {
                return FormValidation.error(Messages.SearchUserDnResolver_SearchQueryTemplate_invalid("Specify \"{0}\" where to replace with the username."));
            }
            
            return FormValidation.ok();
        }
    }
    
    private String searchBase = null;
    /**
     * Returns the base DN to search for the user.
     * 
     * @return the user search base
     */
    public String getSearchBase()
    {
        return searchBase;
    }
    
    private String searchQueryTemplate = null;
    
    /**
     * Returns the template to generate the user search query.
     * 
     * used with String.format, provided a username.
     * 
     * @return the user search template.
     */
    public String getSearchQueryTemplate()
    {
        return searchQueryTemplate;
    }
    
    /**
     * Constructor instantiating with parameters in the configuration page.
     * 
     * When instantiating from the saved configuration,
     * the object is directly serialized with XStream,
     * and no constructor is used.
     * 
     * @param searchBase the base DN to search for the user.
     * @param searchQueryTemplate the query to execute in which the place to put the username is {0}.
     */
    @DataBoundConstructor
    public SearchUserDnResolver(
            String searchBase,
            String searchQueryTemplate
    )
    {
        this.searchBase = StringUtils.trim(searchBase);
        this.searchQueryTemplate = StringUtils.trim(searchQueryTemplate);
    }
    
    /**
     * Resolve the user DN by querying the LDAP directory.
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
        Logger logger = getLogger();
        if(StringUtils.isBlank(getSearchQueryTemplate()))
        {
            // not configured.
            logger.severe("Not configured.");
            
            return null;
        }
        
        try
        {
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            logger.fine(String.format("Searching users base=%s, username=%s", getSearchBase(), username));
            String query = MessageFormat.format(getSearchQueryTemplate(), username);
            NamingEnumeration<SearchResult> entries = ctx.search((getSearchBase() != null)?getSearchBase():"", query, searchControls);
            if(!entries.hasMore())
            {
                // no entry.
                logger.severe(String.format("User not found: %s", username));
                return null;
            }
            
            String userDn = entries.next().getNameInNamespace();
            
            if(entries.hasMore())
            {
                // more than one entry.
                logger.severe(String.format("User found more than one: %s", username));
                return null;
            }
            entries.close();
            
            return userDn;
        }
        catch(NamingException e)
        {
            logger.log(Level.SEVERE, "Failed to search a user", e);
            return null;
        }
    }
}
