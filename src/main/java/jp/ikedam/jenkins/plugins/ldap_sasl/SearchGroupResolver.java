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

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

/**
 * Resolves groups by querying the LDAP directory.
 */
public class SearchGroupResolver extends GroupResolver
{
    /**
     * The internal class to work with views.
     * 
     * The following files are used (put in main/resource directory in the source tree).
     * <dl>
     *     <dt>config.jelly</dt>
     *         <dd>
     *             Shown as a part of a system configuration page when ResolveGroup is selected.
     *             Provides additional configuration fields of a LdapSaslSecurityRealm.
     *         </dd>
     * </dl>
     */
    @Extension(ordinal=10)
    public static class DescriptorImpl extends Descriptor<GroupResolver>
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
            return Messages.SearchGroupResolver_DisplayName();
        }
        
        /**
         * Validate the input group search base.
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
                return FormValidation.error(Messages.SearchGroupResolver_SearchBase_invalid(e.getMessage()));
            }
            
            return FormValidation.ok();
        }
        
        /**
         * Validate the input prefix.
         * 
         * @param prefix
         * @return
         */
        public FormValidation doPrefix(@QueryParameter String prefix)
        {
            // no validation is performed.
            return FormValidation.ok();
        }
    }
    
    
    private Logger getLogger()
    {
        return Logger.getLogger(getClass().getName());
    }
    
    private String searchBase;
    
    /**
     * Returns the base DN for groups.
     * 
     * @return the base DN for searching groups.
     */
    public String getSearchBase()
    {
        return searchBase;
    }
    
    private String prefix;
    
    /**
     * Returns the prefix added to the Jenkins group name
     * 
     * @return the prefix to be added before the group name
     */
    public String getPrefix()
    {
        return prefix;
    }
    
    /**
     * Constructor instantiating with parameters in the configuration page.
     * 
     * When instantiating from the saved configuration,
     * the object is directly serialized with XStream,
     * and no constructor is used.
     * 
     * @param searchBase the base DN to search for groups.
     * @param prefix the prefix added to the Jenkins group name
     */
    @DataBoundConstructor
    public SearchGroupResolver(
            String searchBase,
            String prefix
    )
    {
        this.searchBase = StringUtils.trimToEmpty(searchBase);
        this.prefix = StringUtils.trim(prefix);
    }
    
    /**
     * Resolves groups by querying the LDAP directory. 
     * 
     * Never return null in any case. Returns empty list instead.
     * 
     * @param ctx
     * @param dn
     * @param username
     * @return List of authorities (not null)
     * @see jp.ikedam.jenkins.plugins.ldap_sasl.GroupResolver#resolveGroup(javax.naming.ldap.LdapContext, java.lang.String, java.lang.String)
     */
    @Override
    public List<GrantedAuthority> resolveGroup(LdapContext ctx, String dn, String username)
    {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        
        Logger logger = getLogger();
        
        if(getSearchBase() == null)
        {
            // not configured.
            logger.severe("Not configured.");
            
            return authorities;
        }
        
        if(dn == null)
        {
            logger.warning("Group cannot be resolved: DN of the user is not resolved!");
            return authorities;
        }
        
        try
        {
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            logger.fine(String.format("Searching groups base=%s, dn=%s", getSearchBase(), dn));
            NamingEnumeration<SearchResult> entries = ctx.search(getSearchBase(), getGroupSearchQuery(dn), searchControls);
            while(entries.hasMore()){
                SearchResult entry = entries.next();
                String groupName = entry.getAttributes().get("cn").get().toString();
                if(getPrefix() != null){
                    groupName = getPrefix() + groupName;
                }
                authorities.add(new GrantedAuthorityImpl(groupName));
                logger.fine(String.format("group: %s", groupName));
            }
            entries.close();
        }
        catch(NamingException e)
        {
            logger.log(Level.WARNING, "Failed to search groups", e);
        }
        
        return authorities;
    }

    /**
     * Returns query string to search groups
     * 
     * @param dn
     * @return query
     */
    protected String getGroupSearchQuery(String dn)
    {
        return MessageFormat.format("(| "
                + "(& (objectClass=groupOfUniqueNames) (uniqueMember={0}))"
                + "(& (objectClass=groupOfNames) (member={0}))"
                + ")", dn);
    }
}
