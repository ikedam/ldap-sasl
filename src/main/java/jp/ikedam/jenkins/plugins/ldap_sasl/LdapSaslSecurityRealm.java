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
import hudson.model.AutoCompletionCandidates;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;

import java.util.logging.Level;
import java.util.logging.Logger;

import jp.ikedam.ldap.LdapWhoamiRequest;
import jp.ikedam.ldap.LdapWhoamiResponse;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.springframework.dao.DataAccessException;

/**
 * Security Realm that supports LDAP SASL authentication.
 */
public class LdapSaslSecurityRealm extends AbstractPasswordBasedSecurityRealm
        implements Serializable
{
    static public class ResolveGroup{
        private String groupSearchBase;
        
        /**
         * Returns the base DN for groups.
         * 
         * @return the base DN for searching groups.
         */
        public String getGroupSearchBase()
        {
            return groupSearchBase;
        }
        
        private String groupPrefix;
        
        /**
         * Returns the prefix added to the Jenkins group name
         * 
         * @return the prefix to be added before the group name
         */
        public String getGroupPrefix()
        {
            return groupPrefix;
        }
        
        /**
         * Constructor instantiating with parameters in the configuration page.
         * 
         * When instantiating from the saved configuration,
         * the object is directly serialized with XStream,
         * and no constructor is used.
         * 
         * @param groupSearchBase the base DN for searching groups.
         * @param groupPrefix the prefix added to the Jenkins group name
         */
        @DataBoundConstructor
        public ResolveGroup(
                String groupSearchBase,
                String groupPrefix
        )
        {
            this.groupSearchBase = groupSearchBase;
            this.groupPrefix = groupPrefix;
        }
    }
    /**
     * Descriptor to map the object and the view.
     */
    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm>
    {
        /**
         * Returns the name shown in the system configuration page.
         * 
         * @return the name shown in the system configuration page.
         * @see hudson.model.Descriptor#getDisplayName()
         */
        @Override
        public String getDisplayName()
        {
            return Messages.LdapSaslSecurityRealm_DisplayName();
        }
        
        private static String[] MECH_CANDIDATES = {
            "DIGEST-MD5",
            "CRAM-MD5",
            "PLAIN",
            "EXTERNAL ",    // I don't know wheather this really works...
        };
        
        /**
         * Returns the mechanisms that is supported.
         * 
         * @return the array of available mechanisms.
         */
        public String[] getMechanismCandidates(){
            // TODO: Is there any API to get available mechanisms?
            return MECH_CANDIDATES;
        }
        
        /**
         * Returns auto complete information for the SASL mechanism field.
         * 
         * @param value the value that the user is inputting, and not supposed not completed. 
         * @return the list of candidates.
         */
        public AutoCompletionCandidates doAutoCompleteMechanisms(@QueryParameter String value, @QueryParameter String previous)
        {
            AutoCompletionCandidates candidate = new AutoCompletionCandidates();
            String[] mechanisms = getMechanismCandidates();
            String[] previousList = (previous != null)?previous.split(" +"):new String[0];
            mechanism_loop:
            for(String mechanism: mechanisms){
                if(value.isEmpty() || mechanism.toLowerCase().startsWith(value.toLowerCase())){
                    // This can be a candidate!
                    for(String test: previousList)
                    {
                        if(!test.isEmpty() && test.equals(mechanism))
                        {
                            // ignore this candidate if it is already input.
                            continue mechanism_loop;
                        }
                    }
                    candidate.add(mechanism);
                }
            }
            return candidate;
        }
    }

    private static final long serialVersionUID = 4771805355880928786L;
    
    private List<String> ldapUriList = new ArrayList<String>();
    
    /**
     * Returns the list of LDAP URIs.
     * 
     * @return the list of LDAP URIs.
     */
    public List<String> getLdapUriList()
    {
        return ldapUriList;
    }
    
    /**
     * Returns a joined list of LDAP URIs.
     * 
     * Used to be passed to JNDI.
     * 
     * @return a whitespace-seperated list of LDAP URIs.
     */
    public String getLdapUris(){
        return StringUtils.join(getLdapUriList(), " ");
    }
    
    private List<String> mechanismList = new ArrayList<String>();
    
    /**
     * Returns the mechanisms to be used in SASL negotiation.
     * 
     * @return the mechanisms to be used in SASL negotiation.
     */
    public List<String> getMechanismList()
    {
        return mechanismList;
    }
    
    /**
     * Returns joined list of SASL mechanisms to be used in SASL negotiation.
     * 
     * Used for the displaying purpose.
     * 
     * @returns a whitespace seperated list of SASL mechanisms to be used in SASL negotiation.
     */
    public String getMechanisms(){
        return StringUtils.join(getMechanismList(), " ");
    }
    
    private boolean resolveGroup = false;
    
    /**
     * Returns whether to resolve groups.
     * 
     * @return whether to resolve groups.
     */
    public boolean isResolveGroup()
    {
        return resolveGroup;
    }

    private String groupSearchBase;
    
    /**
     * Returns the base DN for groups.
     * 
     * @return the base DN for searching groups.
     */
    public String getGroupSearchBase()
    {
        return groupSearchBase;
    }
    
    private String groupPrefix;
    
    /**
     * Returns the prefix added to the Jenkins group name
     * 
     * @return the prefix to be added before the group name
     */
    public String getGroupPrefix()
    {
        return groupPrefix;
    }
    
    private int connectionTimeout;
    
    /**
     * Returns the timeout of the LDAP server connection.
     * 
     * @return the millisecond of the timeout to connect to the LDAP server.
     */
    public int getConnectionTimeout()
    {
        return connectionTimeout;
    }
    
    private int readTimeout;
    
    /**
     * Returns the timeout of the LDAP server reading.
     * 
     * @return the millisecond of the timeout to read from the LDAP server.
     */
    public int getReadTimeout()
    {
        return readTimeout;
    }
    
    /**
     * Constructor instantiating with parameters in the configuration page.
     * 
     * When instantiating from the saved configuration,
     * the object is directly serialized with XStream,
     * and no constructor is used.
     * 
     * @param ldapUriList the URIs of LDAP servers.
     * @param mechanisms the whitespace separated list of mechanisms.
     * @param resolveGroup the configuration of group resolving
     * @param connectionTimeout the timeout of the LDAP server connection.
     * @param readTimeout the timeout of the LDAP server reading.
     */
    @DataBoundConstructor
    public LdapSaslSecurityRealm(
            List<String> ldapUriList,
            String mechanisms,
            ResolveGroup resolveGroup,
            int connectionTimeout,
            int readTimeout
    )
    {
        this.ldapUriList = ldapUriList;
        this.mechanismList = Arrays.asList(mechanisms.split("[\\s|,]+"));
        this.resolveGroup = (resolveGroup != null);
        this.groupSearchBase = (resolveGroup != null)?resolveGroup.getGroupSearchBase():null;
        this.groupPrefix = (resolveGroup != null)?resolveGroup.getGroupPrefix():null;
        this.connectionTimeout = connectionTimeout;
        this.readTimeout = readTimeout;
    }
    
    /**
     * Authorize a user.
     * 
     * @param username
     * @param password
     * @see hudson.security.AbstractPasswordBasedSecurityRealm#authenticate(java.lang.String, java.lang.String)
     */
    @Override
    protected UserDetails authenticate(String username, String password)
            throws AuthenticationException
    {
        Logger logger = getLogger();
        
        // TODO: Test with LDAPS.
        
        // Parameters for JNDI
        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, getLdapUris());
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.SECURITY_AUTHENTICATION, getMechanisms());
        env.put("com.sun.jndi.ldap.connect.timeout", Integer.toString(getConnectionTimeout()));
        env.put("com.sun.jndi.ldap.read.timeout", Integer.toString(getReadTimeout()));
        
        logger.fine("Authenticating with LDAP-SASL:");
        logger.fine(String.format("username=%s", username));
        logger.fine(String.format("servers=%s", getLdapUris()));
        logger.fine(String.format("mech=%s", getMechanisms()));
        
        LdapContext ctx = null;
        try{
            ctx = new InitialLdapContext(env,null);
        }
        catch(javax.naming.AuthenticationException e)
        {
            // Authentication Failure...
            throw new BadCredentialsException(String.format("Authentication failed: %s", username), e);
        }
        catch(NamingException e)
        {
            // Unexpected failure...
            throw new AuthenticationServiceException(String.format("Authentication failed: %s", username), e);
        }
        
        List<GrantedAuthority> authorities = performResolveGroup(username, ctx);
        
        logger.fine("Authenticating succeeded.");
        UserDetails user = new User(
                username,
                "",         // password(not used)
                true,       // enabled
                true,       // accountNonExpired
                true,       // credentialsNonExpired
                true,       // accountNonLocked
                authorities.toArray(new GrantedAuthority[0])
        );
        return user;
    }

    /**
     * @param username
     * @param ctx
     * @return List of authorities
     */
    private List<GrantedAuthority> performResolveGroup(String username, LdapContext ctx)
    {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        if(isResolveGroup())
        {
            return authorities;
        }
        
        Logger logger = getLogger();
        
        if(getGroupSearchBase() == null || getGroupSearchBase().isEmpty())
        {
            logger.warning("Group cannot be resolved: groupSearchBase is not specified.");
            return authorities;
        }
        
        // TODO: Resolving userdn and group must be performed in other modules.
        String dn = getUserDn(ctx, username);
        if(dn == null){
            logger.warning("Group cannot be resolved: cannot decide DN of the user!");
            return authorities;
        }
        
        try
        {
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            logger.fine(String.format("Searching groups base=%s, dn=%s", getGroupSearchBase(), dn));
            NamingEnumeration<SearchResult> entries = ctx.search(getGroupSearchBase(), String.format("member=%s", dn), searchControls);
            while(entries.hasMore()){
                SearchResult entry = entries.next();
                String groupName = entry.getAttributes().get("cn").get().toString();
                if(getGroupPrefix() != null){
                    groupName = String.format("%s%s", getGroupPrefix(), groupName);
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
     * Get the authenticated user's DN.
     * 
     * @param ctx LdapContext that is already authenticated.
     * @param username Username that the user entered to authenticate.
     * @return
     */
    private String getUserDn(LdapContext ctx, String username)
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

    private Logger getLogger()
    {
        return Logger.getLogger(getClass().getName());
    }

    /**
     * Used for support user input.
     * Not supported, return null.
     * 
     * @param username
     * @return null
     * @throws UsernameNotFoundException
     * @throws DataAccessException
     * @see hudson.security.AbstractPasswordBasedSecurityRealm#loadUserByUsername(java.lang.String)
     */
    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException
    {
        return null;
    }
    
    /**
     * Used for support user input.
     * Not supported, return null.
     * 
     * @param groupname
     * @return null
     * @throws UsernameNotFoundException
     * @throws DataAccessException
     * @see hudson.security.AbstractPasswordBasedSecurityRealm#loadGroupByGroupname(java.lang.String)
     */
    @Override
    public GroupDetails loadGroupByGroupname(String groupname)
            throws UsernameNotFoundException, DataAccessException
    {
        return null;
    }
    
}
