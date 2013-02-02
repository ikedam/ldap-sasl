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

import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.model.AutoCompletionCandidates;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;

import java.util.logging.Logger;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.springframework.dao.DataAccessException;

/**
 * Security Realm that supports LDAP SASL authentication.
 */
public class LdapSaslSecurityRealm extends AbstractPasswordBasedSecurityRealm
        implements Serializable
{
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
            String[] previousList = (previous != null)?previous.split(SEPERATOR_PATTERN):new String[0];
            mechanism_loop:
            for(String mechanism: mechanisms){
                if(StringUtils.isBlank(value) || mechanism.toLowerCase().startsWith(value.toLowerCase())){
                    // This can be a candidate!
                    for(String test: previousList)
                    {
                        if(!StringUtils.isBlank(test) && test.equals(mechanism))
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
        
        /**
         * Returns the list of available UserDnResolvers.
         *  
         * @return the list of UserDnResolvers.
         */
        public DescriptorExtensionList<UserDnResolver,Descriptor<UserDnResolver>> getUserDnResolverList()
        {
            return UserDnResolver.all();
        }
        
        /**
         * Returns the list of available GroupResolvers.
         *  
         * @return the list of GroupResolvers.
         */
        public DescriptorExtensionList<GroupResolver,Descriptor<GroupResolver>> getGroupResolverList()
        {
            return GroupResolver.all();
        }
        
        /**
         * Validate LDAP URI.
         * 
         * * Can be parsed as URI.
         * * scheme must be ldap or ldaps
         * ** ldaps is warned not tested now.
         * * must not have user info part.
         * * port must be between 1 - 65535 if specified
         * * must not have query part.
         * * must not have fragment part.
         * 
         * @param ldapUriList
         * @return
         */
        public FormValidation doCheckLdapUriList(@QueryParameter String ldapUriList)
        {
            if(StringUtils.isBlank(ldapUriList))
            {
                return FormValidation.error(Messages.LdapSaslSecurityRealm_LdapUriList_empty());
            }
            
            URI uri;
            try
            {
                uri = new URI(StringUtils.trim(ldapUriList));
            }
            catch(URISyntaxException e)
            {
                return FormValidation.error(Messages.LdapSaslSecurityRealm_LdapUriList_invalid(e.getMessage()));
            }
            
            if(StringUtils.isBlank(uri.getScheme())
                    || (!("ldap".equals(uri.getScheme().toLowerCase()))
                        && !("ldaps".equals(uri.getScheme().toLowerCase()))))
            {
                return FormValidation.error(Messages.LdapSaslSecurityRealm_LdapUriList_invalid("invalid scheme"));
            }
            
            /* hostname is not required, use localhost for the default
            if(StringUtils.isBlank(uri.getHost()))
            {
                return FormValidation.error(MessageFormat.format(Messages.LdapSaslSecurityRealm_LdapUriList_invalid(), "invalid host"));
            }
            */
            
            if(uri.getPort() != -1 && 
                    (uri.getPort() < 1 || uri.getPort() > 65535))
            {
                return FormValidation.error(Messages.LdapSaslSecurityRealm_LdapUriList_invalid("Invalid port number"));
            }
            
            if(!StringUtils.isEmpty(uri.getUserInfo()))
            {
                return FormValidation.error(Messages.LdapSaslSecurityRealm_LdapUriList_invalid("Cannot specify a user information."));
            }
            
            if(!StringUtils.isEmpty(uri.getQuery()))
            {
                return FormValidation.error(Messages.LdapSaslSecurityRealm_LdapUriList_invalid("Cannot specify a query."));
            }
            
            if(!StringUtils.isEmpty(uri.getFragment()))
            {
                return FormValidation.error(Messages.LdapSaslSecurityRealm_LdapUriList_invalid("Cannot specify a fragment."));
            }
            
            String path = uri.getPath();
            if(path != null && path.startsWith("/"))
            {
                // remove "/" in the head if exists.
                path = path.substring(1);
            }
            if(!StringUtils.isEmpty(path))
            {
                try
                {
                    new LdapName(path);
                }
                catch(InvalidNameException e)
                {
                    return FormValidation.error(Messages.LdapSaslSecurityRealm_LdapUriList_invalid(e.getMessage()));
                }
            }
            
            if("ldaps".equals(uri.getScheme().toLowerCase()))
            {
                return FormValidation.warning(Messages.LdapSaslSecurityRealm_LdapUriList_ldaps());
            }
            
            return FormValidation.ok();
        }
        
        /**
         * Validate mechanisms.
         * 
         * @param mechanisms
         * @return
         */
        public FormValidation doCheckMechanisms(@QueryParameter String mechanisms)
        {
            if(StringUtils.isBlank(mechanisms))
            {
                return FormValidation.error(Messages.LdapSaslSecurityRealm_Mechanisms_empty());
            }
            
            List<String> mechanismList = Arrays.asList(mechanisms.split(SEPERATOR_PATTERN));
            
            for(String m: mechanismList)
            {
                if(!StringUtils.isBlank(m))
                {
                    // contains at least one valid value
                    return FormValidation.ok();
                }
            }
            
            return FormValidation.error(Messages.LdapSaslSecurityRealm_Mechanisms_empty());
        }
    }
    
    private static final long serialVersionUID = 4771805355880928786L;
    protected static final String SEPERATOR_PATTERN = "[\\s,]+";
    
    private List<String> ldapUriList;
    
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
     * Returns a joined list of valid LDAP URIs.
     * 
     * Used to be passed to JNDI.
     * 
     * @return a whitespace-separated list of valid LDAP URIs. null if no URIs are available
     */
    public String getValidLdapUris()
    {
        List<String> validLdapUriList = new ArrayList<String>();
        DescriptorImpl descriptor = (DescriptorImpl)getDescriptor();
        if(getLdapUriList() != null)
        {
            for(String uri: getLdapUriList())
            {
                if(descriptor.doCheckLdapUriList(uri).kind != FormValidation.Kind.ERROR)
                {
                    validLdapUriList.add(uri);
                }
            }
        }
        
        return !validLdapUriList.isEmpty()?StringUtils.join(validLdapUriList, " "):null;
    }
    
    private List<String> mechanismList;
    
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
     * @returns a whitespace separated list of SASL mechanisms to be used in SASL negotiation.
     */
    public String getMechanisms(){
        return StringUtils.join(getMechanismList(), " ");
    }
    
    private UserDnResolver userDnResolver = null;
    
    /**
     * Returns the object to resolver the user DN.
     * 
     * @return the userDnResolver
     */
    public UserDnResolver getUserDnResolver()
    {
        return userDnResolver;
    }
    
    private GroupResolver groupResolver = null;
    
    /**
     * Returns resolveGroup, that encapsulates the group resolving.
     * 
     * @return the resolveGroup
     */
    public GroupResolver getGroupResolver()
    {
        return groupResolver;
    }
    
    // for old version compatibility.
    private String groupSearchBase = null;
    private String groupPrefix = null;
    /**
     * fix up for the old version.
     * 
     * @return fixed instance.
     */
    public Object readResolve()
    {
        if(userDnResolver == null && groupResolver == null
                && !StringUtils.isBlank(groupSearchBase))
        {
            userDnResolver = new LdapWhoamiUserDnResolver();
            groupResolver = new SearchGroupResolver(
                    groupSearchBase,
                    groupPrefix
            );
            groupSearchBase = null;
            groupPrefix = null;
        }
        return this;
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
            UserDnResolver userDnResolver,
            GroupResolver groupResolver,
            int connectionTimeout,
            int readTimeout
    )
    {
        this.ldapUriList = new ArrayList<String>();
        if(ldapUriList != null)
        {
            for(String ldapUri: ldapUriList)
            {
                if(!StringUtils.isBlank(ldapUri))
                {
                    this.ldapUriList.add(StringUtils.trim(ldapUri));
                }
            }
        }
        
        List<String> mechanismList = (mechanisms != null)?Arrays.asList(mechanisms.split(SEPERATOR_PATTERN)):new ArrayList<String>(0);
        this.mechanismList = new ArrayList<String>();
        for(String mechanism: mechanismList)
        {
            if(!StringUtils.isBlank(mechanism))
            {
                this.mechanismList.add(StringUtils.trim(mechanism));
            }
        }
        this.userDnResolver = userDnResolver;
        this.groupResolver = groupResolver;
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
        
        // check configuration.
        String ldapUris = getValidLdapUris();
        if(StringUtils.isBlank(ldapUris))
        {
            logger.severe("No valid LDAP URI is specified.");
            throw new AuthenticationServiceException("No valid LDAP URI is specified.");
        }
        
        String mechanisms = getMechanisms();
        if(StringUtils.isBlank(mechanisms))
        {
            logger.severe("No valid mechanism is specified.");
            throw new AuthenticationServiceException("No valid mechanism is specified.");
        }
        
        // TODO: Test with LDAPS.
        
        // Parameters for JNDI
        Hashtable<String, Object> env = new Hashtable<String, Object>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUris);
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.SECURITY_AUTHENTICATION, mechanisms);
        env.put("com.sun.jndi.ldap.connect.timeout", Integer.toString(getConnectionTimeout()));
        env.put("com.sun.jndi.ldap.read.timeout", Integer.toString(getReadTimeout()));
        
        logger.fine("Authenticating with LDAP-SASL:");
        logger.fine(String.format("username=%s", username));
        logger.fine(String.format("servers=%s", ldapUris));
        logger.fine(String.format("mech=%s", mechanisms));
        
        LdapContext ctx = null;
        try
        {
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
        
        String userDn = (getUserDnResolver() != null)?getUserDnResolver().getUserDn(ctx, username):null;
        logger.fine(String.format("User DN is %s", userDn));
        
        List<GrantedAuthority> authorities = (getGroupResolver() != null)?
                getGroupResolver().resolveGroup(ctx, userDn, username):
                new ArrayList<GrantedAuthority>();
        
        logger.fine("Authenticating succeeded.");
        return new LdapUser(
                username,
                "",         // password(not used)
                userDn,     // dn of this user.
                true,       // enabled
                true,       // accountNonExpired
                true,       // credentialsNonExpired
                true,       // accountNonLocked
                authorities.toArray(new GrantedAuthority[0])
        );
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
