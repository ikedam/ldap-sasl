/**
 * 
 */
package jp.ikedam.jenkins.plugins.ldap_sasl.ldap;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import javax.naming.ldap.ExtendedResponse;

import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * Response of LDAP "Who am i?" (RFC 4532)
 * 
 * @see LdapWhoamiRequest
 *
 */
public class LdapWhoamiResponse implements ExtendedResponse
{
    private static final long serialVersionUID = -7920991415681532204L;
    
    /**
     * enumuration to distinct the type of AuthzId.
     */
    public enum AuthzIdType
    {
        /**
         * Unknown type
         */
        UNKNOWN_AUTHZ_ID("unknown"),
        /**
         * Indicates the authzId is a distinguished name(DN), like uid=yourname,dc=example,dc=com.
         */
        DN_AUTHZ_ID("dn"),
        /**
         * Indicates the authzId is a user name, like yourname@example.com
         */
        U_AUTHZ_ID("u");
        
        private String name;
        private AuthzIdType(String name)
        {
            this.name = name;
        }
        
        /**
         * @inheritDoc
         */
        @Override
        public String toString(){
            return name;
        }
    }

    private String id;
    /**
     * @return ResponseName of ExtendedResponse
     * @see javax.naming.ldap.ExtendedResponse#getID()
     */
    @Override
    public String getID()
    {
        return id;
    }
   
    
    private byte[] encodedValue;
    
    /**
     * @return ResponseValue of ExtendedResponse
     * @see javax.naming.ldap.ExtendedResponse#getEncodedValue()
     */
    @Override
    public byte[] getEncodedValue()
    {
        return encodedValue;
    }
    
    private String authzId;
    /**
     * @return the authzId returned from the server
     */
    public String getAuthzId()
    {
        return authzId;
    }
    
    private AuthzIdType authzIdType = AuthzIdType.UNKNOWN_AUTHZ_ID;
    /**
     * @return the authzIdType
     */
    public AuthzIdType getAuthzIdType()
    {
        return authzIdType;
    }
    
    private String dn = null;
    /**
     * Returns the distinguished name (DN) returned from the server.
     * Returns valid value only if getAuthzIdType() returns AuthzIdType.DN_AUTHZ_ID
     * 
     * @return the distinguished name (DN).
     */
    public String getDn()
    {
        return dn;
    }
    
    
    private String userid = null;
    /**
     * Returns the user id returned from the server.
     * Returns valid value only if getAuthzIdType() returns AuthzIdType.U_AUTHZ_ID
     * 
     * @return the user id.
     */
    public String getUserid()
    {
        return userid;
    }
    
    /**
     * @param id ResponseName of ExtendedResponse
     * @param berValue ResponseValue of ExtendedResponse
     * @throws UnsupportedEncodingException 
     */
    public LdapWhoamiResponse(String id, byte[] berValue)
    {
        this.id = id;
        this.encodedValue = Arrays.copyOf(berValue, berValue.length);
        
        try
        {
            this.authzId = new String(berValue,"UTF-8");
        }
        catch (UnsupportedEncodingException e)
        {
            Logger logger = Logger.getLogger(getClass().getName());
            logger.log(Level.SEVERE, "Failed to decode LDAP who am i response", e);
            this.authzId = null;
            return;
        }
        if(this.authzId.startsWith("dn:"))
        {
            this.authzIdType = AuthzIdType.DN_AUTHZ_ID;
            this.dn = authzId.substring(3);
        }else if(authzId.startsWith("u:")){
            this.authzIdType = AuthzIdType.U_AUTHZ_ID;
            this.userid = authzId.substring(2);
        }
    }
}
