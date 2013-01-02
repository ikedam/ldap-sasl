/**
 * 
 */
package jp.ikedam.jenkins.plugins.ldap_sasl.ldap;

import java.util.Arrays;

import javax.naming.NamingException;
import javax.naming.ldap.ExtendedRequest;
import javax.naming.ldap.ExtendedResponse;

/**
 * Request to perform LDAP "Who am i?" (RFC 4532)
 * 
 * Use as following:
 * <code>
 *    InitialLdapContext ctx = blahblahblah;
 *    LdapWhoAmIResponse response = (LdapWhoAmIResponse)ctx.extendedOperation(new LdapWhoAmIRequest());
 *    switch(response.getAuthzIdType()){
 *    case LdapWhoamiResponse.AuthzIdType.DN_AUTHZ_ID:
 *        System.out.println(String.format("dn=%s", response.getDn());
 *        break;
 *    case LdapWhoamiResponse.AuthzIdType.U_AUTHZ_ID:
 *        System.out.println(String.format("userid=%s", response.getUserid());
 *        break;
 * </code>
 */
public class LdapWhoamiRequest implements ExtendedRequest
{
    private static final long serialVersionUID = -1089597514883298641L;
    
    
    /**
     * OID for LDAP "Who am i?"
     */
    private static final String OID = "1.3.6.1.4.1.4203.1.11.3";
    
    /**
     * Called when "Who am i" request is completed.
     * Generate and return response object.
     * @param id        responseName of ExtendedResponse. In "Who am i?", this will be null (absent).
     * @param berValue  responseValue of ExtendedResponse. This will be authzId(RFC4513).
     * @param offset
     * @param length
     * @return
     * @throws NamingException
     * @see javax.naming.ldap.ExtendedRequest#createExtendedResponse(java.lang.String, byte[], int, int)
     */
    @Override
    public ExtendedResponse createExtendedResponse(String id, byte[] berValue,
            int offset, int length) throws NamingException
    {
        return new LdapWhoamiResponse(id, Arrays.copyOfRange(berValue, offset, offset+length));
    }
    
    /**
     * @return null for RequestValue field is absent.
     * @see javax.naming.ldap.ExtendedRequest#getEncodedValue()
     */
    @Override
    public byte[] getEncodedValue()
    {
        return null;
    }
    
    /**
     * @return OID for LDAP "who am i?"
     * @see javax.naming.ldap.ExtendedRequest#getID()
     */
    @Override
    public String getID()
    {
        return OID;
    }
    
}
