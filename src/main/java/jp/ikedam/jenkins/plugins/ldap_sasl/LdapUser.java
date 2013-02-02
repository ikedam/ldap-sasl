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

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;

/**
 * Authenticated user information.
 * Added DN field.
 *
 */
public class LdapUser extends User
{
    private static final long serialVersionUID = -2172564020680444430L;
    
    private String dn;
    
    /**
     * Returns dn of this user.
     * 
     * @return DN
     */
    public String getDn()
    {
        return dn;
    }
    
    /**
     * @param username
     * @param password
     * @param dn
     * @param enabled
     * @param accountNonExpired
     * @param credentialsNonExpired
     * @param accountNonLocked
     * @param authorities
     * @throws IllegalArgumentException
     */
    public LdapUser(
            String username,
            String password,
            String dn,
            boolean enabled,
            boolean accountNonExpired,
            boolean credentialsNonExpired,
            boolean accountNonLocked,
            GrantedAuthority[] authorities
    ) throws IllegalArgumentException
    {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired,
                accountNonLocked, authorities);
        this.dn = dn;
    }
    
    /**
     * Construct with minumum parameters.
     * 
     * @param username
     * @param dn
     * @param authorities
     */
    public LdapUser(String username, String dn, GrantedAuthority[] authorities)
        throws IllegalArgumentException
    {
        this(username, "", dn, true, true, true, true, authorities);
    }
}
